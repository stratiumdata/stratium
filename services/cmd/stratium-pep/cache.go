// cache.go is the on-disk store for the PEP's decision cache (spec §4.8,
// §4.8.2 W1-W5; Phase 13 Task 1). It stores and retrieves bytes only -- no
// validity rule lives here. Whether an entry this file returns is still
// USABLE (epoch match, delegation not expired, token still valid, within
// the staleness window -- W3) is Task 2's job, layered on top of cacheGet;
// whether any of the four PEP surfaces ever calls cacheGet or cachePut at
// all is Task 3's. This file never imports internal/authz and never
// inspects Decision beyond storing and returning whatever value it was
// given -- the PEP classifies nothing and decides nothing (this phase's own
// global constraint), and a storage layer that peeked at the verdict to
// make a choice would already be halfway to violating it.
//
// Key and stored fields (W2): an entry is keyed by (delegation id, tool,
// input digest) -- keyed on the DELEGATION rather than the token because a
// token rotates while the delegation persists, so keying on the token would
// discard the whole cache on every reissue -- and records the decision, the
// epoch it was computed under, the delegation's own recorded expiry, and
// when this process cached it. InputDigest reuses sha256.Sum256(raw_input)
// exactly as internal/pdpgrpc/server.go's appendAudit already computes it
// for the audit chain, rather than inventing a second notion of request
// identity for the same bytes. Epoch and CachedAt are plain, non-optional
// values (not pointers, unlike pdpgrpc.DecideResponse.Epoch): a decision
// worth caching came from a call that read a real epoch, and CachedAt is
// supplied by the caller -- like appendAudit's own "now time.Time"
// parameter -- rather than stamped internally with time.Now(), so a caller
// can use one captured instant across a whole decide-and-cache flow and so
// this file's own tests can construct exact, reproducible eviction orders.
//
// # Concurrency
//
// Several "hook" subprocesses may read and write this same file at once,
// with no shared memory between them (hook.go's own package doc) -- there
// is no in-process mutex that could ever help here. The two ways a
// concurrent write can go wrong are not equally bad. A LOST UPDATE --
// writer B's rename lands after writer A's, silently discarding whatever A
// just wrote -- costs A's caller a cache miss on its next lookup, and a
// miss is always safe: this cache is an optimization, not a source of
// truth, and losing an update just means paying for the round trip to the
// PDP a hit would have skipped. A TORN READ -- a reader observing a file
// that is neither the old generation nor the new one, but bytes from both
// -- is not safe: at best it fails to parse (still just a miss), but at
// worst it parses successfully into an entry stitched from two different
// writes, which is a fabricated authorization record wearing a valid
// decision's shape.
//
// This file accepts the first and structurally rules out the second, by
// following writeSessionFile (session_file.go) exactly: every write is
// os.CreateTemp in the target directory + os.Rename, never a modification
// of path in place. POSIX rename(2) retargets a directory entry in one
// step, so a concurrent reader that opens path at any instant gets either
// the complete pre-rename file or the complete post-rename file, in their
// entirety -- there is no intermediate state to observe, because none is
// ever written to path itself (only to the temp file, which nothing else
// has a name for until the rename succeeds).
//
// What is deliberately NOT here: any lock, advisory or otherwise, to
// prevent the lost update. Adding one would mean coordinating processes
// that share no memory (a cross-process file lock, held across a read,
// JSON decode, upsert, JSON encode, and write) to prevent a failure mode
// this task's own brief calls acceptable -- machinery in service of a
// problem that does not need solving. cache_concurrency_test.go proves
// both halves of this against real goroutines racing a real file, not by
// reasoning about the mechanism in prose.
//
// # Eviction
//
// maxCacheEntries bounds the file by entry COUNT, not by age or size. The
// obvious first lever is age -- an entry past Task 2's staleness window is
// dead weight by construction -- but that window is required config with
// no default (spec §4.8.2 W3, C19) that Task 2 introduces, and Task 1 does
// not have it: inventing a Task-1-only duration here would be a second,
// competing notion of staleness, not a stand-in for the real one. A count
// cap needs no duration at all, so it is available now; age still decides
// WHICH entries an over-cap Put evicts (oldest CachedAt first --
// evictOldest below), just not WHEN eviction triggers. The two mechanisms
// compose cleanly once Task 2 lands: nothing here needs to change.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"stratium/internal/pdpgrpc"
)

const (
	// cacheFileMode matches sessionFileMode (session_file.go) exactly: set
	// at creation via os.CreateTemp's own documented 0600-before-umask
	// default, never chmod'd on afterward. Restated as a named constant for
	// the same reason sessionFileMode is -- so the fact is asserted by name
	// here rather than left implicit in a stdlib doc comment -- even though
	// nothing in this file passes it to CreateTemp (CreateTemp does not
	// accept a mode argument; this is what it always creates with).
	cacheFileMode = 0o600

	// maxCacheEntries bounds the cache file's entry count -- see this
	// file's own package doc, "Eviction," for why count rather than age is
	// this task's lever. 500 keeps a decode-then-encode pass, paid on
	// every hook invocation (a fresh subprocess per tool call, per this
	// phase's own W5), comfortably small: at a generous ~250 bytes/entry
	// that is roughly 125KB, an amount neither disk space nor a JSON codec
	// pass notices.
	maxCacheEntries = 500

	// cacheTempPattern mirrors session_file.go's own temp-file naming
	// scheme (".stratium-pep-session-*.tmp") -- a "cache" sibling of it,
	// distinguishable at a glance in a directory listing or a crash-leftover
	// cleanup script from the session file's own temp files.
	cacheTempPattern = ".stratium-pep-cache-*.tmp"
)

// cacheKey is spec §4.8.2 W2's tuple: (delegation id, tool, input digest).
// A named struct rather than three positional parameters on every function
// below -- DelegationID and Tool are both plain strings, and this project
// has repeatedly been bitten by values that type-check but are silently
// transposed; naming the fields forces a call site to say which is which.
type cacheKey struct {
	DelegationID string   `json:"delegation_id"`
	Tool         string   `json:"tool"`
	InputDigest  [32]byte `json:"input_digest"`
}

// cacheEntry is one cached PDP decision. Decision, Epoch, and
// DelegationExpiresAt are exactly what W3 (Task 2) will need to judge
// whether a hit is still valid; CachedAt is when this process wrote it.
// Deliberately not pdpgrpc.DecideResponse or authz.Result: this cache
// replays a verdict, not the machinery that produced it, and embedding
// either wire/decision type would let an unrelated future change to those
// shapes silently reshape what a subprocess reads back off disk days
// later.
type cacheEntry struct {
	cacheKey
	Decision            pdpgrpc.Effect `json:"decision"`
	Epoch               int64          `json:"epoch"`
	DelegationExpiresAt time.Time      `json:"delegation_expires_at"`
	CachedAt            time.Time      `json:"cached_at"`
}

// loadCacheEntries reads and decodes the cache file at path, collapsing
// every failure mode -- absent, unreadable, or not a well-formed JSON array
// of cacheEntry, including a truncated/partially-written one -- into a
// single ok=false, with no error value at all. That is deliberate, not an
// omission: this phase's fail-closed rule is "a missing, unreadable,
// corrupt, or partially-written cache is a miss, never an error that
// propagates," and a function with no error return makes the illegal
// outcome -- some caller forwarding a cache-corruption error into a deny,
// or worse an allow -- unrepresentable rather than merely discouraged.
func loadCacheEntries(path string) ([]cacheEntry, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is caller-supplied cache-file configuration, the same trust boundary as loadSessionFile's identical read (session_file.go) -- not attacker-controlled request data
	if err != nil {
		return nil, false
	}
	var entries []cacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, false
	}
	return entries, true
}

// writeCacheEntries atomically replaces path with entries' JSON encoding.
// See this file's package doc, "Concurrency," for why this is CreateTemp +
// Rename rather than an in-place write, and why cacheFileMode is never
// chmod'd on after creation.
//
// Encoded compactly (json.Marshal), not indented like writeSessionFile's
// MarshalIndent: the session file holds exactly one object meant to be
// human-read while debugging; this file can hold up to maxCacheEntries,
// where indentation would multiply the on-disk size for no reader this
// file is written for -- Task 1's whole reason to bound entry count in the
// first place.
func writeCacheEntries(path string, entries []cacheEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("encode cache file: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), cacheTempPattern)
	if err != nil {
		return fmt.Errorf("create temp cache file: %w", err)
	}
	// A successful rename below moves tmp's name to path, so this Remove is
	// a harmless no-op (ENOENT) on the success path -- it only ever does
	// real work on an error return, where it discards the half-written
	// temp file rather than leaving it behind as debris.
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp cache file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp cache file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename temp cache file into place: %w", err)
	}
	return nil
}

// cacheGet returns the entry for key and true, or a zero cacheEntry and
// false if there is none -- including every failure loadCacheEntries
// collapses into "no data." A cache is an optimization a caller can always
// fall back from; nothing here ever returns an error a caller could
// mishandle into anything but a miss.
//
// Does not check Decision, Epoch, DelegationExpiresAt, or staleness --
// whether a returned entry is still VALID is W3, Task 2's layer on top of
// this one, not this function's job.
func cacheGet(path string, key cacheKey) (cacheEntry, bool) {
	entries, ok := loadCacheEntries(path)
	if !ok {
		return cacheEntry{}, false
	}
	for _, e := range entries {
		if e.cacheKey == key {
			return e, true
		}
	}
	return cacheEntry{}, false
}

// cachePut upserts entry into the cache file at path -- replacing any
// existing entry with the same key -- and evicts the oldest entries first
// if that leaves more than maxCacheEntries (evictOldest).
//
// A read failure from loadCacheEntries here (missing or corrupt file) is
// treated as an empty starting set and silently overwritten, not returned
// as an error: Put's job is to make the NEXT Get succeed, and refusing to
// write over a corrupt file would leave it corrupt forever instead of
// self-healing on the very next call -- the only sense in which a cache
// can meaningfully "heal" itself at all.
//
// This whole read-modify-write is NOT atomic -- see the package doc,
// "Concurrency," for why that is an accepted lost update rather than a
// bug, and why it can never corrupt the file for a third, uninvolved
// reader regardless.
func cachePut(path string, entry cacheEntry) error {
	entries, _ := loadCacheEntries(path)

	found := false
	for i := range entries {
		if entries[i].cacheKey == entry.cacheKey {
			entries[i] = entry
			found = true
			break
		}
	}
	if !found {
		entries = append(entries, entry)
	}

	entries = evictOldest(entries, maxCacheEntries)
	return writeCacheEntries(path, entries)
}

// evictOldest keeps at most maxEntries of entries, dropping the
// oldest-by-CachedAt first when there are more. Age is a reasonable proxy
// for "least likely to still be useful" on its own -- see the package doc,
// "Eviction," for why it is the sort key even though Task 1 does not yet
// have Task 2's staleness window to decide a cutoff BY age, only a count.
func evictOldest(entries []cacheEntry, maxEntries int) []cacheEntry {
	if len(entries) <= maxEntries {
		return entries
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CachedAt.Before(entries[j].CachedAt) })
	return entries[len(entries)-maxEntries:]
}
