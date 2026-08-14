// cache.go is the on-disk store for the PEP's decision cache (spec §4.8,
// §4.8.2 W1-W5; Phase 13 Tasks 1-2), plus -- layered on top of the store --
// whether a retrieved entry is still USABLE (epoch match, delegation not
// expired, token still valid, within the staleness window -- W3) and W4's
// rule that an ESCALATE is never cached or served (see "Validity" below).
// Whether any of the four PEP surfaces ever calls cacheGetValid or cachePut
// at all is Task 3's, not this file's. This file never imports
// internal/authz, and the only thing it inspects Decision for is refusing
// to store or serve an ESCALATE -- it never inspects one to CLASSIFY or
// COMBINE anything (this phase's own global constraint): replaying a
// verdict the PDP already produced, or declining to, is not the same act as
// deriving one.
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
//
// Task 2 has since introduced that window (cacheConfig.StalenessWindow,
// "Validity" below) -- as predicted, evictOldest did not change at all.
//
// # Validity
//
// W3 is four independent conditions, ALL required, each closing a
// different conformance property: epochCurrent (C20), delegationNotExpired
// (C24's time half), tokenNotExpired (C24's credential half), and
// withinStalenessWindow (C19). cacheEntryUsable combines the four -- plus
// W4's rule below -- and cacheGetValid applies the combination on top of
// cacheGet, so a caller never sees "a hit that turned out to be unusable"
// as a distinct outcome from an ordinary miss; fail closed means the two
// are indistinguishable on purpose.
//
// withinStalenessWindow's clock runs from the ENTRY'S OWN CachedAt, not
// from the most recent successful PDP contact of any kind -- the choice
// this task was asked to make and justify. Both are defensible, and they
// differ sharply during an outage that starts right after a busy period:
// "any kind" would let one call's success silently vouch for every OTHER
// entry's freshness too, so the whole cache would read as fresh right up
// until staleness-window after that last unrelated call, then go stale all
// at once. Per-entry CachedAt instead lets each entry age out on its own
// schedule, on the strength of only its own evidence. Chosen because: (1)
// it needs no new state -- no shared "last contact" clock that all four of
// Task 3's surfaces, separate processes with no shared memory (W5), would
// each have to remember to update on every successful call and get right,
// with nothing to catch the one that forgot; (2) it is the strictly more
// conservative reading, matching this phase's own fail-closed bias -- an
// entry never gets to borrow freshness from a call it was not itself part
// of; and (3) it gives an operator's staleness-window setting one bound
// that means the same thing for every decision: no cached verdict is EVER
// served more than that long after the PDP actually computed it, a
// per-decision guarantee rather than one that quietly depends on how much
// unrelated traffic the cache happened to be seeing. The cost an operator
// should expect in exchange: during that same outage, calls whose entries
// happen to be older start denying sooner than calls whose entries are
// newer, even though the PDP went unreachable for both at the same moment
// -- the cache empties out over the course of the window rather than
// holding together and then dropping all at once.
//
// tokenNotExpired decodes the caller's presented token's own "exp" claim
// without verifying its signature, deliberately: internal/token's own
// package doc makes the PDP the ONLY verifier (spec K2 -- no JWKS document
// distributes a key anyone else could check a signature against), so the
// PEP has never held the means to verify a token on ANY path, cached or
// forwarded to Decide. What this condition narrows is specifically "has
// the claimed expiry passed" -- the same claim, the same trust boundary,
// DelegationExpiresAt is itself sourced from (decode the token's "exp"
// claim; pdp.proto's CreateDelegationResponse.token comment), not a new
// capability this task invents.
//
// W4 (an ESCALATE is never cached, spec §4.6) is guarded twice, on
// purpose: cachePut refuses to WRITE one, and cacheEntryUsable refuses to
// SERVE one even if it reached the file another way (a hand-edited file, or
// a future cachePut that lost the guard). The failure is silent if missed
// -- a served ESCALATE either re-blocks a call a human already approved or
// fabricates an approval nobody granted -- so it gets defended at both the
// only door it can be written through and the only door it can be read
// back out of, rather than trusting the first to make the second
// redundant.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/golang-jwt/jwt/v5"

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
// DelegationExpiresAt are exactly what W3 (cacheEntryUsable, below) needs
// to judge whether a hit is still valid; CachedAt is when this process
// wrote it.
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
// whether a returned entry is still VALID is W3, layered on top of this
// function by cacheGetValid below, not this function's own job.
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

// errEscalationNotCacheable is cachePut's refusal for an ESCALATE decision
// -- spec W4, §4.6: an escalation is a human decision left pending, not a
// verdict the PDP produced, so there is nothing here yet to replay. See the
// package doc's "Validity" section for why this is guarded a second time on
// the read side too (cacheEntryUsable), not trusted to this check alone.
var errEscalationNotCacheable = errors.New("cache: ESCALATE decisions are never cached (spec W4)")

// cachePut upserts entry into the cache file at path -- replacing any
// existing entry with the same key -- and evicts the oldest entries first
// if that leaves more than maxCacheEntries (evictOldest).
//
// Refuses outright, before touching the file at all, if entry.Decision is
// ESCALATE (W4, errEscalationNotCacheable) -- the one case where this file
// inspects Decision for a reason other than storing and returning it
// unchanged; see the package doc for why that single exception does not
// widen into classifying or combining anything.
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
	if entry.Decision == pdpgrpc.Effect_EFFECT_ESCALATE {
		return errEscalationNotCacheable
	}
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

// cacheStalenessWindowEnv is condition 4's one new piece of required
// configuration (spec C19): how long a cached decision may keep being
// served without a fresh PDP round trip re-confirming it. No default -- an
// operator states how long an unverifiable decision may keep working, and
// no single value is right for every deployment: too long is too
// permissive (an outage-tolerance feature that quietly becomes a
// revocation-tolerance one), too short is useless (an "outage tolerance"
// that cannot outlast a network blip).
const cacheStalenessWindowEnv = "STRATIUM_PEP_CACHE_STALENESS_WINDOW"

// cacheConfig is this task's one addition to this binary's configuration
// surface. A separate small struct and loader, not a new field folded into
// hookConfig/sessionStartConfig/mcpConfig/extauthzConfig/proxyConfig
// (hook.go/session_start.go/mcp.go/extauthz.go/proxy.go): this file's own
// scope does not extend to those, and each already has its own independent
// loader for exactly this reason -- mcpConfig's own loader doc comment
// makes the same call for its one required value ("moot here with only one
// required variable, but consistent... rather than a special case"). How
// this composes with each surface's own config is Task 3's decision, the
// same way combineConfigErrors (mcp.go) already composes mcpConfig's loader
// with hookConfig's.
type cacheConfig struct {
	StalenessWindow time.Duration
}

// loadCacheConfigFromEnv reads cacheConfig from the environment via the
// same requiredEnv/requiredDuration/missingConfigError machinery
// (config.go) every other loader in this binary uses: no default, and a
// missing or non-positive value fails with a message naming it, never a
// guess.
func loadCacheConfigFromEnv() (cacheConfig, error) {
	var missing []string
	raw := requiredEnv(cacheStalenessWindowEnv, &missing)
	if len(missing) > 0 {
		return cacheConfig{}, missingConfigError(missing)
	}
	window, err := requiredDuration(cacheStalenessWindowEnv, raw)
	if err != nil {
		return cacheConfig{}, err
	}
	return cacheConfig{StalenessWindow: window}, nil
}

// epochCurrent is W3's first condition (C20): the epoch entry was computed
// under must equal the last epoch this PEP has itself observed from the
// PDP. lastKnownEpoch is supplied by the caller, not read or tracked here
// -- this file stores decisions, not PEP-wide session state, and each of
// Task 3's four surfaces already holds a natural source for it (the epoch
// on its own most recent Decide/CreateDelegation/IssueToken response; see
// pdp.proto's own comment on why all three RPCs return one).
//
// Equality, not >=: a cached epoch NEWER than what this call site currently
// believes would mean this process itself is behind, which is exactly as
// untrustworthy as being behind the other way around -- W3 asks for the two
// to agree, not merely for the entry to be no older.
func epochCurrent(entry cacheEntry, lastKnownEpoch int64) bool {
	return entry.Epoch == lastKnownEpoch
}

// delegationNotExpired is W3's second condition (C24's time half):
// entry.DelegationExpiresAt, recorded when the entry was cached, must still
// be in the future as of now. This is the reason spec §4.8.1 V2 keeps a
// delegation's own time-based expiry OUT of the revocation epoch:
// expiring is a state change nobody writes -- no row update, no trigger,
// nothing that could ever bump the epoch -- it simply becomes true the
// instant a clock crosses a value nobody had to act on. epochCurrent can
// therefore never catch this on its own; it needs this separate,
// independent time comparison.
func delegationNotExpired(entry cacheEntry, now time.Time) bool {
	return now.Before(entry.DelegationExpiresAt)
}

// tokenNotExpired is W3's third condition (C24's credential half): the
// CALLER's own presented token -- not anything the entry recorded -- must
// not have passed its own "exp" claim as of now. Deliberately independent
// of entry: a hit replays a decision about a delegation, but the credential
// presenting it can have expired on its own schedule since, and only a live
// PDP call can mint a replacement (reissue.go) -- so during an outage an
// expired token must deny even against an otherwise perfect hit, exactly
// the "a cache hit must not extend a credential's life" rule this phase
// states as a global constraint.
//
// Reads the claim, does not verify the signature: jwt.Parser.ParseUnverified's
// own doc warns this is safe only "in cases where you know the signature is
// valid... since it has already been... checked elsewhere in the stack" --
// exactly this system's shape. internal/token's own package doc makes the
// PDP the only verifier (spec K2: no JWKS document, so verification is
// never on the enforcement path for anyone else), so the PEP has never held
// a key to check a signature with, on this path or the ordinary
// forwarded-to-Decide one either. What this narrows is specifically "has
// the claimed expiry passed" -- the same claim, the same trust boundary,
// DelegationExpiresAt is itself sourced from.
//
// Fails closed on anything unreadable: a token that does not even parse,
// and -- easy to miss, see TestTokenNotExpired_MissingExpClaimDenies -- a
// token that parses fine but carries no "exp" claim at all, which
// jwt.MapClaims.GetExpirationTime reports as (nil, nil), NOT an error. A
// check that only looked at the error would treat an unsigned token with no
// expiry as valid forever; checking exp == nil explicitly is what the
// binding "an unparseable expiry... is a miss" rule actually requires here.
func tokenNotExpired(token string, now time.Time) bool {
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return false
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return false
	}
	return now.Before(exp.Time)
}

// withinStalenessWindow is W3's fourth condition (C19's bound): now must be
// no later than entry.CachedAt plus staleness. Runs from the entry's OWN
// CachedAt rather than the most recent successful PDP contact of any kind
// -- see the package doc's "Validity" section for the choice and its
// justification.
func withinStalenessWindow(entry cacheEntry, now time.Time, staleness time.Duration) bool {
	return !now.After(entry.CachedAt.Add(staleness))
}

// cacheEntryUsable is spec §4.8.2 W3 (all four conditions, all required)
// plus W4 (an ESCALATE is never served, even if one somehow reached the
// file) -- the one place a caller learns whether a looked-up entry may
// actually be replayed. Go's && already fails closed on the first false the
// same way a hand-written all() would: a single missing or unparseable
// input anywhere in the chain (a zero-value CachedAt, an unparseable token,
// an epoch the caller never actually learned) can only ever push the result
// toward false, never true.
func cacheEntryUsable(entry cacheEntry, lastKnownEpoch int64, token string, now time.Time, staleness time.Duration) bool {
	if entry.Decision == pdpgrpc.Effect_EFFECT_ESCALATE {
		// W4, read side. cachePut already refuses to write one; this is the
		// second half of that same guarantee, for a file this process did
		// not itself write (hand-edited, or written by some future cachePut
		// that lost the guard). The failure is silent if missed, so it gets
		// its own line rather than trusting the write-side guard alone.
		return false
	}
	return epochCurrent(entry, lastKnownEpoch) &&
		delegationNotExpired(entry, now) &&
		tokenNotExpired(token, now) &&
		withinStalenessWindow(entry, now, staleness)
}

// cacheGetValid is cacheGet plus cacheEntryUsable layered on top -- the
// single call Task 3's four surfaces need. A hit that fails any condition
// is indistinguishable from an outright miss, on purpose: fail closed means
// an invalid entry is not a distinct outcome a caller could handle
// specially, it is a miss like any other, and the caller falls back to the
// PDP (or denies) exactly as it would for a key that was never cached at
// all.
func cacheGetValid(
	path string, key cacheKey, lastKnownEpoch int64, token string, now time.Time, staleness time.Duration,
) (cacheEntry, bool) {
	entry, ok := cacheGet(path, key)
	if !ok || !cacheEntryUsable(entry, lastKnownEpoch, token, now, staleness) {
		return cacheEntry{}, false
	}
	return entry, true
}
