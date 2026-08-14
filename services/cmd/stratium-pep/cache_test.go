package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"stratium/internal/pdpgrpc"
)

// mustCachePut is the shared "write and fail the test on error" helper
// every test below that seeds a cache file uses, so a seeding failure is
// reported at the seeding call site rather than surfacing later as a
// confusing assertion failure on the read side.
func mustCachePut(t *testing.T, path string, e cacheEntry) {
	t.Helper()
	if err := cachePut(path, e); err != nil {
		t.Fatalf("cachePut: %v", err)
	}
}

// testEntry builds a cacheEntry every one of whose fields is a pure,
// independently-recomputable function of (base, i): DelegationID and Tool
// encode i directly in their text, InputDigest is the digest of a string
// that also encodes i, Decision alternates on i's parity, Epoch is i
// itself, and CachedAt/DelegationExpiresAt are both offsets from base
// keyed on i. Nothing here is the zero value of its type, and no two
// fields could be swapped with each other and still look valid.
//
// This exists so tests that only have an entry's DelegationID in hand
// (parsed back out of it, e.g. after reading it off disk) can independently
// reconstruct what EVERY other field must be and compare -- see
// entrySelfConsistent below -- rather than trust the entry's own fields to
// corroborate each other, which is exactly what a torn read would defeat.
func testEntry(base time.Time, i int) cacheEntry {
	decision := pdpgrpc.Effect_EFFECT_DENY
	if i%2 == 1 {
		decision = pdpgrpc.Effect_EFFECT_ALLOW
	}
	cachedAt := base.Add(time.Duration(i) * time.Second)
	return cacheEntry{
		cacheKey: cacheKey{
			DelegationID: fmt.Sprintf("deleg-%06d", i),
			Tool:         fmt.Sprintf("tool-%06d", i),
			InputDigest:  sha256.Sum256([]byte(fmt.Sprintf("input-%06d", i))),
		},
		Decision:            decision,
		Epoch:               int64(i),
		DelegationExpiresAt: cachedAt.Add(24 * time.Hour),
		CachedAt:            cachedAt,
	}
}

// entrySelfConsistent reports whether e's fields all agree with the single
// index its own DelegationID encodes -- i.e. whether e could have come
// from one, whole call to testEntry, rather than bytes assembled from two
// different ones. strconv.Atoi (not fmt.Sscanf) is used deliberately: it
// rejects trailing garbage after the digits instead of silently ignoring
// it, which matters here because trailing garbage past a valid-looking
// prefix is exactly what a splice could leave behind.
func entrySelfConsistent(base time.Time, e cacheEntry) bool {
	idx, err := strconv.Atoi(strings.TrimPrefix(e.DelegationID, "deleg-"))
	if err != nil {
		return false
	}
	want := testEntry(base, idx)
	return e.DelegationID == want.DelegationID &&
		e.Tool == want.Tool &&
		e.InputDigest == want.InputDigest &&
		e.Decision == want.Decision &&
		e.Epoch == want.Epoch &&
		e.DelegationExpiresAt.Equal(want.DelegationExpiresAt) &&
		e.CachedAt.Equal(want.CachedAt)
}

// TestCachePut_RoundTripPreservesAllFields defends W2 plus the brief's own
// "records the decision, the epoch, the delegation's expiry, and when it
// was cached": every field is asserted individually against a value no
// other field could be confused for, so a mutation dropping or swapping
// any single one of the seven fields fails on that field specifically,
// not just "some field, somewhere."
func TestCachePut_RoundTripPreservesAllFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	want := cacheEntry{
		cacheKey: cacheKey{
			DelegationID: "deleg-round-trip-11111111-2222-3333-4444-555555555555",
			Tool:         "Bash",
			InputDigest:  sha256.Sum256([]byte("round trip raw input")),
		},
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC),
		CachedAt:            time.Date(2026, 8, 14, 9, 30, 0, 123456789, time.UTC),
	}
	mustCachePut(t, path, want)

	got, ok := cacheGet(path, want.cacheKey)
	if !ok {
		t.Fatalf("cacheGet() ok = false, want a hit for the entry just written")
	}
	if got.DelegationID != want.DelegationID {
		t.Errorf("DelegationID = %q, want %q", got.DelegationID, want.DelegationID)
	}
	if got.Tool != want.Tool {
		t.Errorf("Tool = %q, want %q", got.Tool, want.Tool)
	}
	if got.InputDigest != want.InputDigest {
		t.Errorf("InputDigest = %x, want %x", got.InputDigest, want.InputDigest)
	}
	if got.Decision != want.Decision {
		t.Errorf("Decision = %v, want %v", got.Decision, want.Decision)
	}
	if got.Epoch != want.Epoch {
		t.Errorf("Epoch = %d, want %d", got.Epoch, want.Epoch)
	}
	// time.Time uses .Equal, not ==: a value that has round-tripped through
	// JSON never carries a monotonic reading, so comparing it with == against
	// an in-memory time.Time that might still have one is not the same check
	// as comparing the instants -- .Equal is the one that means what this
	// test wants asserted.
	if !got.DelegationExpiresAt.Equal(want.DelegationExpiresAt) {
		t.Errorf("DelegationExpiresAt = %v, want %v", got.DelegationExpiresAt, want.DelegationExpiresAt)
	}
	if !got.CachedAt.Equal(want.CachedAt) {
		t.Errorf("CachedAt = %v, want %v", got.CachedAt, want.CachedAt)
	}
}

// The cache file sits beside the session file and, per W5, gets the same
// integrity posture: group- or world-readable would make it legible to
// any other local account the instant it exists.
//
// Asserts against the literal 0o600, not the cacheFileMode constant: a
// mutation that changes cacheFileMode's own VALUE would still make this
// comparison trivially true if the test re-read that same (now-wrong)
// constant to know what to expect -- a check that cannot fail is not a
// check.
func TestCachePut_FileMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	mustCachePut(t, path, testEntry(time.Now(), 0))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache file mode = %#o, want %#o", perm, 0o600)
	}
}

// TestCacheGet_MissingFileIsMiss defends the fail-closed rule's first
// clause ("a missing... cache is a miss") against a path that has never
// been written at all -- distinct from TestCacheGet_CorruptFileIsMiss and
// TestCacheGet_PartiallyWrittenFileIsMiss below, which both require a file
// to exist in a broken state; this one requires that no file need exist
// for cacheGet to still degrade safely.
func TestCacheGet_MissingFileIsMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-written.json")

	_, ok := cacheGet(path, testEntry(time.Now(), 0).cacheKey)
	if ok {
		t.Errorf("cacheGet() on a nonexistent file ok = true, want a miss")
	}
}

// A corrupt file -- bytes that are not JSON at all -- must be a miss, not
// a panic or a propagated error: spec §4.8.2's binding "fail closed" rule.
func TestCacheGet_CorruptFileIsMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(path, []byte("not json at all {{{"), cacheFileMode); err != nil {
		t.Fatalf("seed corrupt cache file: %v", err)
	}

	_, ok := cacheGet(path, testEntry(time.Now(), 0).cacheKey)
	if ok {
		t.Errorf("cacheGet() on a corrupt file ok = true, want a miss")
	}
}

// TestCacheGet_PartiallyWrittenFileIsMiss is distinct from the corrupt-file
// case above: this simulates a file that WAS a valid, complete JSON
// encoding of real entries but got cut off partway through -- the shape a
// write interrupted mid-flight (a crash, a full disk) would leave, as
// opposed to bytes that were never valid JSON to begin with. Both must
// degrade to a miss, but they are different failure modes and this project
// has been asked to prove each one, not assume a corrupt-file test
// generalizes.
func TestCacheGet_PartiallyWrittenFileIsMiss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	full := []cacheEntry{testEntry(base, 0), testEntry(base, 1), testEntry(base, 2)}

	// The exact encoding writeCacheEntries itself uses (json.Marshal on
	// []cacheEntry), truncated -- not a hand-rolled equivalent, so this
	// test's fixture cannot silently drift from what production actually
	// writes and end up validating the wrong shape of corruption.
	data, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal fixture entries: %v", err)
	}
	truncated := data[:len(data)/2]
	if err := os.WriteFile(path, truncated, cacheFileMode); err != nil {
		t.Fatalf("seed truncated cache file: %v", err)
	}

	_, ok := cacheGet(path, full[0].cacheKey)
	if ok {
		t.Errorf("cacheGet() on a truncated file ok = true, want a miss")
	}
}

// TestCacheGet_MatchesFullKeyNotDelegationAndToolAlone is this task's
// required-but-unprompted mutation target (see the task report): it proves
// cacheGet distinguishes two entries that share a DelegationID and Tool
// but differ only in InputDigest, which a key-matching bug that compared
// just the first two fields would silently conflate -- serving one tool
// call's decision for a DIFFERENT input than the one actually being
// authorized. That is the same "fabricated authorization record" shape as
// a torn read, produced a completely different way: not a race, a
// comparison that used less of the key than W2 defines it to have.
func TestCacheGet_MatchesFullKeyNotDelegationAndToolAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	shared := cacheKey{DelegationID: "deleg-shared", Tool: "Bash"}
	digestA := sha256.Sum256([]byte("input A"))
	digestB := sha256.Sum256([]byte("input B"))

	entryA := cacheEntry{
		cacheKey:            cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestA},
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               1,
		DelegationExpiresAt: base.Add(1 * time.Hour),
		CachedAt:            base,
	}
	entryB := cacheEntry{
		cacheKey:            cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestB},
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               2,
		DelegationExpiresAt: base.Add(2 * time.Hour),
		CachedAt:            base.Add(time.Minute),
	}
	mustCachePut(t, path, entryA)
	mustCachePut(t, path, entryB)

	gotA, ok := cacheGet(path, cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestA})
	if !ok {
		t.Fatalf("cacheGet(digestA) ok = false, want a hit")
	}
	if gotA.Decision != pdpgrpc.Effect_EFFECT_ALLOW || gotA.Epoch != 1 {
		t.Errorf("cacheGet(digestA) = {Decision: %v, Epoch: %d}, want {ALLOW, 1} -- got entryB's values for entryA's key",
			gotA.Decision, gotA.Epoch)
	}

	gotB, ok := cacheGet(path, cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestB})
	if !ok {
		t.Fatalf("cacheGet(digestB) ok = false, want a hit")
	}
	if gotB.Decision != pdpgrpc.Effect_EFFECT_DENY || gotB.Epoch != 2 {
		t.Errorf("cacheGet(digestB) = {Decision: %v, Epoch: %d}, want {DENY, 2} -- got entryA's values for entryB's key",
			gotB.Decision, gotB.Epoch)
	}
}

// TestCachePut_EvictsOldestWhenOverCapacity defends the eviction policy
// (this file's package doc, "Eviction"): a Put that pushes the entry count
// past maxCacheEntries must leave the file at exactly the cap, with the
// OLDEST-by-CachedAt entries gone specifically -- not just "some" entries,
// which a bug evicting an arbitrary or newest-first subset could still
// pass by count alone.
func TestCachePut_EvictsOldestWhenOverCapacity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	const over = 9 // seed strictly over cap; the Put below adds one more
	seed := make([]cacheEntry, maxCacheEntries+over-1)
	for i := range seed {
		seed[i] = testEntry(base, i)
	}
	if err := writeCacheEntries(path, seed); err != nil {
		t.Fatalf("seed cache file: %v", err)
	}

	newest := testEntry(base, len(seed))
	mustCachePut(t, path, newest)

	entries, ok := loadCacheEntries(path)
	if !ok {
		t.Fatalf("cache file unreadable after eviction")
	}
	if len(entries) != maxCacheEntries {
		t.Fatalf("entry count after eviction = %d, want %d (the configured cap)", len(entries), maxCacheEntries)
	}

	// The `over` oldest (indices 0..over-1, by construction the smallest
	// CachedAt values) must be gone.
	for i := 0; i < over; i++ {
		if _, ok := cacheGet(path, testEntry(base, i).cacheKey); ok {
			t.Errorf("entry %d (one of the oldest %d) survived eviction, want it evicted", i, over)
		}
	}
	// The newest seeded entry and the just-written entry must both remain.
	if _, ok := cacheGet(path, testEntry(base, len(seed)-1).cacheKey); !ok {
		t.Errorf("newest seeded entry evicted, want it retained")
	}
	if _, ok := cacheGet(path, newest.cacheKey); !ok {
		t.Errorf("just-written entry evicted, want it retained")
	}
}

// TestCachePut_ReplacesExistingEntryForSameKey defends the "upsert" half of
// cachePut's own doc comment: Putting the same key twice must leave ONE
// entry holding the second value, not two entries or the first value
// retained.
func TestCachePut_ReplacesExistingEntryForSameKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.json")
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := cacheKey{DelegationID: "deleg-upsert", Tool: "Read", InputDigest: sha256.Sum256([]byte("upsert input"))}

	mustCachePut(t, path, cacheEntry{cacheKey: key, Decision: pdpgrpc.Effect_EFFECT_DENY, Epoch: 1, DelegationExpiresAt: base.Add(time.Hour), CachedAt: base})
	mustCachePut(t, path, cacheEntry{cacheKey: key, Decision: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: 2, DelegationExpiresAt: base.Add(2 * time.Hour), CachedAt: base.Add(time.Minute)})

	entries, ok := loadCacheEntries(path)
	if !ok {
		t.Fatalf("cache file unreadable")
	}
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1 (the second Put should replace, not duplicate)", len(entries))
	}

	got, ok := cacheGet(path, key)
	if !ok {
		t.Fatalf("cacheGet() ok = false, want a hit")
	}
	if got.Decision != pdpgrpc.Effect_EFFECT_ALLOW || got.Epoch != 2 {
		t.Errorf("Decision/Epoch = %v/%d, want ALLOW/2 (the second Put's values)", got.Decision, got.Epoch)
	}
}
