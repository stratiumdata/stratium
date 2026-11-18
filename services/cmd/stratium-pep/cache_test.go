package main

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// mustCachePut is the shared "store and fail the test on error" helper
// every test that seeds a cache uses, so a seeding failure is reported at
// the seeding call site rather than surfacing later as a confusing
// assertion failure on the read side.
func mustCachePut(t *testing.T, c *decisionCache, e cacheEntry) {
	t.Helper()
	if err := c.put(e); err != nil {
		t.Fatalf("put: %v", err)
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
// This exists so tests that only have an entry's DelegationID in hand can
// independently reconstruct what EVERY other field must be and compare --
// see entrySelfConsistent below -- rather than trust the entry's own fields
// to corroborate each other, which is exactly what a torn read under
// concurrency (cache_concurrency_test.go) would defeat.
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
	c := newDecisionCache()
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
	mustCachePut(t, c, want)

	got, ok := c.get(want.cacheKey)
	if !ok {
		t.Fatalf("get() ok = false, want a hit for the entry just stored")
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
	// time.Time uses .Equal, not ==: it compares the instants, which is
	// what this test wants asserted.
	if !got.DelegationExpiresAt.Equal(want.DelegationExpiresAt) {
		t.Errorf("DelegationExpiresAt = %v, want %v", got.DelegationExpiresAt, want.DelegationExpiresAt)
	}
	if !got.CachedAt.Equal(want.CachedAt) {
		t.Errorf("CachedAt = %v, want %v", got.CachedAt, want.CachedAt)
	}
}

// TestCacheGet_EmptyCacheIsMiss: a cache nothing has been put into -- every
// process's starting state -- must miss cleanly.
func TestCacheGet_EmptyCacheIsMiss(t *testing.T) {
	if _, ok := newDecisionCache().get(testEntry(time.Now(), 0).cacheKey); ok {
		t.Errorf("get() on an empty cache ok = true, want a miss")
	}
}

// TestDecisionCaches_ShareNothing pins "memory only" at the type's own
// level: an entry put into one cache is invisible to another. A build that
// backed decisionCache with anything shared between instances (a file, a
// package-level variable) would make a restarted process -- a new cache --
// inherit decisions it never received from the PDP.
func TestDecisionCaches_ShareNothing(t *testing.T) {
	entry := testEntry(time.Now(), 1)
	first := newDecisionCache()
	mustCachePut(t, first, entry)

	if _, ok := newDecisionCache().get(entry.cacheKey); ok {
		t.Errorf("get() on a NEW cache found an entry put into a different one, want a miss")
	}
}

// TestCacheGet_MatchesFullKeyNotDelegationAndToolAlone is this task's
// mutation target for key identity: it proves get distinguishes two entries that share a DelegationID and Tool
// but differ only in InputDigest, which a key-matching bug that compared
// just the first two fields would silently conflate -- serving one tool
// call's decision for a DIFFERENT input than the one actually being
// authorized: a comparison that used less of the key than W2 defines it to
// have.
func TestCacheGet_MatchesFullKeyNotDelegationAndToolAlone(t *testing.T) {
	c := newDecisionCache()
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
	mustCachePut(t, c, entryA)
	mustCachePut(t, c, entryB)

	gotA, ok := c.get(cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestA})
	if !ok {
		t.Fatalf("get(digestA) ok = false, want a hit")
	}
	if gotA.Decision != pdpgrpc.Effect_EFFECT_ALLOW || gotA.Epoch != 1 {
		t.Errorf("get(digestA) = {Decision: %v, Epoch: %d}, want {ALLOW, 1} -- got entryB's values for entryA's key",
			gotA.Decision, gotA.Epoch)
	}

	gotB, ok := c.get(cacheKey{DelegationID: shared.DelegationID, Tool: shared.Tool, InputDigest: digestB})
	if !ok {
		t.Fatalf("get(digestB) ok = false, want a hit")
	}
	if gotB.Decision != pdpgrpc.Effect_EFFECT_DENY || gotB.Epoch != 2 {
		t.Errorf("get(digestB) = {Decision: %v, Epoch: %d}, want {DENY, 2} -- got entryA's values for entryB's key",
			gotB.Decision, gotB.Epoch)
	}
}

// TestCachePut_EvictsOldestWhenOverCapacity defends the eviction policy
// (cache.go's package doc, "Eviction"): a put that pushes the entry count
// past maxCacheEntries must leave the cache at exactly the cap, with the
// OLDEST-by-CachedAt entries gone specifically -- not just "some" entries,
// which a bug evicting an arbitrary or newest-first subset could still
// pass by count alone.
func TestCachePut_EvictsOldestWhenOverCapacity(t *testing.T) {
	c := newDecisionCache()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Inserted NEWEST FIRST, so insertion order and age disagree: a build
	// that evicted by position instead of CachedAt would drop the wrong end.
	const over = 9
	total := maxCacheEntries + over
	for i := total - 1; i >= 0; i-- {
		mustCachePut(t, c, testEntry(base, i))
	}

	if got := len(c.entries); got != maxCacheEntries {
		t.Fatalf("entry count after eviction = %d, want %d (the configured cap)", got, maxCacheEntries)
	}
	// The `over` oldest (indices 0..over-1, by construction the smallest
	// CachedAt values) must be gone.
	for i := 0; i < over; i++ {
		if _, ok := c.get(testEntry(base, i).cacheKey); ok {
			t.Errorf("entry %d (one of the oldest %d) survived eviction, want it evicted", i, over)
		}
	}
	// The oldest survivor and the newest entry must both remain.
	for _, i := range []int{over, total - 1} {
		if _, ok := c.get(testEntry(base, i).cacheKey); !ok {
			t.Errorf("entry %d evicted, want it retained", i)
		}
	}
}

// TestCachePut_ReplacesExistingEntryForSameKey defends the "upsert" half of
// put's own doc comment: putting the same key twice must leave ONE
// entry holding the second value, not two entries or the first value
// retained.
func TestCachePut_ReplacesExistingEntryForSameKey(t *testing.T) {
	c := newDecisionCache()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := cacheKey{DelegationID: "deleg-upsert", Tool: "Read", InputDigest: sha256.Sum256([]byte("upsert input"))}

	mustCachePut(t, c, cacheEntry{cacheKey: key, Decision: pdpgrpc.Effect_EFFECT_DENY, Epoch: 1, DelegationExpiresAt: base.Add(time.Hour), CachedAt: base})
	mustCachePut(t, c, cacheEntry{cacheKey: key, Decision: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: 2, DelegationExpiresAt: base.Add(2 * time.Hour), CachedAt: base.Add(time.Minute)})

	if got := len(c.entries); got != 1 {
		t.Fatalf("entry count = %d, want 1 (the second put should replace, not duplicate)", got)
	}

	got, ok := c.get(key)
	if !ok {
		t.Fatalf("get() ok = false, want a hit")
	}
	if got.Decision != pdpgrpc.Effect_EFFECT_ALLOW || got.Epoch != 2 {
		t.Errorf("Decision/Epoch = %v/%d, want ALLOW/2 (the second Put's values)", got.Decision, got.Epoch)
	}
}
