// local_cache_test.go tests local_cache.go's own small pure helpers and its
// two cache-facing entry points directly, isolated from the full
// decideAndRelay flow -- mcp_authorize_cache_test.go instead proves that
// flow actually CALLS this file's functions at the right moments; this file
// proves what those functions do on their own, mirroring cache.go's own
// split (cache_test.go/cache_validity_test.go test the store and validity
// layers directly).
package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

func TestCacheKeyFor_DigestMatchesSHA256OfRawInputExactly(t *testing.T) {
	got := cacheKeyFor("deleg-1", "Bash", "raw input bytes")
	want := cacheKey{DelegationID: "deleg-1", Tool: "Bash", InputDigest: sha256.Sum256([]byte("raw input bytes"))}
	if got != want {
		t.Errorf("cacheKeyFor() = %+v, want %+v -- InputDigest must be sha256(rawInput), the same digest "+
			"internal/pdpgrpc/server.go's appendAudit computes for the audit chain (W2)", got, want)
	}
}

// TestTokenExpiry_DecodesExpClaimWithoutVerifyingSignature reuses
// signedTestToken (cache_validity_test.go) -- a syntactically real JWT signed
// with a throwaway key nothing here ever checks -- to prove tokenExpiry reads
// the same claim tokenNotExpired does, unverified, on purpose (K2: the PDP is
// the only verifier).
func TestTokenExpiry_DecodesExpClaimWithoutVerifyingSignature(t *testing.T) {
	want := time.Date(2030, 3, 4, 5, 6, 7, 0, time.UTC)
	got, ok := tokenExpiry(signedTestToken(t, want))
	if !ok {
		t.Fatal("tokenExpiry() ok = false, want true for a well-formed token carrying an exp claim")
	}
	if !got.Equal(want) {
		t.Errorf("tokenExpiry() = %v, want %v", got, want)
	}
}

func TestTokenExpiry_MalformedTokenFailsClosed(t *testing.T) {
	if _, ok := tokenExpiry("not-a-jwt-at-all"); ok {
		t.Error("tokenExpiry() ok = true for a string that is not a JWT, want false")
	}
}

// TestTokenExpiry_MissingExpClaimFailsClosed reuses tokenWithNoExpClaim
// (cache_validity_test.go) for the identical easy-to-miss reason
// TestTokenNotExpired_MissingExpClaimDenies exists: golang-jwt's
// GetExpirationTime reports a missing claim as (nil, nil), not an error.
func TestTokenExpiry_MissingExpClaimFailsClosed(t *testing.T) {
	if _, ok := tokenExpiry(tokenWithNoExpClaim(t)); ok {
		t.Error("tokenExpiry() ok = true for a token with no exp claim, want false")
	}
}

// testSess builds a *pdpgrpc.CreateDelegationResponse the way loadSessionFile
// would hand one to consultCache's caller -- the one
// argument shape this file's own package doc says is what keeps
// extauthz.go/proxy.go from calling either function by accident.
func testSess(delegationID, token string, epoch int64) *pdpgrpc.CreateDelegationResponse {
	return &pdpgrpc.CreateDelegationResponse{DelegationId: delegationID, Token: token, Epoch: epoch}
}

// TestConsultCache_HitReturnsStoredDecision proves consultCache's own field plumbing end to end: a
// stored entry matching sess's delegation id, the requested tool/rawInput, and the cache's own
// recorded epoch is found and returned. sess's OWN epoch (111) deliberately matches NEITHER the
// entry's epoch (9) nor anything else -- a hit here can only be explained by consultCache reading
// the epoch from the cache, not from sess (see TestConsultCache_EpochComesFromCacheMaxNotSess below
// for the dedicated regression test this fixture's choice is backed by).
func TestConsultCache_HitReturnsStoredDecision(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token := signedTestToken(t, now.Add(time.Hour))
	sess := testSess("deleg-consult", token, 111)

	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-consult", "Bash", "ls -la"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               9,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	entry, hit := consultCache(c, time.Hour, sess, "Bash", "ls -la", now)
	if !hit {
		t.Fatal("consultCache() hit = false, want true for a seeded, valid entry")
	}
	if entry.Decision != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Errorf("consultCache() Decision = %v, want ALLOW", entry.Decision)
	}
}

// --- Epoch sourcing: local_cache.go's package doc, "WHERE THE EPOCH COMES FROM," has the full
// account of the bug these tests are the regression suite for: validating against sess.GetEpoch()
// (frozen at session-start) instead of the cache's own recorded epochs would make every entry fail
// permanently the moment any control-plane write anywhere in the tenant bumped the real epoch
// once. Every fixture below sets sess's own epoch to a value that matches NEITHER entry,
// specifically so a hit or miss here can only be explained by the cache's maxEpoch, never by an
// accidental agreement with sess. ---

// TestConsultCache_EpochComesFromCacheMaxNotSess is "an entry stored after a bump is served on
// the next call" -- the case that was broken before this fix. sess's own epoch (5) is frozen at
// session-start and matches neither entry; the target entry's own epoch (10) matches the cache's
// TRUE max instead (set by a second, unrelated entry simulating some other call having already
// observed the bump), and must hit on that basis alone. Under the original, buggy implementation
// this would have compared 10 against sess's frozen 5 and missed.
func TestConsultCache_EpochComesFromCacheMaxNotSess(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token := signedTestToken(t, now.Add(time.Hour))
	sess := testSess("deleg-bump", token, 5) // frozen at session-start; matches neither entry below

	// A different key, same delegation: simulates some OTHER call already having observed the
	// tenant epoch move to 10, which is what makes 10 the cache's own true max.
	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-bump", "OtherTool", "other input"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               10,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-bump", "Bash", "ls"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               10,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	if _, hit := consultCache(c, time.Hour, sess, "Bash", "ls", now); !hit {
		t.Error("consultCache() hit = false, want true -- the entry's own epoch (10) matches the " +
			"cache's true max (10); the original bug compared it against sess's frozen epoch (5) instead " +
			"and would have missed here")
	}
}

// TestConsultCache_EntryBelowMaxEpoch_IsNotServed is "an entry stored before a bump is not
// served after it": sess's own (frozen, irrelevant) epoch here is set to MATCH the stale entry --
// exactly the shape that would have produced an incorrect hit under the original, buggy
// implementation -- and it must still miss, because a second, newer entry in the same cache proves
// this PEP has since observed a later epoch.
func TestConsultCache_EntryBelowMaxEpoch_IsNotServed(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	token := signedTestToken(t, now.Add(time.Hour))
	sess := testSess("deleg-stale", token, 7) // matches the STALE entry -- must not save it

	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-stale", "Bash", "ls"),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               7, // computed before the bump
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-10 * time.Minute),
	})
	// A newer entry, any other key: proves this PEP has since observed epoch 8.
	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-stale", "OtherTool", "other input"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               8,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	if _, hit := consultCache(c, time.Hour, sess, "Bash", "ls", now); hit {
		t.Error("consultCache() hit = true for an entry cached before a bump this cache's own newer " +
			"entry proves happened, want a miss (C20)")
	}
}

// TestConsultCache_FreshEmptyCache_MissesCleanly is "a fresh session with an empty cache misses
// cleanly": a cache nothing has been stored in -- a new process's first call -- must not
// error, panic, or hit; there is nothing yet to serve. Also the baseline every hit test above
// implicitly relies on.
func TestConsultCache_FreshEmptyCache_MissesCleanly(t *testing.T) {
	c := newDecisionCache()
	sess := testSess("deleg-fresh", signedTestToken(t, time.Now().Add(time.Hour)), 1)

	if _, hit := consultCache(c, time.Hour, sess, "Bash", "ls", time.Now()); hit {
		t.Error("consultCache() hit = true against an empty cache, want a clean miss")
	}
}

// TestConsultCache_OutageWithNoNewWrites_StillServesAtMaxUntilStalenessCloses is "an outage with no
// new writes still serves entries at max until the staleness window closes": with only ONE entry
// ever written -- nothing new arriving, as in a real outage -- repeated lookups keep hitting for as
// long as they fall inside the staleness window, entirely on the strength of that one entry's own
// recorded epoch (which is trivially the cache's own max, being the only entry) and CachedAt, and
// stop the instant they fall outside it.
func TestConsultCache_OutageWithNoNewWrites_StillServesAtMaxUntilStalenessCloses(t *testing.T) {
	c := newDecisionCache()
	cachedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const staleness = 10 * time.Minute
	token := signedTestToken(t, cachedAt.Add(24*time.Hour))
	sess := testSess("deleg-outage", token, 3)

	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-outage", "Bash", "ls"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               3,
		DelegationExpiresAt: cachedAt.Add(48 * time.Hour),
		CachedAt:            cachedAt,
	})

	// Two lookups, still inside the window, no writes in between -- both must hit.
	for _, elapsed := range []time.Duration{time.Minute, staleness} {
		if _, hit := consultCache(c, staleness, sess, "Bash", "ls", cachedAt.Add(elapsed)); !hit {
			t.Errorf("consultCache() at now=CachedAt+%s hit = false, want true (still within the %s "+
				"staleness window, no new writes)", elapsed, staleness)
		}
	}
	// One nanosecond past the window: the same entry, still the only one in the cache, must now miss.
	if _, hit := consultCache(c, staleness, sess, "Bash", "ls", cachedAt.Add(staleness+time.Nanosecond)); hit {
		t.Error("consultCache() hit = true one nanosecond past the staleness window, want false (C19)")
	}
}

// TestConsultCache_UsesSessTokenNotEntryOrHardcoded proves the token half of "which source
// consultCache reads condition 3 from" still holds after the epoch fix above: an entry that is
// otherwise perfectly valid (current epoch, unexpired delegation, within the staleness window)
// must still miss if the CALLER'S OWN presented token -- sess.GetToken(), not anything the entry
// itself recorded -- has expired.
func TestConsultCache_UsesSessTokenNotEntryOrHardcoded(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	expiredToken := signedTestToken(t, now.Add(-time.Hour)) // sess's own token has already expired
	sess := testSess("deleg-token-source", expiredToken, 4)

	mustCachePut(t, c, cacheEntry{
		cacheKey:            cacheKeyFor("deleg-token-source", "Bash", "ls"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               4, // matches the cache's own max (the only entry) -- not what this test defends
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	if _, hit := consultCache(c, time.Hour, sess, "Bash", "ls", now); hit {
		t.Error("consultCache() hit = true despite sess's own token having expired, want a miss (C24 credential half)")
	}
}

// TestMaxCacheEpoch_EmptyCache_ReturnsZero pins the "no data" default (cache.go's own doc comment
// on maxEpoch explains why 0 is inert).
func TestMaxCacheEpoch_EmptyCache_ReturnsZero(t *testing.T) {
	if got := newDecisionCache().maxEpoch(); got != 0 {
		t.Errorf("maxEpoch() = %d, want 0 for an empty cache", got)
	}
}

// TestMaxCacheEpoch_ReturnsHighestAcrossAllEntries proves the actual computation: the highest
// Epoch among every entry in the cache, regardless of insertion order or which key each belongs to.
func TestMaxCacheEpoch_ReturnsHighestAcrossAllEntries(t *testing.T) {
	c := newDecisionCache()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, epoch := range []int64{3, 11, 7} { // deliberately NOT inserted in ascending order
		mustCachePut(t, c, cacheEntry{
			cacheKey:            cacheKeyFor(fmt.Sprintf("deleg-%d", i), "Bash", "ls"),
			Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
			Epoch:               epoch,
			DelegationExpiresAt: base.Add(time.Hour),
			CachedAt:            base,
		})
	}
	if got := c.maxEpoch(); got != 11 {
		t.Errorf("maxEpoch() = %d, want 11 (the highest of 3, 11, 7)", got)
	}
}

// TestStoreCacheResult_WritesRetrievableEntry proves the write side's field plumbing: the entry
// get finds afterward carries resp's own Decision and Epoch, and a DelegationExpiresAt decoded
// from token's exp claim -- not sess's, not a zero value.
func TestStoreCacheResult_WritesRetrievableEntry(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	wantExpiry := now.Add(3 * time.Hour)
	token := signedTestToken(t, wantExpiry)
	epoch := int64(77)
	resp := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Epoch: &epoch, Reason: "not stored -- see cache.go's own doc comment"}

	storeCacheResult(c, "deleg-store", "Read", "raw", token, resp, now)

	got, ok := c.get(cacheKeyFor("deleg-store", "Read", "raw"))
	if !ok {
		t.Fatal("get() ok = false after storeCacheResult, want the entry it just stored")
	}
	if got.Decision != pdpgrpc.Effect_EFFECT_DENY {
		t.Errorf("Decision = %v, want DENY (resp's own effect)", got.Decision)
	}
	if got.Epoch != epoch {
		t.Errorf("Epoch = %d, want %d (resp's own epoch)", got.Epoch, epoch)
	}
	if !got.DelegationExpiresAt.Equal(wantExpiry) {
		t.Errorf("DelegationExpiresAt = %v, want %v (token's own exp claim, decoded)", got.DelegationExpiresAt, wantExpiry)
	}
}

// TestStoreCacheResult_UsesInjectedNowNotWallClock: storeCacheResult takes now as an explicit parameter specifically
// so a caller can capture one instant across a whole decide-and-cache flow (cache.go's own
// cacheEntry doc comment) -- but nothing about TestStoreCacheResult_WritesRetrievableEntry above
// would notice CachedAt silently being stamped from time.Now() instead of now, since the few
// microseconds between the injected value and the real clock in that test are not an observable
// difference. Anchoring now to 1999, mirroring cache_validity_test.go's own
// TestWithinStalenessWindow_UsesInjectedNowNotWallClock, makes the two impossible to confuse: only a
// build that genuinely uses the now parameter can produce a CachedAt this far from the real clock.
func TestStoreCacheResult_UsesInjectedNowNotWallClock(t *testing.T) {
	c := newDecisionCache()
	now := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	resp := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}

	storeCacheResult(c, "deleg-clock", "Bash", "raw", signedTestToken(t, now.Add(time.Hour)), resp, now)

	got, ok := c.get(cacheKeyFor("deleg-clock", "Bash", "raw"))
	if !ok {
		t.Fatal("get() ok = false, want the entry storeCacheResult just stored")
	}
	if !got.CachedAt.Equal(now) {
		t.Errorf("CachedAt = %v, want %v (the injected now) -- a build reading the real wall clock "+
			"instead would produce a CachedAt near the actual test run time, decades later", got.CachedAt, now)
	}
}

// TestStoreCacheResult_RefusesAnEscalation is storeCacheResult's own guard, defended independently
// of cache.go's put -- see local_cache.go's package doc, "WHY AN ESCALATION IS NEVER CACHED, EVEN
// RESOLVED."
func TestStoreCacheResult_RefusesAnEscalation(t *testing.T) {
	c := newDecisionCache()
	resp := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE, ApprovalId: "approval-1"}

	storeCacheResult(c, "deleg-escalate", "Bash", "raw", signedTestToken(t, time.Now().Add(time.Hour)), resp, time.Now())

	if _, ok := c.get(cacheKeyFor("deleg-escalate", "Bash", "raw")); ok {
		t.Error("get() found an entry after storeCacheResult was called with an ESCALATE response, want nothing stored")
	}
}

// TestStoreCacheResult_UndecodableTokenSkipsTheWriteWithoutPanicking exercises the one defensive
// branch storeCacheResult has that the ordinary decideAndRelay flow can never actually
// reach in practice (see that branch's own doc comment for why): a token that does not decode an
// expiry at all. The property under test is narrow but real -- this must not panic, and must not
// write a zero-DelegationExpiresAt entry that would silently occupy a cache slot it can never win a
// hit from.
func TestStoreCacheResult_UndecodableTokenSkipsTheWriteWithoutPanicking(t *testing.T) {
	c := newDecisionCache()
	resp := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}

	storeCacheResult(c, "deleg-bad-token", "Bash", "raw", "not-a-jwt-at-all", resp, time.Now())

	if _, ok := c.get(cacheKeyFor("deleg-bad-token", "Bash", "raw")); ok {
		t.Error("get() found an entry written from an undecodable token, want nothing stored")
	}
}
