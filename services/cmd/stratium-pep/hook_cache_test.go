// hook_cache_test.go tests the decision cache's wiring into runHook (Task 3,
// spec §4.8.3 W6): hook is one of the two surfaces permitted to consult and
// populate the cache at all. See local_cache.go's own package doc for why
// that boundary sits at the type level, not merely in these tests'
// behavior, and extauthz_test.go's/proxy_test.go's own W6 tests for the
// other half of this property -- proving the two surfaces this file does
// NOT touch never gain a cache path either.
//
// Every fixture below writes a REAL, parseable, signed JWT as the session
// token (signedTestToken, cache_validity_test.go) rather than reusing
// testCfg's own bare testSessionToken constant: tokenNotExpired/tokenExpiry
// (cache.go, local_cache.go) both require a decodable "exp" claim, and
// testSessionToken is not a JWT at all -- it would fail every cache-hit and
// cache-store assertion below for a reason that has nothing to do with the
// property under test.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/pdpgrpc"
)

// hookCacheFixture writes a session file naming a fresh delegation id and a
// real signed token expiring at tokenExpiresAt -- everything a cache test
// needs beyond testCfg's own baseline, which cannot be reused unmodified
// here (see this file's own package doc). Deliberately does NOT set the
// session file's own Epoch field: consultCache no longer reads it (see
// local_cache.go's package doc, "WHERE THE EPOCH COMES FROM") -- lastKnownEpoch
// comes from the cache file's own recorded entries, which each test below
// controls directly by seeding whatever entries the property under test
// needs, not by this fixture.
func hookCacheFixture(t *testing.T, tokenExpiresAt time.Time) (cfg hookConfig, delegationID, token string) {
	t.Helper()
	cfg = testCfg(t)
	delegationID = uuid.NewString()
	token = signedTestToken(t, tokenExpiresAt)
	data, err := json.Marshal(&pdpgrpc.CreateDelegationResponse{DelegationId: delegationID, Token: token})
	if err != nil {
		t.Fatalf("marshal session fixture: %v", err)
	}
	if err := os.WriteFile(cfg.SessionFilePath, data, sessionFileMode); err != nil {
		t.Fatalf("write session fixture: %v", err)
	}
	return cfg, delegationID, token
}

// seedHookCache writes entry into the cache file beside cfg's own session
// file -- the exact path derivation runHook itself uses (cacheFilePathFor,
// local_cache.go) -- so a test can construct a hit fixture without reaching
// into runHook's own internals.
func seedHookCache(t *testing.T, cfg hookConfig, entry cacheEntry) {
	t.Helper()
	mustCachePut(t, cacheFilePathFor(cfg.SessionFilePath), entry)
}

// TestRunHook_CacheHit_Allow_ServesWithoutContactingPDP is the property this
// whole task exists for: a valid cached ALLOW is served with the PDP never
// dialed at all. fake would itself answer ALLOW if ever called, so a build
// that ignored the cache entirely would still pass a bare "exit code == 0"
// check -- requestCount() is the load-bearing assertion, per the task
// brief's own "assert it directly: the PDP client must not be contacted"
// instruction. This is also the mutation-testing anchor for "call the PDP
// anyway on a hit."
func TestRunHook_CacheHit_Allow_ServesWithoutContactingPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "Bash", `{"command":"ls"}`),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg, testCacheCfg)

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (cached ALLOW); stdout: %s", code, stdout.String())
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a cache hit must never contact the PDP "+
			"(this is the outage tolerance this phase exists to buy)", got)
	}
}

// TestRunHook_CacheHit_Deny_ServesWithoutContactingPDP is the DENY twin of
// the ALLOW test above: a cached DENY serves too, without contacting the
// PDP, and with a reason that says so rather than fabricating a policy
// explanation the cache never stored (cache.go's own cacheEntry carries no
// Reason field at all -- local_cache.go's cacheHitDenyReason doc comment
// explains why).
func TestRunHook_CacheHit_Deny_ServesWithoutContactingPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "Bash", `{"command":"rm -rf /"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}} // would ALLOW if ever contacted
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"rm -rf /"}`), &stdout, client, cfg, testCacheCfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2 (cached DENY)", code)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a cache hit must never contact the PDP", got)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecisionReason != cacheHitDenyReason {
		t.Errorf("permissionDecisionReason = %q, want the cache-hit reason %q -- never a reason implying "+
			"this process just computed a fresh policy verdict", out.HookSpecificOutput.PermissionDecisionReason, cacheHitDenyReason)
	}
}

// TestRunHook_CacheHit_StaleEpoch_FallsThroughToPDP is the mutation-testing anchor for "serve a
// hit without checking validity" (e.g. swapping cacheGetValid for a bare cacheGet inside
// consultCache, local_cache.go): a SECOND, unrelated entry in the same cache file (a different
// tool/input) proves this PEP has observed a newer epoch than the target entry was cached under --
// exactly the "an entry stored before a bump is not served after it" property local_cache_test.go's
// own TestConsultCache_EntryBelowFileMaxEpoch_IsNotServed defends directly, proven here end to end
// through runHook. The two decisions are deliberately opposite (cached DENY vs. live ALLOW) so a
// build that wrongly served the stale entry would flip the observable exit code, not just the
// internal call count.
func TestRunHook_CacheHit_StaleEpoch_FallsThroughToPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "Bash", `{"command":"ls"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               41, // computed before the bump
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	// A different tool/input, same delegation: proves this PEP has since observed epoch 42 --
	// what makes 42, not 41, the cache file's own true max.
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "OtherTool", "other input"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg, testCacheCfg)

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 -- the stale entry must be ignored and the PDP's live ALLOW must govern", code)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- an entry cached below the file's own "+
			"max epoch is a miss, not a hit, so this must still ask the PDP (a mutation serving any cacheGet "+
			"hit regardless of validity would leave this at 0 and the exit code at 2)", got)
	}
}

// TestRunHook_CacheMiss_CallsPDPAndStoresResult is the other property this
// task exists for: a miss reaches the PDP exactly once, and the live
// decision is written to the cache file afterward, keyed and valued so a
// LATER identical call could find it.
func TestRunHook_CacheMiss_CallsPDPAndStoresResult(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	epoch := int64(42)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: &epoch, Reason: "policy allows"}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg, testCacheCfg)

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0", code)
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s), want exactly 1 -- a miss must ask the PDP", got)
	}

	stored, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "Bash", `{"command":"ls"}`))
	if !ok {
		t.Fatal("cacheGet() ok = false after a live ALLOW, want the decision to have been stored")
	}
	if stored.Decision != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Errorf("stored Decision = %v, want ALLOW", stored.Decision)
	}
	if stored.Epoch != 42 {
		t.Errorf("stored Epoch = %d, want 42 (the PDP's own response epoch)", stored.Epoch)
	}
}

// TestRunHook_CacheMissUnreachablePDP_DeniesWithDistinguishingReason is the
// task brief's third required test: a miss with an unreachable PDP denies
// with a reason distinguishing "no cached decision and the PDP is
// unreachable" from an ordinary policy denial. Both phrases are checked
// independently so a build reporting only one or the other still fails.
func TestRunHook_CacheMissUnreachablePDP_DeniesWithDistinguishingReason(t *testing.T) {
	cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	client := unreachablePDPClient(t)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg, testCacheCfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "no cached decision") {
		t.Errorf("permissionDecisionReason = %q, want it to say no cached decision was available -- "+
			"distinguishing this from an ordinary policy denial, per the task brief", reason)
	}
	if !strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("permissionDecisionReason = %q, want it to also say the PDP could not be reached", reason)
	}
}

// TestRunHook_Escalate_ApprovedOutcome_NeverStoredInCache is the task
// brief's fourth required test, and the mutation-testing anchor for "store
// an escalation": after an ESCALATE resolves -- here, all the way to an
// approved ALLOW -- nothing is ever written to the cache for that key. This
// is stricter than W4's literal text (which only bars caching the raw
// ESCALATE value) on purpose: see local_cache.go's package doc, "WHY AN
// ESCALATION IS NEVER CACHED, EVEN RESOLVED," for why the RESOLVED outcome
// must not be cached either.
func TestRunHook_Escalate_ApprovedOutcome_NeverStoredInCache(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:                 escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{{Status: "approved"}},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, wrapped, cfg, testCacheCfg)

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (escalated, then approved)", code)
	}
	if _, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "Bash", `{"command":"drop the prod table"}`)); ok {
		t.Error("cacheGet() found an entry after an escalation resolved to ALLOW, want nothing stored -- " +
			"a human's approval is a decision about ONE moment, never a general, replayable verdict (W4)")
	}
}

// TestRunHook_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry defends
// storeCacheResult's own req.GetToken()-not-sess.GetToken() choice
// (local_cache.go's own doc comment): the session file's ORIGINAL token
// (soon-expiring, driving the first DENY) is replaced in place by
// reissueAndRetryDecide before the retry succeeds, and the entry this call
// stores must record the FRESH token's own expiry, not the stale original's
// -- the two are set far enough apart here that a mixup fails obviously
// rather than by coincidence.
func TestRunHook_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry(t *testing.T) {
	now := time.Now()
	staleExpiry := now.Add(time.Minute)
	cfg, delegationID, _ := hookCacheFixture(t, staleExpiry)

	// Truncated to whole seconds: a JWT "exp" claim is a Unix timestamp (signedTestToken's own
	// expiresAt.Unix()), so tokenExpiry's decode can never return sub-second precision -- comparing
	// against an untruncated now.Add(...) would fail this test on a precision mismatch that has
	// nothing to do with the property under test (which token's expiry got stored).
	freshExpiry := now.Add(6 * time.Hour).Truncate(time.Second)
	reissuedToken := signedTestToken(t, freshExpiry)
	fake := &fakePDP{
		resp:      &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueResp: &pdpgrpc.IssueTokenResponse{Token: reissuedToken},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, wrapped, cfg, testCacheCfg)

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (reissue then an allowing retry); stdout: %s", code, stdout.String())
	}
	stored, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "Bash", `{"command":"ls"}`))
	if !ok {
		t.Fatal("cacheGet() ok = false, want the post-reissue decision to have been stored")
	}
	if !stored.DelegationExpiresAt.Equal(freshExpiry) {
		t.Errorf("stored DelegationExpiresAt = %v, want %v (the REISSUED token's own exp claim) -- "+
			"sourcing it from sess.GetToken() instead of the token that actually produced this decision "+
			"would record the stale original token's expiry here instead", stored.DelegationExpiresAt, freshExpiry)
	}
}
