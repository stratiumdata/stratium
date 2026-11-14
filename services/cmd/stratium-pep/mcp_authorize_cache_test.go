// mcp_authorize_cache_test.go is mcp's own mirror of hook_cache_test.go: the
// decision cache's wiring into decideAndRelay (Task 3, spec §4.8.3 W6) --
// mcp is the second, and last, surface permitted to consult and populate the
// cache. See local_cache.go's own package doc for the boundary this and
// hook_cache_test.go both exercise, and extauthz_test.go's/proxy_test.go's
// own W6 tests for the other half: the two surfaces that must NEVER gain a
// cache path.
//
// hookCacheFixture (hook_cache_test.go) is reused unmodified: it writes a
// real, parseable, signed JWT session token, which every cache-validity- or
// cache-store-dependent test here needs for the identical reason
// hook_cache_test.go's own package doc states (testCfg's bare
// testSessionToken is not a JWT and cannot be decoded).
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// TestDecideAndRelay_CacheHit_Allow_ForwardsWithoutContactingPDP is the mcp
// twin of TestRunHook_CacheHit_Allow_ServesWithoutContactingPDP: a valid
// cached ALLOW forwards the original frame with the PDP never dialed. fake
// would itself answer ALLOW if ever called, so requestCount() -- not the
// forwarded frame alone -- is what actually proves the cache, not a live
// decision, served this call. Mutation-testing anchor for "call the PDP
// anyway on a hit."
func TestDecideAndRelay_CacheHit_Allow_ForwardsWithoutContactingPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/notes.txt"}`),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/notes.txt"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Fatalf("upstream received %q, want the original request %q forwarded unchanged", got, req)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a cache hit must never contact the PDP", got)
	}
}

// TestDecideAndRelay_CacheHit_Deny_DeniesWithoutContactingPDP is the DENY
// twin: a cached DENY produces a correlated JSON-RPC error carrying
// cacheHitDenyReason, never reaches upstream, and never contacts the PDP.
func TestDecideAndRelay_CacheHit_Deny_DeniesWithoutContactingPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "delete_file", `{"path":"/etc/passwd"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}} // would ALLOW if ever contacted
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":"req-9","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if out.Error.Message != cacheHitDenyReason {
		t.Errorf("error.message = %q, want the cache-hit reason %q", out.Error.Message, cacheHitDenyReason)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a cache hit must never contact the PDP", got)
	}
}

// TestDecideAndRelay_CacheHit_StaleEpoch_FallsThroughToPDP is mcp's own mutation-testing anchor
// for "serve a hit without checking validity": a SECOND, unrelated entry in the same cache file
// proves this PEP has observed a newer epoch than the target entry was cached under (mirroring
// hook_cache_test.go's identical fix, and local_cache_test.go's
// TestConsultCache_EntryBelowFileMaxEpoch_IsNotServed at the direct-unit layer) -- so the entry
// must be a miss, and the PDP's own live (opposite) answer must be what reaches the agent.
func TestDecideAndRelay_CacheHit_StaleEpoch_FallsThroughToPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               41, // computed before the bump
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	// A different tool/input, same delegation: proves this PEP has since observed epoch 42 --
	// what makes 42, not 41, the cache file's own true max.
	seedHookCache(t, cfg, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "other_tool", "other input"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Fatalf("upstream received %q, want the original request forwarded -- the PDP's live ALLOW must govern", got)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- an entry cached under a stale epoch "+
			"is a miss, not a hit, so this must still ask the PDP", got)
	}
}

// TestDecideAndRelay_CacheMiss_CallsPDPAndStoresResult is mcp's own version
// of the task brief's second required test.
func TestDecideAndRelay_CacheMiss_CallsPDPAndStoresResult(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	epoch := int64(42)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: &epoch, Reason: "policy allows"}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Fatalf("upstream received %q, want the original request forwarded", got)
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s), want exactly 1 -- a miss must ask the PDP", got)
	}

	stored, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`))
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

// TestDecideAndRelay_CacheMissUnreachablePDP_DeniesWithDistinguishingReason
// is mcp's own version of the task brief's third required test.
func TestDecideAndRelay_CacheMissUnreachablePDP_DeniesWithDistinguishingReason(t *testing.T) {
	cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	client := unreachablePDPClient(t)
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	msg := out.Error.Message
	if !strings.Contains(msg, "no cached decision") {
		t.Errorf("error.message = %q, want it to say no cached decision was available -- distinguishing "+
			"this from an ordinary policy denial, per the task brief", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "could not reach") {
		t.Errorf("error.message = %q, want it to also say the PDP could not be reached", msg)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// TestDecideAndRelay_Escalate_ApprovedOutcome_NeverStoredInCache is mcp's
// own version of the task brief's fourth required test, and the
// mutation-testing anchor for "store an escalation." See
// TestRunHook_Escalate_ApprovedOutcome_NeverStoredInCache (hook_cache_test.go)
// and local_cache.go's package doc for why the RESOLVED outcome must not be
// cached either, not only the raw ESCALATE value.
func TestDecideAndRelay_Escalate_ApprovedOutcome_NeverStoredInCache(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:                 escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{{Status: "approved"}},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}
	h := newMCPHarness(t, wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"prod"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, 2*time.Second); string(got) != req {
		t.Fatalf("upstream received %q, want the original request forwarded after approval", got)
	}

	if _, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "deploy", `{"env":"prod"}`)); ok {
		t.Error("cacheGet() found an entry after an escalation resolved to ALLOW, want nothing stored -- " +
			"a human's approval is a decision about ONE moment, never a general, replayable verdict (W4)")
	}
}

// TestDecideAndRelay_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry
// is mcp's own version of TestRunHook_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry
// (hook_cache_test.go) -- see that test's own doc comment for the property
// defended and why the two expiries are set far enough apart to fail
// obviously on a mixup.
func TestDecideAndRelay_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry(t *testing.T) {
	now := time.Now()
	staleExpiry := now.Add(time.Minute)
	cfg, delegationID, _ := hookCacheFixture(t, staleExpiry)

	freshExpiry := now.Add(6 * time.Hour).Truncate(time.Second)
	reissuedToken := signedTestToken(t, freshExpiry)
	fake := &fakePDP{
		resp:      &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueResp: &pdpgrpc.IssueTokenResponse{Token: reissuedToken},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}
	h := newMCPHarness(t, wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Fatalf("upstream received %q, want the original request forwarded after reissue", got)
	}

	stored, ok := cacheGet(cacheFilePathFor(cfg.SessionFilePath), cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`))
	if !ok {
		t.Fatal("cacheGet() ok = false, want the post-reissue decision to have been stored")
	}
	if !stored.DelegationExpiresAt.Equal(freshExpiry) {
		t.Errorf("stored DelegationExpiresAt = %v, want %v (the REISSUED token's own exp claim)", stored.DelegationExpiresAt, freshExpiry)
	}
}
