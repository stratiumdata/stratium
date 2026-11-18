// mcp_authorize_cache_test.go tests the decision cache's wiring into
// decideAndRelay: mcp is the one surface that has a cache, and it lives only
// in this process's memory (cache.go's package doc, "Memory only"). See
// local_cache.go's own package doc for the boundary, and extauthz_test.go's/
// proxy_test.go's own W6 tests for the surfaces that must NEVER gain a cache
// path.
//
// Two styles of test, on purpose. The ones that need to seed or inspect the
// cache build an mcpAuthorizer directly (newTestAuthorizer) and call
// decideAndRelay synchronously. The ones that pin WHERE the cache comes
// from -- a forged file on disk, a restart -- go through runMCP itself
// (newMCPHarness), because the property is about what runMCP starts with.
//
// hookCacheFixture (hook_cache_test.go) supplies a session file with a real,
// parseable, signed JWT, which every cache-validity-dependent test needs.
package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// newTestAuthorizer builds an mcpAuthorizer the way runMCP does, with an
// empty cache the test can seed and inspect, and plain buffers for the two
// destinations (decideAndRelay is called synchronously, so nothing else
// writes to them).
func newTestAuthorizer(client pdpgrpc.PDPServiceClient, cfg hookConfig) (a *mcpAuthorizer, upstream, agent *bytes.Buffer) {
	upstream, agent = &bytes.Buffer{}, &bytes.Buffer{}
	a = &mcpAuthorizer{client: client, cfg: cfg, cacheCfg: testCacheCfg, cache: newDecisionCache(), upstreamIn: upstream, agentOut: agent}
	return a, upstream, agent
}

// TestDecideAndRelay_CacheHit_Allow_ForwardsWithoutContactingPDP: a valid
// cached ALLOW forwards the original frame with the PDP never dialed. fake
// would itself answer ALLOW if ever called, so requestCount() -- not the
// forwarded frame alone -- is what proves the cache served this call.
// Mutation-testing anchor for "call the PDP anyway on a hit."
func TestDecideAndRelay_CacheHit_Allow_ForwardsWithoutContactingPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	a, upstream, _ := newTestAuthorizer(startFakePDP(t, fake), cfg)
	mustCachePut(t, a.cache, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/notes.txt"}`),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/notes.txt"}}}`
	a.decideAndRelay([]byte(req))

	if got := strings.TrimSuffix(upstream.String(), "\n"); got != req {
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}} // would ALLOW if ever contacted
	a, upstream, agent := newTestAuthorizer(startFakePDP(t, fake), cfg)
	mustCachePut(t, a.cache, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "delete_file", `{"path":"/etc/passwd"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	const req = `{"jsonrpc":"2.0","id":"req-9","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}`
	a.decideAndRelay([]byte(req))

	out := decodeJSONRPCError(t, bytes.TrimSpace(agent.Bytes()))
	if out.Error.Message != cacheHitDenyReason {
		t.Errorf("error.message = %q, want the cache-hit reason %q", out.Error.Message, cacheHitDenyReason)
	}
	if upstream.Len() != 0 {
		t.Errorf("upstream received %q, want nothing forwarded for a cached DENY", upstream.String())
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a cache hit must never contact the PDP", got)
	}
}

// TestDecideAndRelay_CacheHit_StaleEpoch_FallsThroughToPDP is the
// mutation-testing anchor for "serve a hit without checking validity": a
// SECOND, unrelated entry in the same cache proves this process has observed
// a newer epoch than the target entry was cached under -- so the entry must
// be a miss, and the PDP's own live (opposite) answer must be what reaches
// the agent.
func TestDecideAndRelay_CacheHit_StaleEpoch_FallsThroughToPDP(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Hour))
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
	a, upstream, _ := newTestAuthorizer(startFakePDP(t, fake), cfg)
	mustCachePut(t, a.cache, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`),
		Decision:            pdpgrpc.Effect_EFFECT_DENY,
		Epoch:               41, // computed before the bump
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})
	// A different tool/input, same delegation: what makes 42, not 41, the
	// cache's own max epoch.
	mustCachePut(t, a.cache, cacheEntry{
		cacheKey:            cacheKeyFor(delegationID, "other_tool", "other input"),
		Decision:            pdpgrpc.Effect_EFFECT_ALLOW,
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	})

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	a.decideAndRelay([]byte(req))

	if got := strings.TrimSuffix(upstream.String(), "\n"); got != req {
		t.Fatalf("upstream received %q, want the original request forwarded -- the PDP's live ALLOW must govern", got)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- an entry cached under a stale epoch "+
			"is a miss, not a hit, so this must still ask the PDP", got)
	}
}

// TestDecideAndRelay_CacheMiss_CallsPDPAndStoresResult: a miss reaches the
// PDP exactly once, and the live decision is stored afterward, keyed and
// valued so a LATER identical call could find it.
func TestDecideAndRelay_CacheMiss_CallsPDPAndStoresResult(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	epoch := int64(42)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: &epoch, Reason: "policy allows"}}
	a, upstream, _ := newTestAuthorizer(startFakePDP(t, fake), cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	a.decideAndRelay([]byte(req))

	if got := strings.TrimSuffix(upstream.String(), "\n"); got != req {
		t.Fatalf("upstream received %q, want the original request forwarded", got)
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s), want exactly 1 -- a miss must ask the PDP", got)
	}
	stored, ok := a.cache.get(cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`))
	if !ok {
		t.Fatal("get() ok = false after a live ALLOW, want the decision to have been stored")
	}
	if stored.Decision != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Errorf("stored Decision = %v, want ALLOW", stored.Decision)
	}
	if stored.Epoch != 42 {
		t.Errorf("stored Epoch = %d, want 42 (the PDP's own response epoch)", stored.Epoch)
	}
}

// TestDecideAndRelay_CacheMissUnreachablePDP_DeniesWithDistinguishingReason:
// a miss with an unreachable PDP denies with a reason distinguishing "no
// cached decision and the PDP is unreachable" from an ordinary policy
// denial. Both phrases are checked independently.
func TestDecideAndRelay_CacheMissUnreachablePDP_DeniesWithDistinguishingReason(t *testing.T) {
	cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	a, upstream, agent := newTestAuthorizer(unreachablePDPClient(t), cfg)

	a.decideAndRelay([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`))

	msg := decodeJSONRPCError(t, bytes.TrimSpace(agent.Bytes())).Error.Message
	if !strings.Contains(msg, "no cached decision") {
		t.Errorf("error.message = %q, want it to say no cached decision was available", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "could not reach") {
		t.Errorf("error.message = %q, want it to also say the PDP could not be reached", msg)
	}
	if upstream.Len() != 0 {
		t.Errorf("upstream received %q, want nothing forwarded", upstream.String())
	}
}

// TestDecideAndRelay_Escalate_ApprovedOutcome_NeverStoredInCache is the
// mutation-testing anchor for "store an escalation": after an ESCALATE
// resolves -- here, all the way to an approved ALLOW -- nothing is stored
// for that key. Stricter than W4's literal text on purpose; see
// local_cache.go's package doc, "WHY AN ESCALATION IS NEVER CACHED, EVEN
// RESOLVED."
func TestDecideAndRelay_Escalate_ApprovedOutcome_NeverStoredInCache(t *testing.T) {
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	fake := &fakePDP{
		resp:                 escalateResp(uuid.NewString()),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{{Status: "approved"}},
	}
	wrapped := &decideThenAllowClient{PDPServiceClient: startFakePDP(t, fake), first: fake.resp}
	a, upstream, _ := newTestAuthorizer(wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"prod"}}}`
	a.decideAndRelay([]byte(req))

	if got := strings.TrimSuffix(upstream.String(), "\n"); got != req {
		t.Fatalf("upstream received %q, want the original request forwarded after approval", got)
	}
	if _, ok := a.cache.get(cacheKeyFor(delegationID, "deploy", `{"env":"prod"}`)); ok {
		t.Error("get() found an entry after an escalation resolved to ALLOW, want nothing stored -- " +
			"a human's approval is a decision about ONE moment, never a general, replayable verdict (W4)")
	}
	if got := len(a.cache.entries); got != 0 {
		t.Errorf("cache holds %d entries after an escalation, want 0", got)
	}
}

// TestDecideAndRelay_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry
// defends storeCacheResult's req.GetToken()-not-sess.GetToken() choice: the
// session file's ORIGINAL token (soon-expiring, driving the first DENY) is
// replaced in place by reissueAndRetryDecide before the retry succeeds, and
// the stored entry must record the FRESH token's expiry. The two are set
// far enough apart that a mixup fails obviously.
func TestDecideAndRelay_CacheMiss_AfterReissue_StoresUnderReissuedTokenExpiry(t *testing.T) {
	now := time.Now()
	cfg, delegationID, _ := hookCacheFixture(t, now.Add(time.Minute))

	// Truncated to whole seconds: a JWT "exp" claim is a Unix timestamp.
	freshExpiry := now.Add(6 * time.Hour).Truncate(time.Second)
	fake := &fakePDP{
		resp:      &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueResp: &pdpgrpc.IssueTokenResponse{Token: signedTestToken(t, freshExpiry)},
	}
	wrapped := &decideThenAllowClient{PDPServiceClient: startFakePDP(t, fake), first: fake.resp}
	a, upstream, _ := newTestAuthorizer(wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	a.decideAndRelay([]byte(req))

	if got := strings.TrimSuffix(upstream.String(), "\n"); got != req {
		t.Fatalf("upstream received %q, want the original request forwarded after reissue", got)
	}
	stored, ok := a.cache.get(cacheKeyFor(delegationID, "read_file", `{"path":"/tmp/x"}`))
	if !ok {
		t.Fatal("get() ok = false, want the post-reissue decision to have been stored")
	}
	if !stored.DelegationExpiresAt.Equal(freshExpiry) {
		t.Errorf("stored DelegationExpiresAt = %v, want %v (the REISSUED token's own exp claim)", stored.DelegationExpiresAt, freshExpiry)
	}
}

// TestRunMCP_ForgedCacheFile_DoesNotProduceAHit is mcp's security pin: a
// cache file on disk holding an ALLOW for exactly this call (the format
// older versions read -- writeForgedAllowCacheFile, hook_cache_test.go) has
// no effect on a proxy started afterward. The PDP is asked, its DENY
// reaches the agent, and nothing reaches upstream. Catches a build that
// loads decisions from disk at startup or per call.
func TestRunMCP_ForgedCacheFile_DoesNotProduceAHit(t *testing.T) {
	const tool, args, pdpReason = "delete_file", `{"path":"/etc/passwd"}`, "policy denies this call"
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	writeForgedAllowCacheFile(t, cfg.SessionFilePath, delegationID, tool, args)
	fake := &fakePDP{
		resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason},
		// Fails the one reissue attempt a DENY triggers, so exactly one
		// Decide is the whole expected count.
		issueErr: status.Error(codes.PermissionDenied, "no reissue in this test"),
	}
	h := newMCPHarness(t, startFakePDP(t, fake), cfg)

	h.sendFromAgent(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, 2*time.Second))
	if out.Error.Code != mcpErrorCodeAuthorizationDenied {
		t.Errorf("error.code = %d, want %d", out.Error.Code, mcpErrorCodeAuthorizationDenied)
	}
	if out.Error.Message == cacheHitDenyReason {
		t.Errorf("error.message is the cache-hit reason, want a live denial from the PDP")
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- a forged cache file must not stand in for the PDP", got)
	}
}

// TestRunMCP_SecondIdenticalCallServedFromMemory_RestartAsksPDPAgain pins
// both halves of "one cache for the life of the process": inside one runMCP
// a second identical tools/call within the staleness window is served
// without the PDP, and a NEW runMCP against the same session file -- a
// restart -- starts empty and asks the PDP again. Catches a build with no
// cache at all (first half) and one whose cache outlives the process
// (second half).
func TestRunMCP_SecondIdenticalCallServedFromMemory_RestartAsksPDPAgain(t *testing.T) {
	cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	epoch := int64(42)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: &epoch}}
	client := startFakePDP(t, fake)
	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`

	first := newMCPHarness(t, client, cfg)
	for i := 1; i <= 2; i++ {
		first.sendFromAgent(t, req)
		if got := readFrame(t, first.upstreamReceived, 2*time.Second); string(got) != req {
			t.Fatalf("call %d: upstream received %q, want the original request forwarded", i, got)
		}
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s) for two identical calls in one process, want exactly 1 -- "+
			"the second must be served from memory", got)
	}

	restarted := newMCPHarness(t, client, cfg)
	restarted.sendFromAgent(t, req)
	if got := readFrame(t, restarted.upstreamReceived, 2*time.Second); string(got) != req {
		t.Fatalf("after restart: upstream received %q, want the original request forwarded", got)
	}
	if got := fake.requestCount(); got != 2 {
		t.Errorf("PDP received %d Decide call(s) in total, want 2 -- a new process starts with an empty cache "+
			"and must ask the PDP again", got)
	}
}
