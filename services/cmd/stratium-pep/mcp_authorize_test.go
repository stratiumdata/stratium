package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// decodeJSONRPCError parses raw as the one frame shape this proxy ever authors itself -- mirrors
// hook_test.go's decodeHookOutput for the other surface's own synthesized output.
func decodeJSONRPCError(t *testing.T, raw []byte) jsonrpcErrorFrame {
	t.Helper()
	var out jsonrpcErrorFrame
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("agent frame is not a well-formed JSON-RPC error: %v\nframe: %s", err, raw)
	}
	return out
}

// --- ALLOW: forwards, and the upstream's reply still reaches the agent -----

func TestDecideAndRelay_Allow_ForwardsFrameAndResponseReturnsToAgent(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const req = `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/notes.txt"}}}`
	h.sendFromAgent(t, req)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Errorf("upstream received %q, want the original request %q forwarded unchanged", got, req)
	}

	const upstreamResp = `{"jsonrpc":"2.0","id":5,"result":{"content":"hello"}}`
	h.sendFromUpstream(t, upstreamResp)
	if got := readFrame(t, h.agentReceived, time.Second); string(got) != upstreamResp {
		t.Errorf("agent received %q, want the upstream's own response %q -- an allowed call's reply must still reach the agent", got, upstreamResp)
	}
}

// Reading a resource, subscribing to one and getting a prompt are decided as
// a tool named after the method, with the params as its input: a denied one
// never reaches the server, an allowed one is forwarded unchanged, and a
// listing method is still not decided at all.
func TestIntercept_DecidesResourceAndPromptMethods(t *testing.T) {
	for _, method := range []string{"resources/read", "resources/subscribe", "prompts/get"} {
		t.Run(method, func(t *testing.T) {
			req := `{"jsonrpc":"2.0","id":7,"method":"` + method + `","params":{"uri":"file:///etc/passwd"}}`

			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "not granted"}}
			h := newMCPHarness(t, startFakePDP(t, fake), testCfg(t))
			h.sendFromAgent(t, req)
			assertNoFrame(t, h.upstreamReceived, 200*time.Millisecond)
			if out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second)); string(out.ID) != "7" || out.Error.Message != "not granted" {
				t.Errorf("agent received id %s, message %q; want id 7 and the PDP's reason", out.ID, out.Error.Message)
			}
			if got := fake.lastRequest(); got.GetTool() != method || got.GetRawInput() != `{"uri":"file:///etc/passwd"}` {
				t.Errorf("asked about tool %q with input %q, want %s and the params", got.GetTool(), got.GetRawInput(), method)
			}

			allowed := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			h = newMCPHarness(t, startFakePDP(t, allowed), testCfg(t))
			h.sendFromAgent(t, req)
			if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
				t.Errorf("upstream received %q, want the request forwarded unchanged", got)
			}
		})
	}

	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY}}
	h := newMCPHarness(t, startFakePDP(t, fake), testCfg(t))
	const list = `{"jsonrpc":"2.0","id":8,"method":"resources/list"}`
	h.sendFromAgent(t, list)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != list || fake.requestCount() != 0 {
		t.Errorf("resources/list: upstream received %q and the PDP was asked %d times; want it forwarded and never decided", got, fake.requestCount())
	}
}

// encoding/json matches keys whatever their case and keeps the last of
// several; the MCP server's parser may do neither. A frame that could name
// one method or tool here and another there is dropped or refused, and never
// reaches the server, even though the PDP would allow what this side reads.
func TestIntercept_AmbiguousKeysNeverReachUpstream(t *testing.T) {
	for name, frame := range map[string]string{
		"second method in another case": `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"tools/list","params":{"name":"delete_file","arguments":{}}}`,
		"method twice":                  `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"delete_file","arguments":{}}}`,
		"params twice":                  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","arguments":{}},"params":{"name":"read_file","arguments":{}}}`,
		"params in another case":        `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd"},"Params":{"uri":"file:///tmp/x"}}`,
		"tool name twice":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","name":"read_file","arguments":{}}}`,
		"tool name in another case":     `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_file","Name":"read_file","arguments":{}}}`,
		"arguments twice":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"},"arguments":{"path":"/tmp/x"}}}`,
		"argument twice":                `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd","path":"/tmp/x"}}}`,
		"argument in another case":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd","Path":"/tmp/x"}}}`,
		"resource uri twice":            `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd","uri":"file:///tmp/x"}}`,
		"resource uri in another case":  `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///etc/passwd","URI":"file:///tmp/x"}}`,
		"prompt name twice":             `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"a","name":"b"}}`,
		"escaped duplicate":             `{"jsonrpc":"2.0","id":1,"method":"tools/call","m\u0065thod":"tools/list","params":{"name":"delete_file","arguments":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			h := newMCPHarness(t, startFakePDP(t, fake), testCfg(t))
			h.sendFromAgent(t, frame)
			assertNoFrame(t, h.upstreamReceived, 200*time.Millisecond)
			if fake.requestCount() != 0 {
				t.Errorf("the PDP was asked %d times about a frame that cannot be read one way", fake.requestCount())
			}
		})
	}

	// The same keys one level further down are not checked, and an ordinary
	// frame is untouched.
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	h := newMCPHarness(t, startFakePDP(t, fake), testCfg(t))
	const fine = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"method":"x","opts":{"Name":"a","name":"b"}}}}`
	h.sendFromAgent(t, fine)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != fine {
		t.Errorf("upstream received %q, want the frame forwarded unchanged", got)
	}
}

// --- DENY: never reaches upstream, agent gets a correlated JSON-RPC error --

// Anchors the required mutation "forward on DENY": if decideAndRelay ever forwarded on a denial,
// this fails on the assertNoFrame check below, not on the error-shape assertions after it.
func TestDecideAndRelay_Deny_NeverReachesUpstreamAndReturnsCorrelatedJSONRPCError(t *testing.T) {
	const pdpReason = "principal has no policy permitting delete_file:call"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const req = `{"jsonrpc":"2.0","id":"req-9","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}`
	h.sendFromAgent(t, req)

	assertNoFrame(t, h.upstreamReceived, 200*time.Millisecond)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if out.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want %q", out.JSONRPC, "2.0")
	}
	if string(out.ID) != `"req-9"` {
		t.Errorf("id = %s, want the original request's id %q", out.ID, `"req-9"`)
	}
	if out.Error.Message != pdpReason {
		t.Errorf("error.message = %q, want the PDP's own reason %q", out.Error.Message, pdpReason)
	}
	if out.Error.Code == 0 {
		t.Error("error.code = 0, want a real JSON-RPC error code, not the zero value -- a zero code is indistinguishable from an unset field")
	}
}

// Anchors the required mutation "return the denial with the wrong JSON-RPC id": two concurrent
// denied calls with clearly different, non-default ids ("alpha-111"/"beta-222", not 1/2, so a
// mutation that hardcodes or off-by-ones an id is not accidentally still correct) must each get
// back their OWN id, never the other's and never a fabricated one. A single-request test (the one
// above) cannot catch a mutation that always echoes "whichever request happened to be handled
// first" or a hardcoded id that happens to match that test's own fixture.
func TestDecideAndRelay_Deny_ErrorCorrelatesToOriginatingRequestID_NotAnotherConcurrentOne(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "denied"}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const reqAlpha = `{"jsonrpc":"2.0","id":"alpha-111","method":"tools/call","params":{"name":"tool_a"}}`
	const reqBeta = `{"jsonrpc":"2.0","id":"beta-222","method":"tools/call","params":{"name":"tool_b"}}`
	h.sendFromAgent(t, reqAlpha)
	h.sendFromAgent(t, reqBeta)

	gotIDs := map[string]bool{}
	for i := 0; i < 2; i++ {
		out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
		gotIDs[string(out.ID)] = true
	}
	wantIDs := map[string]bool{`"alpha-111"`: true, `"beta-222"`: true}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Errorf("agent received error ids %v, want exactly %v -- a swapped, duplicated, or hardcoded "+
			"id would still produce two responses but with the wrong correlation", gotIDs, wantIDs)
	}
}

// A tools/call this file cannot even identify a tool for (no params.name) has nothing to send the
// PDP -- it must deny without ever reaching the network, the same "malformed input never reaches
// the network" rule TestRunHook_MalformedStdin_ExitsTwo proves for hook's own surface.
func TestDecideAndRelay_MalformedToolsCall_DeniesWithoutCallingPDP(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"path":"/etc/passwd"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(out.Error.Message, "params.name is required") {
		t.Errorf("error.message = %q, want it to say params.name is required", out.Error.Message)
	}
	if fake.requestCount() != 0 {
		t.Errorf("PDP was called %d times, want 0 -- a tool this file cannot identify has nothing to ask the PDP about", fake.requestCount())
	}
}

// A tools/call sent with no id at all (a notification -- which MCP's tools/call is never meant to
// be, since it always expects a reply) has nothing for a denial to correlate to. This proves the
// documented choice directly: dropped, not answered with a fabricated id and not forwarded either.
func TestDecideAndRelay_IDLessFrame_DroppedNotForwardedNorAnswered(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "denied"}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const idless = `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"delete_file"}}`
	h.sendFromAgent(t, idless)
	assertNoFrame(t, h.upstreamReceived, 200*time.Millisecond)
	assertNoFrame(t, h.agentReceived, 200*time.Millisecond)

	// The relay itself must still be healthy afterward -- an id-less frame is dropped, not treated
	// as a reason to wedge the whole direction.
	const validReq = `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	h.sendFromAgent(t, validReq)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != validReq {
		t.Errorf("upstream received %q, want %q -- the relay must keep working after an id-less tools/call", got, validReq)
	}
}

// --- ESCALATE: blocks, then forwards on approval, or denies on timeout -----

func TestDecideAndRelay_Escalate_ApprovedRetryAllows_ForwardsFrame(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp: escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{
			{Status: "pending"}, {Status: "pending"}, {Status: "pending"},
			{Status: "pending"}, {Status: "pending"}, {Status: "pending"},
			{Status: "approved"},
		},
	}
	client := startFakePDP(t, fake)
	// decideThenAllowClient (hook_test.go) answers the FIRST Decide call from fake's own ESCALATE
	// script and every call after that (the post-approval retry) with ALLOW -- reused unmodified,
	// same as escalateResp/pendingApproval below reuse hook_test.go's fixtures unmodified.
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}
	cfg := testCfg(t)
	cfg.ApprovalPollInterval = 20 * time.Millisecond // ~6 polls before "approved" lands, ~120ms total
	h := newMCPHarness(t, wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"prod"}}}`
	h.sendFromAgent(t, req)

	// BLOCKS: nothing reaches upstream while still polling -- checked well before the ~120ms the
	// scripted "approved" response lands at.
	assertNoFrame(t, h.upstreamReceived, 60*time.Millisecond)

	// THEN FORWARDS: once GetApproval resolves "approved" and the retry Decide (wrapped) answers
	// ALLOW, the ORIGINAL frame -- unchanged -- reaches upstream.
	if got := readFrame(t, h.upstreamReceived, 2*time.Second); string(got) != req {
		t.Errorf("upstream received %q, want the original request %q forwarded unchanged after approval", got, req)
	}
	if got := fake.lastGetApprovalRequest().GetApprovalId(); got != approvalID {
		t.Errorf("GetApproval was asked about %q, want the escalation's own approval id %q", got, approvalID)
	}
}

// Anchors the required mutation "treat an escalation timeout as allow". GetApproval never resolves
// (pendingApproval repeats "pending" forever, per fakePDP's own last-entry-repeats rule), so the
// only way this call ends is ApprovalTimeout firing -- and it must deny, never forward.
func TestDecideAndRelay_EscalationTimeout_Denies(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	cfg.ApprovalPollInterval = 5 * time.Millisecond
	// Deliberately not a multiple of the interval -- see TestRunHook_Escalate_TimeoutStillPendingDenies
	// (hook_test.go) for why: avoids the deadline racing a tick at the same instant.
	cfg.ApprovalTimeout = 33 * time.Millisecond
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"prod"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, 2*time.Second))
	if !strings.Contains(out.Error.Message, "did not resolve within the escalation timeout") {
		t.Errorf("error.message = %q, want it to name the escalation timeout", out.Error.Message)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// --- Fail-closed: no session file, unreachable PDP --------------------------

func TestDecideAndRelay_MissingSessionFile_Denies(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	if err := os.Remove(cfg.SessionFilePath); err != nil {
		t.Fatalf("remove session file fixture: %v", err)
	}
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(out.Error.Message, "no session file") {
		t.Errorf("error.message = %q, want it to say no session file was found", out.Error.Message)
	}
	if fake.requestCount() != 0 {
		t.Errorf("PDP was called %d times, want 0 -- no session file means there is nothing to ask the PDP about", fake.requestCount())
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

func TestDecideAndRelay_UnreachablePDP_Denies(t *testing.T) {
	client := unreachablePDPClient(t)
	h := newMCPHarness(t, client, testCfg(t))

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(strings.ToLower(out.Error.Message), "could not reach") {
		t.Errorf("error.message = %q, want it to say the PDP could not be reached", out.Error.Message)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// Anchors the required mutation "cache the session file across calls". The first tools/call
// succeeds against a real, valid session file; the file is then removed -- simulating a revocation
// or an ended session, the two real-world events loadSessionFile's own doc comment names -- and a
// SECOND tools/call in the SAME runMCP session (same process, same mcpAuthorizer) must deny, not
// silently reuse whatever delegation_id the first call read. A cached read would let this second
// call through, because the fake PDP allows unconditionally regardless of what delegation_id it is
// asked about.
func TestDecideAndRelay_SessionFileReadFreshPerCall_RevocationTakesEffectNextCall(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	h := newMCPHarness(t, client, cfg)

	const req1 = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`
	h.sendFromAgent(t, req1)
	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req1 {
		t.Fatalf("first call: upstream received %q, want %q (fixture is a valid session + ALLOW)", got, req1)
	}

	if err := os.Remove(cfg.SessionFilePath); err != nil {
		t.Fatalf("remove session file to simulate revocation: %v", err)
	}

	const req2 = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}`
	h.sendFromAgent(t, req2)
	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(out.Error.Message, "no session file") {
		t.Errorf("second call: error.message = %q, want it to say no session file was found -- "+
			"a cached read would instead let this call through", out.Error.Message)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// --- Reissue (Task 4, Phase 9): mirrors hook_test.go's own reissue block ---
// for the second surface decideAndRelay shares reissueAndRetryDecide (reissue.go)
// with -- see that function's own doc comment for why it never tries to tell an
// expired token apart from an ordinary policy denial before attempting exactly
// one reissue and retry.

// The happy path: a denied first Decide, one successful IssueToken, and an
// allowing retry -- carrying the FRESH token, not the stale one -- forwards
// the original frame. issueRequestCount()==1 is the load-bearing assertion
// for "exactly one attempt": a mutant that retried re-issuance in a loop
// would still reach this same forwarded outcome the first time IssueToken
// happened to succeed.
func TestDecideAndRelay_ExpiredToken_ReissuesOnceThenForwards(t *testing.T) {
	const reissuedToken = "freshly-reissued-token"
	fake := &fakePDP{
		resp:      &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueResp: &pdpgrpc.IssueTokenResponse{Token: reissuedToken},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}
	cfg := testCfg(t)
	h := newMCPHarness(t, wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	if got := readFrame(t, h.upstreamReceived, time.Second); string(got) != req {
		t.Errorf("upstream received %q, want the original request %q forwarded unchanged after reissue", got, req)
	}
	if got := fake.issueRequestCount(); got != 1 {
		t.Errorf("IssueToken called %d times, want exactly 1", got)
	}
	if got := wrapped.calls; got != 2 {
		t.Errorf("Decide called %d times, want exactly 2 (the original denial, then one retry)", got)
	}
	// Never a bare delegation id: the retry's own token must be the freshly
	// issued one, not IssueToken's own delegation_id argument.
	if got := wrapped.lastDecideReq.GetToken(); got != reissuedToken {
		t.Errorf("retry Decide request token = %q, want the freshly reissued token %q", got, reissuedToken)
	}
	if got := fake.lastIssueRequest().GetDelegationId(); got == wrapped.lastDecideReq.GetToken() {
		t.Errorf("retry Decide's token equals IssueToken's own delegation_id (%q) -- a bare delegation id "+
			"must never be sent as a token", got)
	}
}

// The reissue succeeds, but the retry -- a full, fresh evaluation -- still
// denies for an unrelated reason. The JSON-RPC error must carry the RETRY's
// own reason, and IssueToken must not be called a second time just because
// the retry also denied.
func TestDecideAndRelay_ExpiredToken_ReissuesOnceThenDeniesWithRetrysOwnReason(t *testing.T) {
	const retryDenyReason = "principal has no policy permitting read_file:call"
	fake := &fakePDP{
		resp:      &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueResp: &pdpgrpc.IssueTokenResponse{Token: "freshly-reissued-token"},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenDenyClient{PDPServiceClient: client, first: fake.resp, denyReason: retryDenyReason}
	cfg := testCfg(t)
	h := newMCPHarness(t, wrapped, cfg)

	const req = `{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if out.Error.Message != retryDenyReason {
		t.Errorf("error.message = %q, want the RETRY's own reason %q", out.Error.Message, retryDenyReason)
	}
	if got := fake.issueRequestCount(); got != 1 {
		t.Errorf("IssueToken called %d times, want exactly 1 -- a second denial must not trigger a second "+
			"reissue attempt", got)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// A failed reissue denies outright, with no retry Decide call at all --
// requestCount() staying at 1 proves the failure short-circuits before any
// retry is attempted, the mutation-testing anchor for "treat a failed
// re-issue as allow".
func TestDecideAndRelay_ReissueFails_Denies(t *testing.T) {
	fake := &fakePDP{
		resp:     &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token: verify: token is expired"},
		issueErr: status.Error(codes.PermissionDenied, "delegation 3fa85f64-5717-4562-b3fc-2c963f66afa6 is revoked"),
	}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(out.Error.Message, "re-issue token") {
		t.Errorf("error.message = %q, want it to say the token could not be re-issued", out.Error.Message)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("Decide called %d times, want exactly 1 -- a failed reissue must never reach a retry Decide call", got)
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// The mcp-mode twin of TestRunHook_SessionFileHasNoToken_ExitsTwo: a session
// file that parses and names a delegation, but whose token field is empty,
// must deny before ever reaching the network.
func TestDecideAndRelay_SessionFileHasNoToken_Denies(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	data, err := json.Marshal(&pdpgrpc.CreateDelegationResponse{DelegationId: uuid.NewString()}) // Token deliberately left unset
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(cfg.SessionFilePath, data, sessionFileMode); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	h := newMCPHarness(t, client, cfg)

	const req = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/x"}}}`
	h.sendFromAgent(t, req)

	out := decodeJSONRPCError(t, readFrame(t, h.agentReceived, time.Second))
	if !strings.Contains(out.Error.Message, "has no token") {
		t.Errorf("error.message = %q, want it to say the session file has no token", out.Error.Message)
	}
	if fake.requestCount() != 0 {
		t.Errorf("PDP was called %d times, want 0 -- a session file with no token must not reach the network", fake.requestCount())
	}
	assertNoFrame(t, h.upstreamReceived, 100*time.Millisecond)
}

// --- Request shape: raw_input, no declared_tier, verb from tool name only --

// Assert its absence on the wire, as the task requires -- mirrors
// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier (hook_test.go) exactly, for the second
// surface that must make the same promise.
// TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier is the wire-level proof of this
// file's entire contract after spec §4.4.2 T3, mirroring hook_test.go's identically-named test for
// its own surface (see that test's own doc comment for the full account of the three tests Task 3
// deleted here too -- TestDecideAndRelay_RequestCarriesResourceAttrs,
// TestDecideAndRelay_RequestNeverCarriesClassificationOrHierarchy, and
// TestDecideAndRelay_VerbDependsOnlyOnToolName_NotOnArguments -- and why the Resource assertion
// below replaces all of them at once rather than being kept as its own test).
func TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	wantDelegationID := uuid.NewString()
	wantToken := "wire-proof-token-" + uuid.NewString()
	writeTestSessionFile(t, cfg.SessionFilePath, wantDelegationID, wantToken)
	h := newMCPHarness(t, client, cfg)

	const arguments = `{"command":"rm -rf /","classification":"TOP-SECRET","hierarchy":"nato"}`
	req := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":%s}}`, arguments)
	h.sendFromAgent(t, req)
	readFrame(t, h.upstreamReceived, time.Second) // synchronize: lastRequest is set before this returns

	got := fake.lastRequest()
	if got == nil {
		t.Fatal("PDP never received a request")
	}
	if got.GetRawInput() != arguments {
		t.Errorf("raw_input = %q, want the exact arguments bytes %q", got.GetRawInput(), arguments)
	}
	if got.DeclaredTier != nil {
		t.Errorf("declared_tier = %v, want unset (nil) -- sending a guessed tier is the exact defect "+
			"this binary exists to not reintroduce", got.GetDeclaredTier())
	}
	if got.GetTool() != "Bash" {
		t.Errorf("tool = %q, want %q", got.GetTool(), "Bash")
	}
	if got.GetAgentId() != cfg.AgentID || got.GetSubject() != cfg.Subject {
		t.Errorf("request identity = (agent=%q subject=%q), want (%q, %q)",
			got.GetAgentId(), got.GetSubject(), cfg.AgentID, cfg.Subject)
	}
	// The property Phase 9 Task 4 exists for, mirroring hook_test.go's
	// identically-worded assertion on its own version of this test: the
	// session file's TOKEN reaches the wire, and the delegation id --
	// structurally absent from DecideRequest since Task 3 -- never does,
	// under any name.
	if got.GetToken() != wantToken {
		t.Errorf("token = %q, want the session file's own token %q", got.GetToken(), wantToken)
	}
	if got.GetToken() == wantDelegationID {
		t.Errorf("token = %q, want it to differ from the delegation id %q -- a bare delegation id must never "+
			"be sent as the token", got.GetToken(), wantDelegationID)
	}
	if resc := got.GetResource(); len(resc) != 0 {
		t.Errorf("resource = %v, want empty -- this file extracts nothing anymore, for any tool or arguments", resc)
	}
}

// --- Concurrency: a slow decision cannot block another ----------------------

// Defends the CONCURRENCY property for tools/call specifically -- mcp.go's own
// TestRunMCP_PipelinedRequests_NotSerializedBehindEachOther proves it for the relay in general,
// using non-gated methods, precisely because tools/call's real (post-Task-2) behavior cannot
// promise arrival ORDER the way that test checks. What tools/call CAN promise, and what this test
// checks instead, is that neither decision blocks the OTHER from starting: if they were serialized
// (request 2's Decide call not even dispatched until request 1's finishes), both frames could not
// reach upstream in under roughly 2x one decision's delay.
func TestDecideAndRelay_ConcurrentToolsCalls_DoNotSerialize(t *testing.T) {
	const decideDelay = 200 * time.Millisecond
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}, decideDelay: decideDelay}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	const req1 = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tool_a"}}`
	const req2 = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"tool_b"}}`
	start := time.Now()
	h.sendFromAgent(t, req1)
	h.sendFromAgent(t, req2)

	// bound sits comfortably above one decideDelay (scheduling jitter, two real goroutines, a mutex
	// in syncWriter) and comfortably below two -- serialized execution cannot land both within it.
	const bound = decideDelay + decideDelay/2
	gotIDs := map[float64]bool{}
	for i := 0; i < 2; i++ {
		frame := readFrame(t, h.upstreamReceived, bound)
		var env struct {
			ID float64 `json:"id"`
		}
		if err := json.Unmarshal(frame, &env); err != nil {
			t.Fatalf("upstream frame %d not valid JSON: %v", i, err)
		}
		gotIDs[env.ID] = true
	}
	if elapsed := time.Since(start); elapsed >= 2*decideDelay {
		t.Errorf("both tools/call frames took %s to reach upstream, want well under %s (2x one "+
			"decision's delay) -- looks serialized", elapsed, 2*decideDelay)
	}
	if !gotIDs[1] || !gotIDs[2] {
		t.Fatalf("upstream received frames for ids %v, want both 1 and 2", gotIDs)
	}
}

// --- Real subprocess: a denied call must never reach a REAL upstream --------

// TestMCPDenyHelperProcess is TestMCPHelperProcess's (mcp_test.go) sibling, purpose-built to prove
// "never reaches the upstream" at the level Task 1's own report says a frame-level test cannot: a
// REAL OS subprocess's REAL stdin. It echoes exactly like TestMCPHelperProcess, but additionally
// appends every line it actually receives to a log file named by an env var -- never to stdout,
// which stays the protocol channel -- so the parent test can inspect, after this process has run
// and exited, exactly what bytes crossed the pipe into a real process.
func TestMCPDenyHelperProcess(t *testing.T) {
	if os.Getenv("STRATIUM_MCP_DENY_TEST_HELPER") != "1" {
		return
	}
	defer os.Exit(0)

	logPath := os.Getenv("STRATIUM_MCP_DENY_TEST_HELPER_LOG")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Bytes()
		if logPath != "" {
			if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.Write(append(append([]byte(nil), line...), '\n'))
				_ = f.Close()
			}
		}
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(line, &req) != nil {
			continue
		}
		_, _ = fmt.Fprintf(os.Stdout, `{"jsonrpc":"2.0","id":%s,"result":{"echo":true}}`+"\n", req.ID)
	}
}

// The test the brief asks for by name: "a denied call must never reach the upstream ... test that
// directly against a real subprocess, not only at the frame level -- Task 1 found a real bug that
// only its real-subprocess test caught." A denied tools/call and a harmless ping both go to a REAL
// helper subprocess; the log it kept of what it actually received must show the ping (proving the
// logging mechanism itself works, so "the denied call is absent" is a meaningful claim, not a
// vacuous one from a log that is always empty) and must NOT show the denied call.
func TestRunMCPCmd_DeniedToolsCall_NeverReachesRealUpstreamSubprocess(t *testing.T) {
	clearMCPEnv(t)
	clearHookEnv(t)
	// runMCPCmd now loads cacheConfig too (Task 3); this test needs a real, fully successful
	// startup (code 0 -- a denial is a normal decision outcome, not a startup fault), so every
	// loader it composes must be satisfied, not just mcpConfig and hookConfig.
	t.Setenv(cacheStalenessWindowEnv, "1h")

	const denyReason = "principal has no policy permitting delete_file:call"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: denyReason}}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	pdpgrpc.RegisterPDPServiceServer(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	sessionPath := filepath.Join(t.TempDir(), "session.json")
	writeTestSessionFile(t, sessionPath, uuid.NewString(), testSessionToken)
	setAllHookEnv(t, map[string]string{
		"STRATIUM_PEP_PDP_ADDR":     lis.Addr().String(),
		"STRATIUM_PEP_SESSION_FILE": sessionPath,
	})
	// The fake PDP above serves plaintext; TLS is the PEP's default.
	t.Setenv("STRATIUM_PEP_PDP_INSECURE", "true")

	logPath := filepath.Join(t.TempDir(), "upstream-received.log")
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_COMMAND", os.Args[0])
	t.Setenv("STRATIUM_PEP_MCP_UPSTREAM_ARGS", "-test.run=TestMCPDenyHelperProcess")
	t.Setenv("STRATIUM_MCP_DENY_TEST_HELPER", "1")
	t.Setenv("STRATIUM_MCP_DENY_TEST_HELPER_LOG", logPath)

	const deniedReq = `{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"delete_file","arguments":{"path":"/etc/passwd"}}}`
	const pingReq = `{"jsonrpc":"2.0","id":"call-2","method":"ping"}`
	agentIn := strings.NewReader(deniedReq + "\n" + pingReq + "\n")
	var agentOut, agentErr bytes.Buffer

	var code int
	mustReturnWithin(t, 5*time.Second, func() {
		code = runMCPCmd(agentIn, &agentOut, &agentErr)
	})
	if code != 0 {
		t.Fatalf("runMCPCmd() = %d, want 0 (a denial is a normal outcome, not a proxy fault); stderr: %s", code, agentErr.String())
	}

	logBytes, err := os.ReadFile(logPath)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("read helper log: %v", err)
	}
	if !bytes.Contains(logBytes, []byte(`"call-2"`)) {
		t.Fatalf("real upstream subprocess log = %q, want it to show the harmless ping was received "+
			"-- otherwise this test cannot tell an empty log apart from a broken logging mechanism", logBytes)
	}
	if bytes.Contains(logBytes, []byte("delete_file")) || bytes.Contains(logBytes, []byte(`"call-1"`)) {
		t.Errorf("real upstream subprocess log = %q, want NO trace of the denied call -- "+
			"a denied call must never reach the upstream", logBytes)
	}

	out := decodeJSONRPCError(t, []byte(firstLine(t, agentOut.String())))
	found := out
	if string(found.ID) != `"call-1"` {
		// Frames can arrive in either order once tools/call runs asynchronously (see
		// TestRunMCP_PipelinedRequests_NotSerializedBehindEachOther's doc comment) -- try the
		// second line before giving up.
		lines := strings.Split(strings.TrimRight(agentOut.String(), "\n"), "\n")
		if len(lines) < 2 {
			t.Fatalf("agent output = %q, want two response lines", agentOut.String())
		}
		found = decodeJSONRPCError(t, []byte(lines[1]))
	}
	if string(found.ID) != `"call-1"` {
		t.Fatalf("agent output = %q, want a JSON-RPC error for id \"call-1\"", agentOut.String())
	}
	if found.Error.Message != denyReason {
		t.Errorf("error.message = %q, want the PDP's reason %q", found.Error.Message, denyReason)
	}
}

// firstLine returns s's first newline-delimited line, for picking apart runMCPCmd's two-response
// stdout in the real-subprocess test above without pulling in a full line-oriented parsing helper
// for one call site.
func firstLine(t *testing.T, s string) string {
	t.Helper()
	i := strings.IndexByte(s, '\n')
	if i < 0 {
		return s
	}
	return s[:i]
}
