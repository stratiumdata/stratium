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

	"stratium/internal/pdpgrpc"
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

// --- Request shape: raw_input, no declared_tier, verb from tool name only --

// Assert its absence on the wire, as the task requires -- mirrors
// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier (hook_test.go) exactly, for the second
// surface that must make the same promise.
func TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	wantDelegationID := uuid.NewString()
	writeTestSessionFile(t, cfg.SessionFilePath, wantDelegationID)
	h := newMCPHarness(t, client, cfg)

	const arguments = `{"command":"rm -rf /"}`
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
	if got.GetAgentId() != cfg.AgentID || got.GetSubject() != cfg.Subject || got.GetDelegationId() != wantDelegationID {
		t.Errorf("request identity = (agent=%q subject=%q delegation=%q), want (%q, %q, %q)",
			got.GetAgentId(), got.GetSubject(), got.GetDelegationId(), cfg.AgentID, cfg.Subject, wantDelegationID)
	}
}

// Proves "verb derived from the tool name only, not the arguments" directly, mirroring
// TestRunHook_VerbDependsOnlyOnToolName_NotOnInput: the same tool name with very different
// arguments must produce the same verb, because a verb that varied with input would be a second,
// informal classification channel alongside raw_input.
func TestDecideAndRelay_VerbDependsOnlyOnToolName_NotOnArguments(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	h := newMCPHarness(t, client, testCfg(t))

	h.sendFromAgent(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"ls"}}}`)
	readFrame(t, h.upstreamReceived, time.Second)
	harmlessVerb := fake.lastRequest().GetVerb()

	h.sendFromAgent(t, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"Bash","arguments":{"command":"rm -rf /"}}}`)
	readFrame(t, h.upstreamReceived, time.Second)
	destructiveVerb := fake.lastRequest().GetVerb()

	if harmlessVerb != destructiveVerb {
		t.Errorf("verb changed with arguments: %q (harmless) vs %q (destructive), want identical", harmlessVerb, destructiveVerb)
	}
	if harmlessVerb != toolVerbs["Bash"] {
		t.Errorf("verb = %q, want the tool-name label %q (reused from hook.go's own table -- "+
			"see its doc comment on why an MCP tool name is an expected, honest lookup miss)", harmlessVerb, toolVerbs["Bash"])
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
	writeTestSessionFile(t, sessionPath, uuid.NewString())
	setAllHookEnv(t, map[string]string{
		"STRATIUM_PEP_PDP_ADDR":     lis.Addr().String(),
		"STRATIUM_PEP_SESSION_FILE": sessionPath,
	})

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
