package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
)

// testCfg returns a valid baseline hookConfig: an existing, well-formed
// session file under a test-scoped temp directory, naming a fresh
// delegation ID, plus a generous ConnectTimeout -- so a test that is not
// itself about the session file or about timing (most of them) does not
// have to think about either. Tests that need a specific failure mode (no
// file, a malformed file, a delegation the fake PDP does not recognize, a
// short timeout) build on top of this instead of duplicating it.
//
// ApprovalPollInterval/ApprovalTimeout are small (milliseconds), not
// ConnectTimeout's generous seconds: only escalation.go's poll loop reads
// them, and every escalation test in this file wants its fixture to resolve,
// time out, or busy-wait-check in well under a second, not because that is
// realistic for a human approver but because a slow test suite is one nobody
// runs. A test that cares about the exact values (the timeout tests) sets
// them explicitly rather than trusting these defaults.
func testCfg(t *testing.T) hookConfig {
	t.Helper()
	cfg := hookConfig{
		AgentID:              uuid.NewString(),
		Subject:              "alice@example.com",
		SessionFilePath:      filepath.Join(t.TempDir(), "session.json"),
		ConnectTimeout:       5 * time.Second,
		ApprovalPollInterval: 5 * time.Millisecond,
		ApprovalTimeout:      500 * time.Millisecond,
	}
	writeTestSessionFile(t, cfg.SessionFilePath, uuid.NewString())
	return cfg
}

// writeTestSessionFile writes a well-formed session file naming
// delegationID at path -- the same shape session-start's own
// writeSessionFile (session_file.go) produces, so hook_test.go's fixtures
// do not silently drift from what a real session-start run would leave
// behind.
func writeTestSessionFile(t *testing.T, path, delegationID string) {
	t.Helper()
	data, err := json.Marshal(&pdpgrpc.CreateDelegationResponse{DelegationId: delegationID})
	if err != nil {
		t.Fatalf("marshal test session file: %v", err)
	}
	if err := os.WriteFile(path, data, sessionFileMode); err != nil {
		t.Fatalf("write test session file: %v", err)
	}
}

// stdinBody builds the exact bytes a PreToolUse hook receives on stdin, byte
// for byte, so a test asserting what crossed into raw_input can compare
// against toolInputJSON directly rather than against whatever a round trip
// through encoding/json's own marshaler happened to produce.
func stdinBody(toolName, toolInputJSON string) *strings.Reader {
	return strings.NewReader(fmt.Sprintf(`{"tool_name":%q,"tool_input":%s}`, toolName, toolInputJSON))
}

func decodeHookOutput(t *testing.T, raw []byte) hookOutput {
	t.Helper()
	var out hookOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("stdout is not well-formed JSON: %v\nstdout: %s", err, raw)
	}
	return out
}

func TestRunHook_Allow_ExitsZeroSilently(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Write", `{"file_path":"/tmp/notes.txt"}`), &stdout, client, testCfg(t))

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on allow", stdout.String())
	}
}

// The tool here is deliberately "Read", not "Bash" -- see the local-shortcut
// mutation in the task's mutation-testing requirement ("add a local
// shortcut that exits 0 for a tool named Read without calling the PDP"). A
// hook carrying that shortcut would still pass every other test in this
// file; this is the one that catches it, because it is the one place a tool
// commonly assumed "obviously safe" is asked for and denied anyway.
func TestRunHook_Deny_ExitsTwoWithPDPReason(t *testing.T) {
	const pdpReason = "principal has no policy permitting Read:read"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Read", `{"file_path":"/etc/shadow"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	if fake.requestCount() != 1 {
		t.Fatalf("PDP was called %d times, want exactly 1 -- a Read shortcut would leave this at 0", fake.requestCount())
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q, want %q", out.HookSpecificOutput.HookEventName, "PreToolUse")
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	if out.HookSpecificOutput.PermissionDecisionReason != pdpReason {
		t.Errorf("permissionDecisionReason = %q, want the PDP's reason %q",
			out.HookSpecificOutput.PermissionDecisionReason, pdpReason)
	}
}

// --- Escalation (Task 4, E6): the PEP blocks on GetApproval, then either
// retries Decide with the resolved approval id or denies. Every test below
// starts from an EFFECT_ESCALATE DecideResponse naming a fresh approval id
// (escalateResp) and scripts what GetApproval (and, on the approved path,
// the retry Decide) report from there -- mirroring
// internal/pdpgrpc/escalation_test.go's escalationFixture pattern one layer
// up the stack. ---

// escalateResp returns a DecideResponse fixture for the ESCALATE effect,
// naming approvalID -- every escalation test below starts here.
func escalateResp(approvalID string) *pdpgrpc.DecideResponse {
	return &pdpgrpc.DecideResponse{
		Effect:     pdpgrpc.Effect_EFFECT_ESCALATE,
		Reason:     "tier DESTRUCTIVE requires escalation",
		ApprovalId: approvalID,
	}
}

// pending repeats "pending" for every GetApproval call -- fakePDP's
// last-entry-repeats rule (pdp_fake_test.go) means one entry is enough to
// script "never resolves on its own".
func pendingApproval() []*pdpgrpc.GetApprovalResponse {
	return []*pdpgrpc.GetApprovalResponse{{Status: "pending"}}
}

// mustReturnWithin runs fn in its own goroutine and fails the test unless fn
// returns within maxWait -- the direct, deterministic way to prove a
// function does not hang, rather than trusting go test's own multi-minute
// default timeout to eventually notice. Used for the properties where
// hanging IS the bug under test (a mutated "retry forever" timeout, or a
// context that is never actually honored) -- every other test in this file
// has no such risk and calls runHook/pollApproval directly.
func mustReturnWithin(t *testing.T, maxWait time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(maxWait):
		t.Fatalf("did not return within %s -- looks hung", maxWait)
	}
}

// The happy path: GetApproval resolves "approved" on its third call, the
// retry Decide answers ALLOW, and the exact approval id polled and retried
// with is the one the escalation named -- not a hardcoded or mismatched one.
func TestRunHook_Escalate_ApprovedRetryAllows_ExitsZero(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp: escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{
			{Status: "pending"}, {Status: "pending"}, {Status: "approved"},
		},
	}
	client := startFakePDP(t, fake)

	// Decide is called twice (escalate, then retry): script the SECOND call's
	// response by switching fake.resp once the first has been observed is not
	// possible with fakePDP's single fixed resp/err fields, so this uses a
	// tiny wrapper client instead -- see decideThenAllowClient below.
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, wrapped, testCfg(t))

	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (approved retry allows); stdout: %s", code, stdout.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q, want empty on allow", stdout.String())
	}
	if fake.getApprovalCallCount() != 3 {
		t.Errorf("GetApproval called %d times, want 3", fake.getApprovalCallCount())
	}
	if got := fake.lastGetApprovalRequest().GetApprovalId(); got != approvalID {
		t.Errorf("last GetApproval request approval_id = %q, want %q", got, approvalID)
	}
	if got := wrapped.lastDecideReq.GetApprovalId(); got != approvalID {
		t.Errorf("retry Decide request approval_id = %q, want %q", got, approvalID)
	}
}

// decideThenAllowClient wraps a real client to answer the FIRST Decide call
// from the embedded fakePDP's own script (an ESCALATE) and every call after
// that with EFFECT_ALLOW -- fakePDP itself only has one fixed resp field, so
// a second, different Decide response needs this thin wrapper rather than a
// change to fakePDP's own shape, which every other test in this file already
// depends on staying "one fixed response per fake".
type decideThenAllowClient struct {
	pdpgrpc.PDPServiceClient
	first         *pdpgrpc.DecideResponse
	calls         int
	lastDecideReq *pdpgrpc.DecideRequest
}

func (c *decideThenAllowClient) Decide(ctx context.Context, req *pdpgrpc.DecideRequest, opts ...grpc.CallOption) (*pdpgrpc.DecideResponse, error) {
	c.calls++
	c.lastDecideReq = req
	if c.calls == 1 {
		return c.first, nil
	}
	return &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "escalation approved"}, nil
}

// Required fail-closed test 1/5: the deadline passes while still pending.
// Wrapped in mustReturnWithin so a "retry forever" mutation of the timeout
// handling fails this test in under a second rather than by eventually
// exhausting go test's own default timeout.
func TestRunHook_Escalate_TimeoutStillPendingDenies(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	cfg.ApprovalPollInterval = 5 * time.Millisecond
	// Deliberately not a multiple of the interval: a deadline landing exactly
	// on a tick would race the ticker firing at the same instant (Go's select
	// picks pseudo-randomly between two simultaneously-ready cases) -- 33ms
	// falls cleanly between the 30ms and 35ms ticks so the timeout always
	// wins while this function is waiting, not mid-call.
	cfg.ApprovalTimeout = 33 * time.Millisecond

	var code int
	var stdout bytes.Buffer
	mustReturnWithin(t, 2*time.Second, func() {
		code = runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, cfg)
	})

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2 (C22: a timeout must deny)", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "did not resolve within the escalation timeout") {
		t.Errorf("permissionDecisionReason = %q, want it to name the escalation timeout", reason)
	}
}

// Catches "make the poll ignore its interval and busy-wait": a correctly
// interval-respecting loop over ApprovalTimeout/ApprovalPollInterval makes
// roughly that many GetApproval calls; a busy-wait would make many thousands
// in the same window. The bound below is generous enough to absorb ordinary
// scheduling jitter while remaining orders of magnitude below what a
// busy-wait produces.
func TestRunHook_Escalate_PollRespectsInterval_DoesNotBusyWait(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	cfg.ApprovalPollInterval = 10 * time.Millisecond
	cfg.ApprovalTimeout = 100 * time.Millisecond

	var stdout bytes.Buffer
	mustReturnWithin(t, 2*time.Second, func() {
		runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, cfg)
	})

	const wantApprox = 10 // ApprovalTimeout / ApprovalPollInterval
	if got := fake.getApprovalCallCount(); got > wantApprox*3 {
		t.Errorf("GetApproval called %d times in %s at a %s interval, want roughly %d -- "+
			"looks like the poll is not waiting between checks (busy-wait)",
			got, cfg.ApprovalTimeout, cfg.ApprovalPollInterval, wantApprox)
	}
}

// Required fail-closed test 2/5: the approval is denied. Also the anchor for
// "make a denied status fall through to the retry": Decide's own call count
// stays at 1 (the original escalation only) -- a mutant that retried anyway
// would drive it to 2.
func TestRunHook_Escalate_ApprovalDeniedExitsTwo_NoRetry(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:                 escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{{Status: "denied"}},
	}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "was denied") {
		t.Errorf("permissionDecisionReason = %q, want it to say the approval was denied", reason)
	}
	if fake.requestCount() != 1 {
		t.Errorf("Decide called %d times, want exactly 1 -- a denied approval must not fall through to a retry",
			fake.requestCount())
	}
}

// Required fail-closed test 3/5: the PDP becomes unreachable mid-poll. A
// REAL torn-down connection, not a scripted error response: the fake server
// is started and stopped manually (not via startFakePDP's t.Cleanup, which
// would stop it only at test end) so the initial Decide call succeeds before
// the server goes away and every GetApproval call after that hits a genuinely
// dead connection -- the same "prove it over the wire, not with a mock"
// discipline pdp_fake_test.go's own doc comment describes.
func TestRunHook_Escalate_PDPUnreachableMidPollExitsTwo(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	pdpgrpc.RegisterPDPServiceServer(gs, fake)
	go func() { _ = gs.Serve(lis) }()
	client := dialTestClient(t, lis.Addr().String())

	cfg := testCfg(t)
	cfg.ApprovalPollInterval = 5 * time.Millisecond
	cfg.ApprovalTimeout = 2 * time.Second // bounded by mustReturnWithin below, not relied on to fire itself
	time.AfterFunc(20*time.Millisecond, gs.Stop)

	var code int
	var stdout bytes.Buffer
	mustReturnWithin(t, 3*time.Second, func() {
		code = runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, cfg)
	})

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP could not be reached", reason)
	}
}

// The mutation-testing anchor for "make an unreachable PDP mid-poll allow":
// unlike TestRunHook_Escalate_PDPUnreachableMidPollExitsTwo above, the
// connection here stays alive -- only GetApproval's own scripted response is
// an Unavailable error -- specifically so that a mutant treating that error
// as a resolution would actually be ABLE to reach the retry Decide call and
// have it counted. (A real torn-down connection, as the test above uses,
// cannot distinguish this mutation: the retry would fail to connect either
// way, producing the same exit code and a reason that still contains "could
// not reach" whether pollApproval failed closed on its own or only accidentally
// via the also-broken retry.) Decide's call count staying at 1 is therefore
// the load-bearing assertion, not the exit code.
func TestRunHook_Escalate_GetApprovalUnavailableExitsTwo_NoRetry(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:           escalateResp(approvalID),
		getApprovalErr: status.Error(codes.Unavailable, "connection reset by peer"),
	}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP could not be reached", reason)
	}
	if fake.requestCount() != 1 {
		t.Errorf("Decide called %d times, want exactly 1 -- an unreachable signal mid-poll must not be "+
			"treated as a resolution and retried", fake.requestCount())
	}
}

// Required fail-closed test 4/5: GetApproval returns an unknown id.
func TestRunHook_Escalate_UnknownApprovalIDExitsTwo(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:           escalateResp(approvalID),
		getApprovalErr: status.Error(codes.NotFound, fmt.Sprintf("approval %s: not found", approvalID)),
	}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "unknown to the PDP") {
		t.Errorf("permissionDecisionReason = %q, want it to say the approval id is unknown", reason)
	}
}

// Required fail-closed test 5/5: the retry Decide denies anyway (a leg the
// approval does not cover -- e.g. a revoked delegation -- started refusing
// between the escalation and the retry; internal/pdpgrpc/escalation_test.go
// proves this server-side, this proves the PEP surfaces it as a deny rather
// than mistaking "approved" for "allowed").
func TestRunHook_Escalate_RetryDecideDeniesExitsTwo(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp:                 escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{{Status: "approved"}},
	}
	client := startFakePDP(t, fake)
	const denyReason = "delegation was revoked after the escalation was approved"
	wrapped := &decideThenDenyClient{PDPServiceClient: client, first: fake.resp, denyReason: denyReason}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, wrapped, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecisionReason != denyReason {
		t.Errorf("permissionDecisionReason = %q, want the retry's own reason %q",
			out.HookSpecificOutput.PermissionDecisionReason, denyReason)
	}
}

// decideThenDenyClient is decideThenAllowClient's sibling for
// TestRunHook_Escalate_RetryDecideDeniesExitsTwo: the retry must surface
// EXACTLY the second call's DENY reason, not the first call's ESCALATE
// reason and not a generic fallback.
type decideThenDenyClient struct {
	pdpgrpc.PDPServiceClient
	first      *pdpgrpc.DecideResponse
	denyReason string
	calls      int
}

func (c *decideThenDenyClient) Decide(ctx context.Context, req *pdpgrpc.DecideRequest, opts ...grpc.CallOption) (*pdpgrpc.DecideResponse, error) {
	c.calls++
	if c.calls == 1 {
		return c.first, nil
	}
	return &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: c.denyReason}, nil
}

// A defensive branch, not one of the five required scenarios: a PDP build
// that returns ESCALATE with no approval_id at all violates
// DecideResponse.approval_id's own doc comment. There is nothing to poll, so
// this must deny without ever calling GetApproval.
func TestRunHook_Escalate_NoApprovalIDInResponse_DeniesWithoutPolling(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE, Reason: "tier DESTRUCTIVE"}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	if fake.getApprovalCallCount() != 0 {
		t.Errorf("GetApproval called %d times, want 0 -- nothing to poll without an approval_id", fake.getApprovalCallCount())
	}
}

// Proves the poll primitive itself is interruptible -- the property "a
// context cancellation or a PEP shutdown mid-poll denies rather than
// hanging" the brief names directly. GetApproval always reports "pending"
// (never resolves on its own), so the only way this call can return is via
// ctx -- proving cancellation, not a lucky resolution, unblocked it.
// Wrapped in mustReturnWithin: a mutation that ignored ctx here would hang,
// and this is what turns that into a fast, reported failure instead of a
// multi-minute one.
func TestPollApproval_ContextCancelledMidPoll_ReturnsPromptlyAndDenies(t *testing.T) {
	fake := &fakePDP{getApprovalResponses: pendingApproval()}
	client := startFakePDP(t, fake)

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel) // simulates external cancellation, independent of any ApprovalTimeout

	var ok bool
	var reason string
	mustReturnWithin(t, 2*time.Second, func() {
		ok, reason = pollApproval(ctx, client, 5*time.Millisecond, uuid.NewString())
	})

	if ok {
		t.Fatal("pollApproval() ok = true, want false: a cancelled context must deny, not allow")
	}
	// Same reason text pollApproval reports for an ApprovalTimeout deadline
	// (see its own doc comment on why both converge to one message): from
	// this function's perspective a timeout and an external cancellation are
	// indistinguishable -- both are "ctx said stop" -- and giving both the
	// same wording is what keeps the reason deterministic rather than a
	// coin-flip between two different-looking messages for the same event.
	if !strings.Contains(reason, "did not resolve within the escalation timeout") {
		t.Errorf("reason = %q, want it to say the approval did not resolve (not a resolution, not a generic RPC error)", reason)
	}
}

func TestRunHook_MalformedStdin_ExitsTwo(t *testing.T) {
	tests := []struct {
		name  string
		stdin string
	}{
		{"invalid JSON", `{not json`},
		{"missing tool_name", `{"tool_input":{}}`},
		{"empty body", ``},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			client := startFakePDP(t, fake)

			var stdout bytes.Buffer
			code := runHook(strings.NewReader(tt.stdin), &stdout, client, testCfg(t))

			if code != 2 {
				t.Fatalf("runHook() = %d, want 2", code)
			}
			if fake.requestCount() != 0 {
				t.Errorf("PDP was called %d times, want 0 -- malformed stdin must not reach the network", fake.requestCount())
			}
			decodeHookOutput(t, stdout.Bytes()) // must still be well-formed JSON
		})
	}
}

func TestRunHook_UnreachablePDP_ExitsTwo(t *testing.T) {
	client := unreachablePDPClient(t)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP could not be reached", reason)
	}
}

// ---------------------------------------------------------------------------
// Fail-closed matrix (Task 3). Every scenario below must exit 2, and each
// produces its own distinct, actionable reason -- see describeRPCError
// and loadSessionFile's doc comments (hook.go, session_file.go) for why a
// single flat "denied" would not be good enough. Together with
// TestRunHook_UnreachablePDP_ExitsTwo above and
// TestRunHookCmd_MissingConfig_Denies below, this is the full set the task
// brief asks for: no session file; a malformed session file; a session file
// naming a delegation that no longer exists; PDP unreachable; PDP returns an
// error; PDP times out; and a response whose effect is unset.
// ---------------------------------------------------------------------------

func TestRunHook_NoSessionFile_ExitsTwo(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	cfg := testCfg(t)
	if err := os.Remove(cfg.SessionFilePath); err != nil {
		t.Fatalf("remove session file fixture: %v", err)
	}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	if fake.requestCount() != 0 {
		t.Errorf("PDP was called %d times, want 0 -- no session file means there is nothing to ask the PDP about", fake.requestCount())
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "no session file") {
		t.Errorf("permissionDecisionReason = %q, want it to say no session file was found", reason)
	}
	if !strings.Contains(reason, "session-start") {
		t.Errorf("permissionDecisionReason = %q, want it to say how to fix this (run session-start)", reason)
	}
}

func TestRunHook_MalformedSessionFile_ExitsTwo(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	cfg := testCfg(t)
	if err := os.WriteFile(cfg.SessionFilePath, []byte(`{not json`), sessionFileMode); err != nil {
		t.Fatalf("corrupt session file fixture: %v", err)
	}

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	if fake.requestCount() != 0 {
		t.Errorf("PDP was called %d times, want 0 -- a malformed session file must not reach the network", fake.requestCount())
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "malformed") {
		t.Errorf("permissionDecisionReason = %q, want it to say the session file is malformed", reason)
	}
}

// The session file itself is perfectly well-formed -- a real-looking
// delegation_id, exactly as a real session-start run would write -- but the
// delegation it names is gone: revoked, expired past cleanup, or a session
// file copied from another environment. The PEP cannot tell locally; only
// the PDP's own chain lookup can (services/internal/pdpgrpc/server.go's
// LoadChain call, which returns codes.NotFound). This is distinct from
// "malformed session file" (the file is fine; the request goes out over the
// wire) and from "PDP unreachable" (the PDP is right there, and answers) --
// describeRPCError's reason must not claim a connectivity problem for
// this one.
func TestRunHook_SessionNamesUnknownDelegation_ExitsTwo(t *testing.T) {
	fake := &fakePDP{err: status.Error(codes.NotFound, "delegation 3fa85f64-5717-4562-b3fc-2c963f66afa6: not found")}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Read", `{}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "unknown") || !strings.Contains(reason, "not found") {
		t.Errorf("permissionDecisionReason = %q, want it to distinguish an unknown delegation from a connectivity problem", reason)
	}
	if strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("permissionDecisionReason = %q, must not claim a connectivity problem -- the PDP was reached and answered", reason)
	}
}

// Distinct from "PDP unreachable": the PDP answers, but the answer is an
// application-level error, not a decision. describeRPCError's default
// case is what makes this reason say "returned an error" instead of
// reusing "could not reach" -- the two are different failures with
// different fixes (a network/ops problem vs. something wrong server-side).
func TestRunHook_PDPReturnsError_ExitsTwo(t *testing.T) {
	fake := &fakePDP{err: status.Error(codes.Internal, "policy engine panicked")}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "returned an error") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP returned an error", reason)
	}
	if !strings.Contains(reason, "policy engine panicked") {
		t.Errorf("permissionDecisionReason = %q, want the PDP's own error text preserved", reason)
	}
}

// Distinct from "PDP unreachable": the PDP is there and would eventually
// answer, but not inside ConnectTimeout. A hook that waited forever for a
// wedged PDP would block every tool call indefinitely instead of failing
// closed in finite time -- exactly what ConnectTimeout exists to bound.
func TestRunHook_PDPTimesOut_ExitsTwo(t *testing.T) {
	fake := &fakePDP{
		resp:        &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW},
		decideDelay: 300 * time.Millisecond,
	}
	client := startFakePDP(t, fake)
	cfg := testCfg(t)
	cfg.ConnectTimeout = 20 * time.Millisecond

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, cfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	reason := out.HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(reason, "did not respond in time") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP did not respond in time", reason)
	}
}

// EFFECT_DENY is the proto's zero value (see pdp.proto's Effect doc
// comment), deliberately, so that an Effect field the server never sets
// deserializes as deny rather than an ambiguous state -- the wire-format
// half of the invariant LegResult's own zero value documents on the
// decision core's side (internal/authz/verdict.go). fake.resp below never
// assigns Effect at all (not "assigns EFFECT_DENY explicitly", which would
// prove nothing beyond Go's own zero-value rule) and goes over a real TCP
// round trip through startFakePDP -- the same reason
// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier does: proto3 omits a
// zero-value field from the wire entirely, so this proves the *wire*
// encoding/decoding preserves the invariant, not just that a Go zero value
// happens to compare equal to EFFECT_DENY.
func TestRunHook_EffectUnset_DeniesByZeroValue(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Reason: "no policy evaluated this leg"}} // Effect field deliberately never assigned
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2 -- an unset effect must deny, not allow", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	if out.HookSpecificOutput.PermissionDecisionReason != "no policy evaluated this leg" {
		t.Errorf("permissionDecisionReason = %q, want the PDP's reason to pass through even though effect was unset",
			out.HookSpecificOutput.PermissionDecisionReason)
	}
}

// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier is the wire-level proof
// of this file's entire contract after spec §4.4.2 T3: raw_input travels
// unconditionally and nothing else is ever derived from it. Task 3 deleted
// three test functions that used to live here, each proving a PEP-side
// extraction table actually reached the wire --
// TestRunHook_RequestCarriesNormalizedInput (normalize.go's
// extractNormalizedInput), TestRunHook_RequestCarriesResourceAttrs and
// TestRunHook_RequestNeverCarriesClassificationOrHierarchy (resource.go's
// extractResourceAttrs), and TestRunHook_VerbDependsOnlyOnToolName_NotOnInput
// (hook.go's toolVerbs) -- because the tables themselves are deleted: there
// is nothing left to extract, so there is nothing left for those tests to
// prove reached the wire. The Resource assertion below is that property's
// replacement, folded into this test rather than kept as its own: an
// adversarial input (carrying "classification"/"hierarchy" under their own
// names, exactly what the deleted classification-boundary test used)
// combined with a non-nil, non-empty check is a STRICTLY stronger claim than
// either deleted test made individually -- an empty map can never carry
// those two keys, or any others, regardless of what tool_input contains.
func TestRunHook_RequestCarriesRawInputAndNoDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	const toolInput = `{"command":"rm -rf /","classification":"TOP-SECRET","hierarchy":"nato"}`
	cfg := testCfg(t)
	// Overwrite testCfg's random delegation ID with a known one, so the
	// identity assertion below can compare against something this test
	// controls rather than something buried inside cfg -- cfg no longer
	// carries a DelegationID field at all; it lives in the session file.
	wantDelegationID := uuid.NewString()
	writeTestSessionFile(t, cfg.SessionFilePath, wantDelegationID)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", toolInput), &stdout, client, cfg)
	if code != 0 {
		t.Fatalf("runHook() = %d, want 0 (fixture is an ALLOW)", code)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.GetRawInput() != toolInput {
		t.Errorf("raw_input = %q, want the exact tool_input bytes %q", req.GetRawInput(), toolInput)
	}
	if req.DeclaredTier != nil {
		t.Errorf("declared_tier = %v, want unset (nil) -- sending a guessed tier is the exact defect "+
			"this binary exists to not reintroduce", req.GetDeclaredTier())
	}
	if req.GetTool() != "Bash" {
		t.Errorf("tool = %q, want %q", req.GetTool(), "Bash")
	}
	if req.GetAgentId() != cfg.AgentID || req.GetSubject() != cfg.Subject || req.GetDelegationId() != wantDelegationID {
		t.Errorf("request identity = (agent=%q subject=%q delegation=%q), want (%q, %q, %q)",
			req.GetAgentId(), req.GetSubject(), req.GetDelegationId(), cfg.AgentID, cfg.Subject, wantDelegationID)
	}
	if resc := req.GetResource(); len(resc) != 0 {
		t.Errorf("resource = %v, want empty -- this file extracts nothing anymore, for any tool or input", resc)
	}
}

// requiredHookEnvVars names every variable loadHookConfigFromEnv requires --
// shared by clearHookEnv and setAllHookEnv below and the "missing variable"
// table in TestLoadHookConfigFromEnv, so a variable added to hookConfig
// without being added HERE would silently go untested for its own absence
// rather than failing loudly.
var requiredHookEnvVars = []string{
	"STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT",
	"STRATIUM_PEP_SESSION_FILE", "STRATIUM_PEP_CONNECT_TIMEOUT",
	"STRATIUM_PEP_APPROVAL_POLL_INTERVAL", "STRATIUM_PEP_APPROVAL_TIMEOUT",
}

// clearHookEnv clears every variable loadHookConfigFromEnv reads, so each
// subtest below starts from a known-empty baseline regardless of what the
// ambient environment happens to have set -- t.Setenv restores each after
// the test, so subtests never leak into one another.
func clearHookEnv(t *testing.T) {
	t.Helper()
	for _, k := range requiredHookEnvVars {
		t.Setenv(k, "")
	}
}

// setAllHookEnv sets every required variable to a valid value, then applies
// overrides -- the shared "everything valid except what this subtest is
// deliberately testing" baseline every case in TestLoadHookConfigFromEnv
// builds on, so proving one field invalid/missing does not also require
// restating the other six valid values inline at every call site.
func setAllHookEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	values := map[string]string{
		"STRATIUM_PEP_PDP_ADDR":               "localhost:50051",
		"STRATIUM_PEP_AGENT_ID":               "agent-1",
		"STRATIUM_PEP_SUBJECT":                "alice@example.com",
		"STRATIUM_PEP_SESSION_FILE":           "/tmp/stratium-pep-session.json",
		"STRATIUM_PEP_CONNECT_TIMEOUT":        "5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "1s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT":       "1h",
	}
	for k, v := range overrides {
		values[k] = v
	}
	for _, k := range requiredHookEnvVars {
		t.Setenv(k, values[k])
	}
}

func TestLoadHookConfigFromEnv(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		clearHookEnv(t)
		setAllHookEnv(t, nil)

		cfg, err := loadHookConfigFromEnv()
		if err != nil {
			t.Fatalf("loadHookConfigFromEnv() error = %v, want nil", err)
		}
		want := hookConfig{
			PDPAddr: "localhost:50051", AgentID: "agent-1",
			Subject:              "alice@example.com",
			SessionFilePath:      "/tmp/stratium-pep-session.json",
			ConnectTimeout:       5 * time.Second,
			ApprovalPollInterval: time.Second,
			ApprovalTimeout:      time.Hour,
		}
		if cfg != want {
			t.Errorf("loadHookConfigFromEnv() = %+v, want %+v", cfg, want)
		}
	})

	// Every required variable, one at a time -- not just STRATIUM_PEP_PDP_ADDR
	// as before Task 4 -- so adding a field to hookConfig without wiring its
	// presence check into loadHookConfigFromEnv fails here rather than only
	// being caught by an operator's first production deploy.
	t.Run("missing variable is named in the error", func(t *testing.T) {
		for _, missing := range requiredHookEnvVars {
			t.Run(missing, func(t *testing.T) {
				clearHookEnv(t)
				setAllHookEnv(t, map[string]string{missing: ""})

				_, err := loadHookConfigFromEnv()
				if err == nil {
					t.Fatalf("loadHookConfigFromEnv() error = nil, want an error naming %s", missing)
				}
				if !strings.Contains(err.Error(), missing) {
					t.Errorf("loadHookConfigFromEnv() error = %q, want it to name %s", err.Error(), missing)
				}
			})
		}
	})

	// Every duration field rejects the same three bad shapes requiredDuration
	// (config.go) is meant to catch: unparseable, zero, and negative. A zero
	// STRATIUM_PEP_APPROVAL_POLL_INTERVAL in particular would panic
	// time.NewTicker inside pollApproval (escalation.go) rather than fail
	// cleanly at startup if this check were ever missing.
	t.Run("invalid duration", func(t *testing.T) {
		badValues := []struct {
			name  string
			value string
		}{
			{"not a duration", "not-a-duration"},
			{"zero", "0s"},
			{"negative", "-5s"},
		}
		for _, field := range []string{
			"STRATIUM_PEP_CONNECT_TIMEOUT", "STRATIUM_PEP_APPROVAL_POLL_INTERVAL", "STRATIUM_PEP_APPROVAL_TIMEOUT",
		} {
			for _, bad := range badValues {
				t.Run(field+"/"+bad.name, func(t *testing.T) {
					clearHookEnv(t)
					setAllHookEnv(t, map[string]string{field: bad.value})

					_, err := loadHookConfigFromEnv()
					if err == nil {
						t.Fatalf("loadHookConfigFromEnv() error = nil, want an error naming %s", field)
					}
					if !strings.Contains(err.Error(), field) {
						t.Errorf("loadHookConfigFromEnv() error = %q, want it to name %s", err.Error(), field)
					}
				})
			}
		}
	})
}

// Missing configuration is one of the fail-closed paths the plan calls out
// explicitly: a hook that starts with a guessed identity is worse than one
// that refuses to start.
func TestRunHookCmd_MissingConfig_Denies(t *testing.T) {
	clearHookEnv(t)

	var stdout bytes.Buffer
	code := runHookCmd(stdinBody("Read", `{}`), &stdout)

	if code != 2 {
		t.Fatalf("runHookCmd() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	if out.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Error("permissionDecisionReason is empty, want a reason naming the missing configuration")
	}
}
