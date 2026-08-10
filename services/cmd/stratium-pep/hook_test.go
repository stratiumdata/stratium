package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
func testCfg(t *testing.T) hookConfig {
	t.Helper()
	cfg := hookConfig{
		AgentID:         uuid.NewString(),
		Subject:         "alice@example.com",
		SessionFilePath: filepath.Join(t.TempDir(), "session.json"),
		ConnectTimeout:  5 * time.Second,
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

func TestRunHook_Escalate_ExitsTwoSayingApprovalUnimplemented(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_ESCALATE,
		Reason: "tier DESTRUCTIVE requires escalation",
	}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg(t))

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q (escalate must deny, not allow)",
			out.HookSpecificOutput.PermissionDecision, "deny")
	}
	reason := strings.ToLower(out.HookSpecificOutput.PermissionDecisionReason)
	if !strings.Contains(reason, "human approval") || !strings.Contains(reason, "not yet implemented") {
		t.Errorf("permissionDecisionReason = %q, want it to say human approval is required and not yet implemented",
			out.HookSpecificOutput.PermissionDecisionReason)
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
// produces its own distinct, actionable reason -- see describeDecideError
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
// describeDecideError's reason must not claim a connectivity problem for
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
// application-level error, not a decision. describeDecideError's default
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

func TestRunHook_RequestCarriesRawInputAndNoDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	const toolInput = `{"command":"rm -rf /"}`
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
}

// Proves "verb derived from the tool name only, not the input" directly: the
// same tool name with two very different inputs must produce the same verb.
// If it did not, the verb would itself be a second, informal classification
// channel alongside raw_input -- exactly what the task brief singles out as
// not fine ("Deriving anything from tool_input is not fine").
func TestRunHook_VerbDependsOnlyOnToolName_NotOnInput(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	if code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, testCfg(t)); code != 0 {
		t.Fatalf("runHook() (harmless input) = %d, want 0", code)
	}
	harmlessVerb := fake.lastRequest().GetVerb()

	stdout.Reset()
	if code := runHook(stdinBody("Bash", `{"command":"rm -rf /"}`), &stdout, client, testCfg(t)); code != 0 {
		t.Fatalf("runHook() (destructive input) = %d, want 0", code)
	}
	destructiveVerb := fake.lastRequest().GetVerb()

	if harmlessVerb != destructiveVerb {
		t.Errorf("verb changed with input: %q (harmless) vs %q (destructive), want identical", harmlessVerb, destructiveVerb)
	}
	if harmlessVerb != toolVerbs["Bash"] {
		t.Errorf("verb = %q, want the tool-name label %q", harmlessVerb, toolVerbs["Bash"])
	}
}

// clearHookEnv clears every variable loadHookConfigFromEnv reads, so each
// subtest below starts from a known-empty baseline regardless of what the
// ambient environment happens to have set -- t.Setenv restores each after
// the test, so subtests never leak into one another.
func clearHookEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT",
		"STRATIUM_PEP_SESSION_FILE", "STRATIUM_PEP_CONNECT_TIMEOUT",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadHookConfigFromEnv(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		clearHookEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")

		cfg, err := loadHookConfigFromEnv()
		if err != nil {
			t.Fatalf("loadHookConfigFromEnv() error = %v, want nil", err)
		}
		want := hookConfig{
			PDPAddr: "localhost:50051", AgentID: "agent-1",
			Subject:         "alice@example.com",
			SessionFilePath: "/tmp/stratium-pep-session.json",
			ConnectTimeout:  5 * time.Second,
		}
		if cfg != want {
			t.Errorf("loadHookConfigFromEnv() = %+v, want %+v", cfg, want)
		}
	})

	t.Run("missing variable is named in the error", func(t *testing.T) {
		clearHookEnv(t)
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
		// STRATIUM_PEP_PDP_ADDR left unset.

		_, err := loadHookConfigFromEnv()
		if err == nil {
			t.Fatal("loadHookConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_PDP_ADDR")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_PDP_ADDR") {
			t.Errorf("loadHookConfigFromEnv() error = %q, want it to name STRATIUM_PEP_PDP_ADDR", err.Error())
		}
	})

	t.Run("invalid connect timeout", func(t *testing.T) {
		tests := []struct {
			name  string
			value string
		}{
			{"not a duration", "not-a-duration"},
			{"zero", "0s"},
			{"negative", "-5s"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				clearHookEnv(t)
				t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
				t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
				t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
				t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
				t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", tt.value)

				_, err := loadHookConfigFromEnv()
				if err == nil {
					t.Fatal("loadHookConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_CONNECT_TIMEOUT")
				}
				if !strings.Contains(err.Error(), "STRATIUM_PEP_CONNECT_TIMEOUT") {
					t.Errorf("loadHookConfigFromEnv() error = %q, want it to name STRATIUM_PEP_CONNECT_TIMEOUT", err.Error())
				}
			})
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
