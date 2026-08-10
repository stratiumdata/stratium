package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"stratium/internal/pdpgrpc"
)

func testCfg() hookConfig {
	return hookConfig{
		AgentID:      uuid.NewString(),
		Subject:      "alice@example.com",
		DelegationID: uuid.NewString(),
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
	code := runHook(stdinBody("Write", `{"file_path":"/tmp/notes.txt"}`), &stdout, client, testCfg())

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
	code := runHook(stdinBody("Read", `{"file_path":"/etc/shadow"}`), &stdout, client, testCfg())

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
	code := runHook(stdinBody("Bash", `{"command":"drop the prod table"}`), &stdout, client, testCfg())

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
			code := runHook(strings.NewReader(tt.stdin), &stdout, client, testCfg())

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
	code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, testCfg())

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2", code)
	}
	out := decodeHookOutput(t, stdout.Bytes())
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want %q", out.HookSpecificOutput.PermissionDecision, "deny")
	}
	if out.HookSpecificOutput.PermissionDecisionReason == "" {
		t.Error("permissionDecisionReason is empty, want it to say the PDP could not be reached")
	}
}

func TestRunHook_RequestCarriesRawInputAndNoDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)

	const toolInput = `{"command":"rm -rf /"}`
	cfg := testCfg()
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
	if req.GetAgentId() != cfg.AgentID || req.GetSubject() != cfg.Subject || req.GetDelegationId() != cfg.DelegationID {
		t.Errorf("request identity = (agent=%q subject=%q delegation=%q), want cfg's (%q, %q, %q)",
			req.GetAgentId(), req.GetSubject(), req.GetDelegationId(), cfg.AgentID, cfg.Subject, cfg.DelegationID)
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
	if code := runHook(stdinBody("Bash", `{"command":"ls"}`), &stdout, client, testCfg()); code != 0 {
		t.Fatalf("runHook() (harmless input) = %d, want 0", code)
	}
	harmlessVerb := fake.lastRequest().GetVerb()

	stdout.Reset()
	if code := runHook(stdinBody("Bash", `{"command":"rm -rf /"}`), &stdout, client, testCfg()); code != 0 {
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

func TestLoadHookConfigFromEnv(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_DELEGATION_ID", "deleg-1")

		cfg, err := loadHookConfigFromEnv()
		if err != nil {
			t.Fatalf("loadHookConfigFromEnv() error = %v, want nil", err)
		}
		want := hookConfig{
			PDPAddr: "localhost:50051", AgentID: "agent-1",
			Subject: "alice@example.com", DelegationID: "deleg-1",
		}
		if cfg != want {
			t.Errorf("loadHookConfigFromEnv() = %+v, want %+v", cfg, want)
		}
	})

	t.Run("missing variable is named in the error", func(t *testing.T) {
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_DELEGATION_ID", "deleg-1")

		_, err := loadHookConfigFromEnv()
		if err == nil {
			t.Fatal("loadHookConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_PDP_ADDR")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_PDP_ADDR") {
			t.Errorf("loadHookConfigFromEnv() error = %q, want it to name STRATIUM_PEP_PDP_ADDR", err.Error())
		}
	})
}

// Missing configuration is one of the fail-closed paths the plan calls out
// explicitly: a hook that starts with a guessed identity is worse than one
// that refuses to start.
func TestRunHookCmd_MissingConfig_Denies(t *testing.T) {
	t.Setenv("STRATIUM_PEP_PDP_ADDR", "")
	t.Setenv("STRATIUM_PEP_AGENT_ID", "")
	t.Setenv("STRATIUM_PEP_SUBJECT", "")
	t.Setenv("STRATIUM_PEP_DELEGATION_ID", "")

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
