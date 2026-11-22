package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

func TestRunHookFor(t *testing.T) {
	const reason = "stratium-pep: denied by policy"
	allow := func(string, io.Reader, io.Writer) int { return 0 }
	deny := func(_ string, _ io.Reader, w io.Writer) int { return writeDeny(w, reason) }
	crash := func(string, io.Reader, io.Writer) int { return 1 } // no output at all

	tests := []struct {
		name       string
		args       []string
		run        func(string, io.Reader, io.Writer) int
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring; "" means stderr must be empty
	}{
		{"claude allow", nil, allow, 0, "", ""},
		{"claude deny is the JSON on stdout, untouched", nil, deny, 2, `"permissionDecision":"deny"`, ""},
		{"codex allow", []string{"--harness", "codex"}, allow, 0, "", ""},
		{"codex deny puts the reason on stderr and exits 2", []string{"--harness=codex"}, deny, 2,
			`"permissionDecision":"deny"`, reason},
		// The case the shell shim existed for: anything but a clean allow
		// must come out as the blocking exit code, never as 1.
		{"codex: a failure with no output still blocks", []string{"--harness", "codex"}, crash, 2,
			"", "denied with no output (exit 1)"},
		{"unknown harness blocks", []string{"--harness", "nope"}, allow, 2,
			`"permissionDecision":"deny"`, `unknown --harness "nope"`},
		{"--harness with no value blocks", []string{"--harness"}, allow, 2,
			`"permissionDecision":"deny"`, "--harness needs a value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookFor(tt.args, strings.NewReader(""), &stdout, &stderr, tt.run)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			if !strings.Contains(stdout.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", stdout.String(), tt.wantStdout)
			}
			if tt.wantStderr == "" && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// The harness name reaches the hook, which is what puts it on the request.
func TestRunHookFor_PassesTheHarnessName(t *testing.T) {
	for args, want := range map[string]string{"": "claude", "--harness codex": "codex"} {
		var got string
		runHookFor(strings.Fields(args), strings.NewReader(""), io.Discard, io.Discard,
			func(h string, _ io.Reader, _ io.Writer) int { got = h; return 0 })
		if got != want {
			t.Errorf("args %q: harness = %q, want %q", args, got, want)
		}
	}
}

// ...and the hook sends it, with the tool name exactly as the harness gave
// it: renaming is the PDP's job (DecideRequest.harness), never this binary's.
func TestRunHook_SendsHarnessAndTheToolNameUntouched(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	cfg := testCfg(t)
	cfg.Harness = "codex"

	var stdout bytes.Buffer
	stdin := strings.NewReader(`{"tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch"},"cwd":"/work"}`)
	if code := runHook(stdin, &stdout, startFakePDP(t, fake), cfg); code != 0 {
		t.Fatalf("runHook() = %d, want 0; stdout: %s", code, stdout.String())
	}
	req := fake.lastRequest()
	if req.GetHarness() != "codex" || req.GetTool() != "apply_patch" {
		t.Errorf("request harness = %q, tool = %q; want codex, apply_patch", req.GetHarness(), req.GetTool())
	}
	if req.GetCwd() != "/work" {
		t.Errorf("request cwd = %q, want the harness's own", req.GetCwd())
	}
}
