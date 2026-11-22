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
		{"opencode deny is read off stderr by its plugin", []string{"--harness", "opencode"}, deny, 2,
			"", reason},
		{"opencode allow", []string{"--harness", "opencode"}, allow, 0, "", ""},
		{"cursor allow says so: silence is a failed hook there", []string{"--harness", "cursor"}, allow, 0,
			`{"permission":"allow"}`, ""},
		{"cursor deny is its own JSON, exit 2, reason on stderr too", []string{"--harness", "cursor"}, deny, 2,
			`{"agent_message":"stratium-pep: denied by policy","permission":"deny","user_message":"stratium-pep: denied by policy"}`, reason},
		{"cursor: a failure with no output still blocks", []string{"--harness", "cursor"}, crash, 2,
			`"permission":"deny"`, "denied with no output (exit 1)"},
		{"copilot allow is silent: its own permission flow carries on", []string{"--harness", "copilot"}, allow, 0, "", ""},
		{"copilot deny is its decision JSON, exit 2", []string{"--harness", "copilot"}, deny, 2,
			`{"permissionDecision":"deny","permissionDecisionReason":"stratium-pep: denied by policy"}`, reason},
		{"antigravity allow is silent", []string{"--harness", "antigravity"}, allow, 0, "", ""},
		{"antigravity deny is its decision JSON with exit 0: exit 2 would lose it", []string{"--harness", "antigravity"}, deny, 0,
			`{"decision":"deny","reason":"stratium-pep: denied by policy"}`, reason},
		{"antigravity: a failure with no output still prints a deny", []string{"--harness", "antigravity"}, crash, 0,
			`{"decision":"deny","reason":"stratium-pep: denied with no output (exit 1)"}`, "denied with no output"},
		{"unknown harness blocks", []string{"--harness", "nope"}, allow, 2,
			`"permissionDecision":"deny"`, `unknown --harness "nope"`},
		{"--harness with no value blocks", []string{"--harness"}, allow, 2,
			`"permissionDecision":"deny"`, "--harness needs a value"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runHookFor(tt.args, strings.NewReader("{}"), &stdout, &stderr, tt.run)
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

// Copilot CLI's payloads, as captured from live sessions (1.0.114) with the
// ids and paths shortened, and the JSON-encoded form its documentation shows.
func TestParseCopilot(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"an object is passed on as sent",
			`{"sessionId":"s","timestamp":1,"cwd":"/proj","toolName":"view","toolArgs":{"path":"/proj/notes.txt"},"toolCallId":"c"}`,
			`{"tool_name":"view","tool_input":{"path":"/proj/notes.txt"},"cwd":"/proj"}`},
		{"apply_patch's input is the patch text, and stays a string",
			`{"cwd":"/proj","toolName":"apply_patch","toolArgs":"*** Begin Patch\n*** Add File: /proj/hello.txt\n+hi.\n*** End Patch\n"}`,
			`{"tool_name":"apply_patch","tool_input":"*** Begin Patch\n*** Add File: /proj/hello.txt\n+hi.\n*** End Patch\n","cwd":"/proj"}`},
		{"a string holding a JSON object is that object",
			`{"timestamp":1704614400000,"cwd":"/tmp","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`,
			`{"tool_name":"bash","tool_input":{"command":"ls"},"cwd":"/tmp"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCopilot([]byte(tt.in))
			if err != nil || string(got) != tt.want {
				t.Errorf("parseCopilot() = %s, %v\nwant %s", got, err, tt.want)
			}
		})
	}
	if _, err := parseCopilot([]byte("not json")); err == nil {
		t.Error("parseCopilot() accepted malformed stdin")
	}
}

// The hook is run on the parsed call, and input it cannot parse is refused
// in Copilot's own terms.
func TestRunHookFor_Copilot(t *testing.T) {
	var seen string
	run := func(_ string, stdin io.Reader, _ io.Writer) int {
		b, _ := io.ReadAll(stdin)
		seen = string(b)
		return 0
	}
	var stdout, stderr bytes.Buffer
	in := `{"cwd":"/proj","toolName":"bash","toolArgs":{"command":"ls"}}`
	if code := runHookFor([]string{"--harness", "copilot"}, strings.NewReader(in), &stdout, &stderr, run); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if want := `{"tool_name":"bash","tool_input":{"command":"ls"},"cwd":"/proj"}`; seen != want {
		t.Errorf("hook saw %s, want %s", seen, want)
	}
	stdout.Reset()
	if code := runHookFor([]string{"--harness", "copilot"}, strings.NewReader("{"), &stdout, &stderr, run); code != 2 ||
		!strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Errorf("malformed stdin: exit code = %d, stdout = %q; want a deny", code, stdout.String())
	}
}

// report reads a harness's payload the way hook does, so the two match.
func TestHarnessStdin(t *testing.T) {
	in := `{"cwd":"/proj","toolName":"bash","toolArgs":{"command":"ls"},"toolResult":{"resultType":"success"}}`
	for args, want := range map[string]string{
		"--harness copilot": `{"tool_name":"bash","tool_input":{"command":"ls"},"cwd":"/proj"}`,
		"":                  in,
		"--harness codex":   in,
	} {
		r, err := harnessStdin(strings.Fields(args), strings.NewReader(in))
		if err != nil {
			t.Fatalf("%q: %v", args, err)
		}
		if got, _ := io.ReadAll(r); string(got) != want {
			t.Errorf("%q: stdin = %s, want %s", args, got, want)
		}
	}
}

// Antigravity CLI's payload, as captured from a live session (1.5.14) with
// ids and paths shortened. The user's prompt is in it and must not be passed on.
func TestParseAntigravity(t *testing.T) {
	in := `{"toolCall":{"args":{"Path":"/proj/notes.txt"},"id":"call_1","name":"read_file"},"stepIdx":3,` +
		`"hookEventName":"PreToolUse","cwd":"/proj","workspacePaths":["/proj"],"conversationId":"c",` +
		`"modelName":"auto","lastUserInput":"a private prompt","transcriptPath":"/t","artifactDirectoryPath":"/a"}`
	got, err := parseAntigravity([]byte(in))
	if want := `{"tool_name":"read_file","tool_input":{"Path":"/proj/notes.txt"},"cwd":"/proj"}`; err != nil || string(got) != want {
		t.Errorf("parseAntigravity() = %s, %v\nwant %s", got, err, want)
	}
	if strings.Contains(string(got), "private prompt") {
		t.Error("the user's prompt was passed on")
	}

	// Input that cannot be parsed is refused in Antigravity's terms, and the hook is not run.
	var stdout, stderr bytes.Buffer
	ran := false
	code := runHookFor([]string{"--harness", "antigravity"}, strings.NewReader("not json"), &stdout, &stderr,
		func(string, io.Reader, io.Writer) int { ran = true; return 0 })
	if ran || code != 0 || !strings.Contains(stdout.String(), `"decision":"deny"`) {
		t.Errorf("malformed stdin: ran = %v, exit = %d, stdout = %q; want a deny without running the hook", ran, code, stdout.String())
	}
}

// report answers Antigravity CLI's after-the-call hook with the empty object
// it expects, whether or not the report itself could be sent.
func TestRunReportCmd_AntigravityReply(t *testing.T) {
	var stdout, stderr bytes.Buffer
	in := `{"toolCall":{"name":"read_file","args":{"Path":"/proj/a"}},"cwd":"/proj","error":""}`
	if code := runReportCmd([]string{"--harness", "antigravity"}, strings.NewReader(in), &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(stdout.String()) != "{}" {
		t.Errorf("stdout = %q, want {}", stdout.String())
	}
	stdout.Reset()
	runReportCmd(nil, strings.NewReader(in), &stdout, &stderr)
	if stdout.Len() != 0 {
		t.Errorf("stdout = %q for a harness that reads no reply", stdout.String())
	}
}
