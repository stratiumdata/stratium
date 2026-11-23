package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// A harness is an agent runtime whose pre-tool-call hook this binary can be.
// They differ in how a hook must say "no": Claude Code reads a JSON decision
// from stdout; Codex reads the reason from stderr on exit 2.
//
// The hook itself (hook.go) always answers in Claude Code's format. For any
// other harness, runHookFor runs it into a buffer and deny re-says a refusal
// the way that harness reads one. A nil deny means "Claude Code's format is
// this harness's format": the output passes straight through.
//
// What a harness sends on stdin is the other half. Codex sends Claude Code's
// tool_name/tool_input fields, so there is no input translation yet; a
// harness that sends something else adds it here.
//
// allow is for a harness that reads silence as a failed hook: it writes what
// that harness needs to see for the call to go ahead.
//
// parse is for a harness whose stdin is not Claude Code's: it returns the
// same call in Claude Code's fields (tool_name, tool_input, cwd). It moves
// the input, whole; it never looks inside it or renames the tool.
//
// reportReply is what `report` prints for a harness that reads a reply from
// its after-the-call hook.
var harnesses = map[string]struct {
	deny        func(stdout, stderr io.Writer, claudeOut []byte, reason string) int
	allow       func(stdout io.Writer)
	parse       func(stdin []byte) ([]byte, error)
	reportReply string
}{
	"claude": {},
	"codex":  {deny: denyOnStderr},
	// Kiro CLI sends Claude Code's field names. It blocks a call only on
	// exit 2, with stderr as the reason: on 3.5.0 any other failing exit,
	// a timeout or a missing command let the call run.
	"kiro": {deny: denyOnStderr},
	// Goose names the working directory working_dir. An allow prints
	// nothing: anything on stdout that is not a decision counts as a failed
	// hook there.
	"goose": {deny: denyGoose, parse: parseGoose},
	// Devin sends Claude Code's field names without the working directory.
	// It blocks on exit 2 with stderr as the reason.
	"devin": {deny: denyOnStderr, parse: parseDevin},
	// OpenCode has no command hooks. Its plugin (deploy/opencode) runs this
	// binary, sends Claude Code's field names, and rejects the tool call
	// with stderr as the reason on any exit but 0.
	"opencode": {deny: denyOnStderr},
	"cursor":   {deny: denyCursor, allow: allowCursor},
	"copilot":  {deny: denyCopilot, parse: parseCopilot},
	// An allow prints nothing. Antigravity CLI runs the call on a hook that
	// exits 0 in silence, and an explicit "allow" there is an automatic
	// approval that would skip a prompt of its own.
	"antigravity": {deny: denyAntigravity, parse: parseAntigravity, reportReply: "{}"},
}

// parseAntigravity reads Antigravity CLI's payload: the call is nested under
// toolCall, with the input as args. The payload also carries the user's
// prompt (lastUserInput), which goes no further than this function.
func parseAntigravity(stdin []byte) ([]byte, error) {
	var in struct {
		ToolCall struct {
			Name string          `json:"name"`
			Args json.RawMessage `json:"args"`
		} `json:"toolCall"`
		Cwd string `json:"cwd"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return nil, fmt.Errorf("malformed stdin: %w", err)
	}
	return json.Marshal(hookStdin{ToolName: in.ToolCall.Name, ToolInput: in.ToolCall.Args, Cwd: in.Cwd})
}

// harnessFlag is --harness, with one harness recognised without it. Devin
// runs the hooks in Claude Code's settings files as well as its own, so a
// hook installed for Claude Code is called by Devin with no flag; Devin sets
// DEVIN_PROJECT_DIR for every hook it runs.
func harnessFlag(args []string) (string, bool, error) {
	name, ok, err := flagValue(args, "--harness")
	if err == nil && !ok && os.Getenv("DEVIN_PROJECT_DIR") != "" {
		return "devin", true, nil
	}
	return name, ok, err
}

// parseDevin reads Devin's hook payload: Claude Code's, less the working
// directory. Devin runs a hook in the session's directory, so that is where
// a relative path in the tool input is resolved. A working directory the
// payload does carry is kept: Devin is recognised by an environment variable,
// which another harness's session can inherit, and that harness's own cwd
// must not be replaced.
func parseDevin(stdin []byte) ([]byte, error) {
	var in hookStdin
	if err := json.Unmarshal(stdin, &in); err != nil {
		return nil, fmt.Errorf("malformed stdin: %w", err)
	}
	if in.Cwd != "" {
		return stdin, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("no working directory: %w", err)
	}
	in.Cwd = cwd
	return json.Marshal(in)
}

// parseGoose reads Goose's hook payload. It has Claude Code's tool_name and
// tool_input, and the working directory under working_dir.
func parseGoose(stdin []byte) ([]byte, error) {
	var in struct {
		ToolName   string          `json:"tool_name"`
		ToolInput  json.RawMessage `json:"tool_input"`
		WorkingDir string          `json:"working_dir"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return nil, fmt.Errorf("malformed stdin: %w", err)
	}
	return json.Marshal(hookStdin{ToolName: in.ToolName, ToolInput: in.ToolInput, Cwd: in.WorkingDir})
}

// denyGoose gives both of Goose's denials: exit code 2 with the reason on
// stderr, and its block decision on stdout, which it honours on any exit.
func denyGoose(stdout, stderr io.Writer, _ []byte, reason string) int {
	_, _ = fmt.Fprintln(stderr, reason)
	out, _ := json.Marshal(map[string]string{"decision": "block", "reason": reason})
	_, _ = fmt.Fprintln(stdout, string(out))
	return 2
}

// denyAntigravity is the one deny that exits 0. Antigravity CLI reads the
// decision from stdout only when the hook succeeds; on exit 2 it discards
// stdout and tells the model the hook failed. Any other non-zero exit is
// refused as well (seen on 1.5.14), so a crash still blocks.
func denyAntigravity(stdout, stderr io.Writer, _ []byte, reason string) int {
	_, _ = fmt.Fprintln(stderr, reason)
	out, _ := json.Marshal(map[string]string{"decision": "deny", "reason": reason})
	_, _ = fmt.Fprintln(stdout, string(out))
	return 0
}

// parseCopilot reads the payload of Copilot CLI's camelCase events, which
// carry its own tool names: toolName, toolArgs, cwd.
//
// toolArgs is passed on as sent, object or string (apply_patch sends the
// patch text itself as a string), with one exception: a string that holds a
// JSON object is that object. Copilot's documentation shows the arguments
// encoded that way, and the PDP reads fields from an object.
func parseCopilot(stdin []byte) ([]byte, error) {
	var in struct {
		ToolName string          `json:"toolName"`
		ToolArgs json.RawMessage `json:"toolArgs"`
		Cwd      string          `json:"cwd"`
	}
	if err := json.Unmarshal(stdin, &in); err != nil {
		return nil, fmt.Errorf("malformed stdin: %w", err)
	}
	var encoded string
	if json.Unmarshal(in.ToolArgs, &encoded) == nil {
		var object map[string]json.RawMessage
		if json.Unmarshal([]byte(encoded), &object) == nil && object != nil {
			in.ToolArgs = json.RawMessage(encoded)
		}
	}
	return json.Marshal(hookStdin{ToolName: in.ToolName, ToolInput: in.ToolArgs, Cwd: in.Cwd})
}

// denyCopilot is Copilot CLI's deny: its decision JSON on stdout, which is
// where it reads the reason it shows the model, and exit code 2, which it
// treats as a deny whatever stdout holds.
func denyCopilot(stdout, stderr io.Writer, _ []byte, reason string) int {
	_, _ = fmt.Fprintln(stderr, reason)
	out, _ := json.Marshal(map[string]string{
		"permissionDecision": "deny", "permissionDecisionReason": reason})
	_, _ = fmt.Fprintln(stdout, string(out))
	return 2
}

// harnessStdin returns stdin as the named harness's parse leaves it. The
// harness is taken from args; with no --harness, or one that needs no
// parsing, stdin comes back untouched.
func harnessStdin(args []string, stdin io.Reader) (io.Reader, error) {
	name, _, err := harnessFlag(args)
	if err != nil {
		return nil, err
	}
	h := harnesses[name]
	if h.parse == nil {
		return stdin, nil
	}
	body, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("could not read stdin: %w", err)
	}
	if body, err = h.parse(body); err != nil {
		return nil, err
	}
	return bytes.NewReader(body), nil
}

// Cursor reads a JSON decision from stdout, and treats a hook that prints
// nothing as a failed hook, which an install with failClosed set turns into
// a block. So an allow has to say so.
func allowCursor(stdout io.Writer) {
	_, _ = fmt.Fprintln(stdout, `{"permission":"allow"}`)
}

// denyCursor says no every way Cursor documents: its own deny JSON on stdout,
// and exit code 2, which Cursor treats as a deny whatever stdout holds. The
// reason goes to stderr as well.
func denyCursor(stdout, stderr io.Writer, _ []byte, reason string) int {
	_, _ = fmt.Fprintln(stderr, reason)
	out, _ := json.Marshal(map[string]string{
		"permission": "deny", "user_message": reason, "agent_message": reason})
	_, _ = fmt.Fprintln(stdout, string(out))
	return 2
}

// denyOnStderr is Codex's contract: exit 2 blocks, and the reason shown to
// the model is whatever is on stderr. The JSON still goes to stdout, as the
// stratium-codex-hook shell shim this replaces always did.
func denyOnStderr(stdout, stderr io.Writer, claudeOut []byte, reason string) int {
	_, _ = fmt.Fprintln(stderr, reason)
	_, _ = stdout.Write(claudeOut)
	return 2
}

// runHookFor picks the harness from args and runs the hook for it.
//
// Every outcome but a clean allow blocks, in the harness's own terms: a
// harness lets the tool run on any exit code it does not read as a refusal,
// so a failure here that exited 1 would be an allow.
func runHookFor(args []string, stdin io.Reader, stdout, stderr io.Writer,
	run func(harness string, stdin io.Reader, stdout io.Writer) int) int {
	name, ok, err := harnessFlag(args)
	if !ok {
		name = "claude"
	}
	h, known := harnesses[name]
	if err != nil || !known {
		// Which format to refuse in is the thing that is unknown, so use
		// both: exit 2 with the reason on stderr blocks in every harness
		// this binary supports, and the JSON covers Claude Code.
		reason := fmt.Sprintf("stratium-pep: unknown --harness %q", name)
		if err != nil {
			reason = fmt.Sprintf("stratium-pep: %s", err)
		}
		_, _ = fmt.Fprintln(stderr, reason)
		return writeDeny(stdout, reason)
	}
	if h.deny == nil {
		return run(name, stdin, stdout)
	}

	var out bytes.Buffer
	stdin, err = harnessStdin(args, stdin)
	if err != nil {
		reason := fmt.Sprintf("stratium-pep: %s", err)
		return h.deny(stdout, stderr, nil, reason)
	}
	code := run(name, stdin, &out)
	if code == 0 {
		if h.allow != nil {
			h.allow(stdout)
		}
		return 0
	}
	return h.deny(stdout, stderr, out.Bytes(), denyReason(out.Bytes(), code))
}

// denyReason reads the reason back out of the hook's own Claude-format
// output. A refusal with no readable reason is still a refusal.
func denyReason(claudeOut []byte, code int) string {
	var out hookOutput
	if err := json.Unmarshal(bytes.TrimSpace(claudeOut), &out); err == nil &&
		out.HookSpecificOutput.PermissionDecisionReason != "" {
		return out.HookSpecificOutput.PermissionDecisionReason
	}
	if text := bytes.TrimSpace(claudeOut); len(text) > 0 {
		return string(text)
	}
	return fmt.Sprintf("stratium-pep: denied with no output (exit %d)", code)
}
