package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
var harnesses = map[string]struct {
	deny  func(stdout, stderr io.Writer, claudeOut []byte, reason string) int
	allow func(stdout io.Writer)
	parse func(stdin []byte) ([]byte, error)
}{
	"claude": {},
	"codex":  {deny: denyOnStderr},
	// OpenCode has no command hooks. Its plugin (deploy/opencode) runs this
	// binary, sends Claude Code's field names, and rejects the tool call
	// with stderr as the reason on any exit but 0.
	"opencode": {deny: denyOnStderr},
	"cursor":   {deny: denyCursor, allow: allowCursor},
	"copilot":  {deny: denyCopilot, parse: parseCopilot},
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
	name, _, err := flagValue(args, "--harness")
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
	name, ok, err := flagValue(args, "--harness")
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
