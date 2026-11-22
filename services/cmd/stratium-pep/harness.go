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
var harnesses = map[string]struct {
	deny func(stdout, stderr io.Writer, claudeOut []byte, reason string) int
}{
	"claude": {},
	"codex":  {deny: denyOnStderr},
	// OpenCode has no command hooks. Its plugin (deploy/opencode) runs this
	// binary, sends Claude Code's field names, and rejects the tool call
	// with stderr as the reason on any exit but 0.
	"opencode": {deny: denyOnStderr},
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
	code := run(name, stdin, &out)
	if code == 0 {
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
