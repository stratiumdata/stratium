// Command stratium-pep is the Policy Enforcement Point: the client-side
// binary that sits in front of a real agent and gates its tool calls by
// asking the PDP (stratium-pdp) for a decision over gRPC, then enforcing
// whatever it says.
//
// It is organized as subcommands, one per enforcement surface, because it
// will grow more than one: "hook" (hook.go), wired to Claude Code's
// PreToolUse hook, and "mcp" (mcp.go), an MCP proxy over stdio, exist today;
// "proxy" and "extauthz" are later surfaces over the same PDP call.
// Structuring the dispatch this way now means adding one of those later is a
// new case in dispatch, not a restructuring of this binary. "session-start"
// (session_start.go) is not itself an enforcement surface — it provisions
// the delegation an enforcement surface later enforces, by calling
// CreateDelegation once at session setup and caching what it returns for
// hook (and mcp, and later proxy/extauthz) to read.
//
// "mcp" gates tools/call the same way hook gates a PreToolUse event — see
// mcp.go's package doc, and mcp_authorize.go for the decision logic itself.
// Every other MCP method, including tools/list, relays unconditionally; that
// omission is deliberate, not partial coverage — see mcp.go's package doc for
// why filtering tools/list would reintroduce D1 rather than avoid it.
//
// The property every enforcement subcommand here shares, and the only one
// that makes this binary worth having: it classifies nothing itself. A
// PreToolUse payload's tool_input crosses this process only as opaque
// bytes, forwarded to the PDP as DecideRequest.raw_input and never
// inspected. The system this replaces ran a local regex classifier and sent
// the server its own verdict — the component being policed declared its own
// sensitivity, and the enforcement path took it at face value. That is spec
// defect D1, and it made every enforcement surface in that system
// bypassable. See hook.go for where that boundary is drawn in code.
// session-start holds the analogous line for its own RPC: it caches
// whatever CreateDelegation actually granted, never what was requested —
// see session_start.go.
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// dispatch routes to a subcommand and returns the process exit code. main
// stays a single os.Exit call; dispatch is what tests call instead, with
// stdin/stdout/stderr swapped for buffers.
func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: stratium-pep <hook|session-start|mcp> ...")
		return 1
	}

	switch args[0] {
	case "hook":
		return runHookCmd(stdin, stdout)
	case "session-start":
		return runSessionStartCmd(stderr)
	case "mcp":
		return runMCPCmd(stdin, stdout, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "stratium-pep: unknown subcommand %q\n", args[0])
		return 1
	}
}
