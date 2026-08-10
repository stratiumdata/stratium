// Command stratium-pep is the Policy Enforcement Point: the client-side
// binary that sits in front of a real agent and gates its tool calls by
// asking the PDP (stratium-pdp) for a decision over gRPC, then enforcing
// whatever it says.
//
// It is organized as subcommands, one per enforcement surface, because it
// will grow more than one: "hook" (hook.go) today, wired to Claude Code's
// PreToolUse hook; "mcp", "proxy", and "extauthz" are later surfaces over
// the same PDP call. Structuring the dispatch this way now means adding one
// of those later is a new case in dispatch, not a restructuring of this
// binary.
//
// The property every subcommand here shares, and the only one that makes
// this binary worth having: it classifies nothing itself. A PreToolUse
// payload's tool_input crosses this process only as opaque bytes, forwarded
// to the PDP as DecideRequest.raw_input and never inspected. The system
// this replaces ran a local regex classifier and sent the server its own
// verdict — the component being policed declared its own sensitivity, and
// the enforcement path took it at face value. That is spec defect D1, and
// it made every enforcement surface in that system bypassable. See hook.go
// for where that boundary is drawn in code.
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
		_, _ = fmt.Fprintln(stderr, "usage: stratium-pep <hook> ...")
		return 1
	}

	switch args[0] {
	case "hook":
		return runHookCmd(stdin, stdout)
	default:
		_, _ = fmt.Fprintf(stderr, "stratium-pep: unknown subcommand %q\n", args[0])
		return 1
	}
}
