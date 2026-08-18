// Command mcp-upstream is the MCP server the `mcp` enforcement surface's live
// proof (Task 2) puts behind `stratium-pep mcp`: the proxy launches it as its
// child, JSON-RPC frames flow agent -> proxy -> here and back, and every call
// that arrives is appended to the record file named by this command's single
// argument.
//
// Unlike deploy/docker/echo-upstream and services/cmd/grpc-target -- the same
// kind of fixture for the Envoy and gRPC-proxy surfaces, both of them compose
// services -- this one is BUILT BY THE TEST, into a temp directory, and spawned
// by the test process. It has to be: `mcp` is stdio, so its upstream is a child
// process on the test host, not a container on a network. That is also why the
// record file is an argument rather than a fixed path: every run gets its own,
// and two runs in parallel cannot see each other's calls.
//
// Everything this command does lives in internal/mcpupstream -- see that
// package's doc for why it is a package inside the module rather than a loose
// main.go outside it, and for the one design rule that matters most here (the
// record is out of band; it is never retrievable through a tools/call, which is
// the very thing the proxy gates).
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"stratium/internal/mcpupstream"
)

func main() {
	if len(os.Args) != 2 {
		// A missing record path is refused rather than defaulted. A default would
		// mean two concurrent runs sharing one file, and -- far worse for the
		// proofs this exists to serve -- a run whose records went somewhere the
		// test does not read, making every "the denied call never arrived"
		// assertion pass for the wrong reason.
		_, _ = fmt.Fprintf(os.Stderr, "usage: %s <record-file>\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	if err := mcpupstream.Serve(os.Stdin, os.Stdout, os.Args[1]); err != nil {
		// stderr, never stdout: stdout is the live JSON-RPC channel the proxy is
		// parsing frame by frame, and the proxy passes a child's stderr through
		// untouched (mcp.go's runMCPCmd sets cmd.Stderr = stderr), so this lands
		// somewhere a failing test can actually read it.
		_, _ = fmt.Fprintf(os.Stderr, "mcp-upstream: %v\n", err)
		os.Exit(1)
	}
}
