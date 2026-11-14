// mcpclient.go implements agent.Transport over a child process speaking MCP (Model Context
// Protocol) via stdio -- it does not know or care whether the child it launched is the real
// @modelcontextprotocol/server-filesystem or `stratium-pep mcp` standing in front of one -- that
// substitution is main.go's business, and is the entire point of this example (see README.md).
// The stdio JSON-RPC 2.0 mechanics (the initialize/notifications/initialized handshake, tools/list,
// framing) live in stratium/example/mcpwire, shared with example/depth/mcp rather than
// re-implemented there; what stays here, deliberately not hoisted into that shared package, is the
// mapping from an MCP result to an agent.Result -- Tools(), Call(), startMCP -- because that
// mapping, together with main.go's own task and expectations, is this example's whole story.
//
// THE CENTRAL RULE THIS FILE FOLLOWS: a JSON-RPC error on a tools/call response is a DECISION, not
// a fault. `stratium-pep mcp` denies a call by answering it with a JSON-RPC error whose message is
// the PDP's reason (see services/cmd/stratium-pep/mcp_authorize.go's `deny`) -- there is no other
// channel on this transport for a policy answer to travel on. Call maps that shape to
// agent.Result{Allowed:false, Reason: <message>}. A transport fault -- the child died, a pipe
// broke, a response failed to parse, ids stopped matching -- is a Go `error` instead, and aborts
// the run; it is never turned into a Result, denied or otherwise, because a broken example
// reporting a "successful denial" would be indistinguishable from a working one.
package main

import (
	"context"
	"io"

	"github.com/stratiumdata/stratium/example/agent"
	"github.com/stratiumdata/stratium/example/mcpwire"
)

// mcpTransport implements agent.Transport against a child process speaking MCP over stdio.
type mcpTransport struct {
	client *mcpwire.Client
	tools  []agent.ToolSpec
}

// startMCP launches command/args as a child process (env, if non-nil, replaces the child's
// environment; nil inherits this process's own -- see main.go's two call sites) via mcpwire.Start.
func startMCP(command string, args []string, env []string, stderr io.Writer) (*mcpTransport, error) {
	client, tools, err := mcpwire.Start(command, args, env, stderr)
	if err != nil {
		return nil, err
	}
	specs := make([]agent.ToolSpec, len(tools))
	for i, t := range tools {
		specs[i] = agent.ToolSpec{Name: t.Name, Description: t.Description, Schema: t.InputSchema}
	}
	return &mcpTransport{client: client, tools: specs}, nil
}

func (c *mcpTransport) Tools() []agent.ToolSpec { return c.tools }

// Call places one tools/call and maps the answer per this file's package doc: a JSON-RPC error is
// a policy decision (agent.Result{Allowed:false}); anything that keeps request/response from
// completing at all is a transport error.
func (c *mcpTransport) Call(_ context.Context, call agent.ToolCall) (agent.Result, error) {
	args := call.Args
	if args == nil {
		args = map[string]any{}
	}
	result, rpcErr, err := c.client.Request("tools/call", map[string]any{"name": call.Name, "arguments": args})
	if err != nil {
		return agent.Result{}, err
	}
	if rpcErr != nil {
		return agent.Result{Allowed: false, Reason: rpcErr.Message}, nil
	}
	return agent.Result{Allowed: true, Output: mcpwire.ExtractText(result)}, nil
}

// Close asks the child to shut down and waits for it to exit.
func (c *mcpTransport) Close() error {
	return c.client.Close()
}
