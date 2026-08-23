// mcpclient.go implements agent.Transport over a child process speaking MCP via stdio, exactly the
// same mapping example/mcp/mcpclient.go's own file makes -- deliberately duplicated rather than
// imported from that package (which is package main and cannot be imported anyway), because that
// mapping, together with this directory's own task and expectations, is what makes THIS example's
// story readable from its own file rather than scattered across two directories. The stdio
// JSON-RPC 2.0 mechanics underneath both copies live once, in stratium/example/mcpwire.
package main

import (
	"context"
	"io"

	"stratium/example/agent"
	"stratium/example/mcpwire"
)

// mcpTransport implements agent.Transport against a child process speaking MCP over stdio.
type mcpTransport struct {
	client *mcpwire.Client
	tools  []agent.ToolSpec
}

// startMCP launches command/args as a child process (env, if non-nil, replaces the child's
// environment) via mcpwire.Start.
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

// Call places one tools/call. A JSON-RPC error is a policy decision
// (agent.Result{Allowed:false}); anything that keeps request/response from completing at all is a
// transport error -- see example/mcp/mcpclient.go's own package doc for the fuller reasoning,
// identical here.
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
