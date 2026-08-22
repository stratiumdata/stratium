// mcpclient.go is a minimal MCP (Model Context Protocol) client over stdio: it launches a server
// as a child process and speaks newline-delimited JSON-RPC 2.0 to its stdin/stdout. It implements
// agent.Transport, and it does not know or care whether the child it launched is the real
// @modelcontextprotocol/server-filesystem or `stratium-pep mcp` standing in front of one -- that
// substitution is main.go's business, and is the entire point of this example (see README.md).
//
// Three JSON-RPC methods are used: `initialize` and `notifications/initialized` (the required MCP
// handshake -- captured empirically against the real server; see startMCP's doc comment), and
// `tools/call`. `tools/list` fills out ToolSpec once, at startup.
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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"stratium/example/agent"
)

// mcpTransport implements agent.Transport against a child process speaking MCP over stdio.
type mcpTransport struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	nextID int
	tools  []agent.ToolSpec
}

// maxFrameBytes bounds a single JSON-RPC line this client will read, matching the limit
// stratium-pep's own mcp proxy applies (services/cmd/stratium-pep/mcp.go) -- generous for any real
// tool payload, and a stated bound rather than an unbounded scanner buffer.
const maxFrameBytes = 32 * 1024 * 1024

// startMCP launches command/args as a child process (env, if non-nil, replaces the child's
// environment; nil inherits this process's own -- see main.go's two call sites), performs the MCP
// initialize/notifications/initialized handshake, and fetches the tool list via tools/list. The
// exact handshake shape below was captured by running the real server directly and recording what
// it actually sent, the same empirical discipline
// deploy/seed/tool-catalog-mcp-filesystem.sql documents for its own tool names -- not copied from
// a library, since this project deliberately uses none (see stratium-pep mcp.go's own package doc
// for why: a proxy needs raw JSON-RPC frames, and every Go MCP library available when the PEP was
// built centers on typed dispatch instead).
func startMCP(command string, args []string, env []string, stderr io.Writer) (*mcpTransport, error) {
	cmd := exec.Command(command, args...) //nolint:gosec // G204: command/args are this example's own fixed configuration (main.go), never request data.
	cmd.Env = env
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("mcp: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("mcp: could not start %q: %w", command, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), maxFrameBytes)
	c := &mcpTransport{cmd: cmd, stdin: stdin, lines: scanner}

	if _, rpcErr, err := c.request("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "stratium-example-mcp-agent", "version": "0.1.0"},
	}); err != nil {
		return nil, fmt.Errorf("mcp: initialize: %w", err)
	} else if rpcErr != nil {
		return nil, fmt.Errorf("mcp: initialize: server error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	// A notification: no id, no response expected or read. Required before the server will answer
	// anything else -- omitting it left tools/list hanging against the real server.
	if err := c.writeLine(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return nil, fmt.Errorf("mcp: notifications/initialized: %w", err)
	}

	result, rpcErr, err := c.request("tools/list", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("mcp: tools/list: %w", err)
	}
	if rpcErr != nil {
		return nil, fmt.Errorf("mcp: tools/list: server error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	var parsed struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, fmt.Errorf("mcp: tools/list: malformed result: %w", err)
	}
	for _, t := range parsed.Tools {
		c.tools = append(c.tools, agent.ToolSpec{Name: t.Name, Description: t.Description, Schema: t.InputSchema})
	}
	return c, nil
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
	result, rpcErr, err := c.request("tools/call", map[string]any{"name": call.Name, "arguments": args})
	if err != nil {
		return agent.Result{}, err
	}
	if rpcErr != nil {
		return agent.Result{Allowed: false, Reason: rpcErr.Message}, nil
	}
	return agent.Result{Allowed: true, Output: extractText(result)}, nil
}

// Close asks the child to shut down (closing its stdin, the standard stdio-subprocess shutdown
// contract) and waits for it to exit.
func (c *mcpTransport) Close() error {
	_ = c.stdin.Close()
	return c.cmd.Wait()
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
}

func (c *mcpTransport) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("mcp: encode: %w", err)
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("mcp: write to child: %w", err)
	}
	return nil
}

// request sends a JSON-RPC request and blocks for its response. This client never has more than
// one request in flight -- the agent loop calls Transport.Call sequentially, one tool call at a
// time -- so, unlike stratium-pep's own mcp proxy, there is no need to correlate responses out of
// order; the very next line read is the answer to the request just sent, and its id is checked
// against that assumption rather than trusted blindly.
func (c *mcpTransport) request(method string, params any) (json.RawMessage, *rpcError, error) {
	c.nextID++
	id := c.nextID
	if err := c.writeLine(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, nil, err
	}
	if !c.lines.Scan() {
		if err := c.lines.Err(); err != nil {
			return nil, nil, fmt.Errorf("mcp: reading response to %q: %w", method, err)
		}
		return nil, nil, fmt.Errorf("mcp: reading response to %q: child closed its output", method)
	}
	var resp rpcResponse
	if err := json.Unmarshal(c.lines.Bytes(), &resp); err != nil {
		return nil, nil, fmt.Errorf("mcp: malformed response to %q: %w", method, err)
	}
	if resp.ID != id {
		return nil, nil, fmt.Errorf("mcp: response id %d does not match request id %d for %q", resp.ID, id, method)
	}
	return resp.Result, resp.Error, nil
}

// extractText pulls the plain-text answer out of an MCP tool result's `content` array (every read
// tool in @modelcontextprotocol/server-filesystem answers with `{"content":[{"type":"text",...}]}`
// -- captured the same way startMCP's handshake was). A shape this does not recognize is returned
// as its raw JSON rather than silently discarded, so an unexpected result is still visible in the
// transcript instead of showing up as an empty answer.
func extractText(raw json.RawMessage) string {
	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil || len(parsed.Content) == 0 {
		return string(raw)
	}
	var sb strings.Builder
	for _, item := range parsed.Content {
		if item.Type == "text" {
			sb.WriteString(item.Text)
		}
	}
	return sb.String()
}
