// Package mcpwire is the stdio JSON-RPC 2.0 client every depth-0 MCP surface in this suite
// launches an upstream server through: the `initialize`/`notifications/initialized` handshake and
// `tools/list` at startup, plus the one framing rule every caller of this package must itself
// honor -- a JSON-RPC error on a `tools/call` response is a DECISION, not a fault, and it is this
// package's caller's job to turn it into an agent.Result, never this package's. This package holds
// only the wire mechanics: it does not import stratium/example/agent and knows nothing of
// agent.Transport, agent.ToolSpec, or agent.Result. What it deliberately does NOT hold is the
// agent.Transport implementation itself (Tools()/Call()/Close()) -- that mapping from a JSON-RPC
// result to an agent.Result is what makes each of example/mcp's and example/depth/mcp's own
// mcpclient.go the whole story a reader needs from that one file, not shared plumbing lifted out
// from under it.
//
// Extracted from example/mcp/mcpclient.go, unchanged in behavior: the exact handshake shape below
// was captured empirically by running the real @modelcontextprotocol/server-filesystem directly
// and recording what it actually sent (see git history on that file), not copied from a library --
// this project deliberately uses none for MCP (stratium-pep's own mcp.go package doc explains why:
// a proxy needs raw JSON-RPC frames, and every Go MCP library available when the PEP was built
// centers on typed dispatch instead).
package mcpwire

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// MaxFrameBytes bounds a single JSON-RPC line this client will read, matching the limit
// stratium-pep's own mcp proxy applies (services/cmd/stratium-pep/mcp.go) -- generous for any real
// tool payload, and a stated bound rather than an unbounded scanner buffer.
const MaxFrameBytes = 32 * 1024 * 1024

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	ID     int             `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
}

// Tool is one entry from `tools/list`, before a caller turns it into its own tool-spec shape --
// this package deliberately stays free of stratium/example/agent's own ToolSpec type so it can be
// reused without pulling that dependency in just to describe a tool.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// Client is a child process speaking MCP over stdio, already past the initialize handshake.
type Client struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	nextID int
}

// Start launches command/args as a child process (env, if non-nil, replaces the child's
// environment; nil inherits this process's own), performs the MCP initialize/
// notifications/initialized handshake, and fetches the tool list via tools/list.
func Start(command string, args []string, env []string, stderr io.Writer) (*Client, []Tool, error) {
	cmd := exec.Command(command, args...) //nolint:gosec // G204: command/args are the caller's own fixed configuration, never request data.
	cmd.Env = env
	cmd.Stderr = stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcpwire: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("mcpwire: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: could not start %q: %w", command, err)
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 4096), MaxFrameBytes)
	c := &Client{cmd: cmd, stdin: stdin, lines: scanner}

	if _, rpcErr, err := c.Request("initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "stratium-example-mcp-agent", "version": "0.1.0"},
	}); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: initialize: %w", err)
	} else if rpcErr != nil {
		return nil, nil, fmt.Errorf("mcpwire: initialize: server error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	// A notification: no id, no response expected or read. Required before the server will answer
	// anything else -- omitting it left tools/list hanging against the real server.
	if err := c.writeLine(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: notifications/initialized: %w", err)
	}

	result, rpcErr, err := c.Request("tools/list", map[string]any{})
	if err != nil {
		return nil, nil, fmt.Errorf("mcpwire: tools/list: %w", err)
	}
	if rpcErr != nil {
		return nil, nil, fmt.Errorf("mcpwire: tools/list: server error %d: %s", rpcErr.Code, rpcErr.Message)
	}
	var parsed struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: tools/list: malformed result: %w", err)
	}
	tools := make([]Tool, len(parsed.Tools))
	for i, t := range parsed.Tools {
		tools[i] = Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema}
	}
	return c, tools, nil
}

// Close asks the child to shut down (closing its stdin, the standard stdio-subprocess shutdown
// contract) and waits for it to exit.
func (c *Client) Close() error {
	_ = c.stdin.Close()
	return c.cmd.Wait()
}

func (c *Client) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("mcpwire: encode: %w", err)
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("mcpwire: write to child: %w", err)
	}
	return nil
}

// Request sends a JSON-RPC request and blocks for its response. This client never has more than
// one request in flight -- a caller's own agent loop calls Call sequentially, one tool call at a
// time -- so, unlike stratium-pep's own mcp proxy, there is no need to correlate responses out of
// order; the very next line read is the answer to the request just sent, and its id is checked
// against that assumption rather than trusted blindly.
func (c *Client) Request(method string, params any) (json.RawMessage, *RPCError, error) {
	c.nextID++
	id := c.nextID
	if err := c.writeLine(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params}); err != nil {
		return nil, nil, err
	}
	if !c.lines.Scan() {
		if err := c.lines.Err(); err != nil {
			return nil, nil, fmt.Errorf("mcpwire: reading response to %q: %w", method, err)
		}
		return nil, nil, fmt.Errorf("mcpwire: reading response to %q: child closed its output", method)
	}
	var resp rpcResponse
	if err := json.Unmarshal(c.lines.Bytes(), &resp); err != nil {
		return nil, nil, fmt.Errorf("mcpwire: malformed response to %q: %w", method, err)
	}
	if resp.ID != id {
		return nil, nil, fmt.Errorf("mcpwire: response id %d does not match request id %d for %q", resp.ID, id, method)
	}
	return resp.Result, resp.Error, nil
}

// ExtractText pulls the plain-text answer out of an MCP tool result's `content` array (every read
// tool in @modelcontextprotocol/server-filesystem answers with `{"content":[{"type":"text",...}]}`
// -- captured the same way Start's own handshake was). A shape this does not recognize is returned
// as its raw JSON rather than silently discarded, so an unexpected result is still visible in the
// transcript instead of showing up as an empty answer.
func ExtractText(raw json.RawMessage) string {
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
