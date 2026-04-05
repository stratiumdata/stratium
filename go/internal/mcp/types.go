package mcp

import "encoding/json"

// JSON-RPC 2.0 message types for MCP protocol.

// Request represents a JSON-RPC 2.0 request.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParse          = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternal       = -32603
)

// MCP protocol types.

// ServerInfo describes the MCP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Capabilities describes what the server supports.
type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability indicates tools support.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// InitializeResult is returned from the initialize handshake.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

// Tool describes an MCP tool.
type Tool struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	InputSchema ToolSchema `json:"inputSchema"`
}

// ToolSchema is a JSON Schema for tool inputs.
type ToolSchema struct {
	Type       string                    `json:"type"`
	Properties map[string]PropertySchema `json:"properties,omitempty"`
	Required   []string                  `json:"required,omitempty"`
}

// PropertySchema describes a single property in a tool schema.
type PropertySchema struct {
	Type        string         `json:"type"`
	Description string         `json:"description,omitempty"`
	Items       *PropertySchema `json:"items,omitempty"`
	Enum        []string       `json:"enum,omitempty"`
	Default     any            `json:"default,omitempty"`
}

// ToolsListResult is returned from tools/list.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// ToolCallParams are the parameters for tools/call.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolCallResult is returned from tools/call.
type ToolCallResult struct {
	Content []ContentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

// ContentBlock is a piece of content in a tool result.
type ContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// TextContent creates a text content block.
func TextContent(text string) ContentBlock {
	return ContentBlock{Type: "text", Text: text}
}
