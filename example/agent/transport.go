package agent

import (
	"context"
	"encoding/json"
)

// ToolSpec is one tool as advertised to the model.
//
// Schema is a raw JSON Schema object, not map[string]any, deliberately: a Go map has no key
// order, and json.Marshal on map[string]any always re-serializes its keys ALPHABETICALLY --
// confirmed empirically to matter, not merely cosmetic. A tool's real inputSchema, decoded from an
// upstream MCP server's own tools/list response, typically opens with `"$schema"` then
// `"type":"object"` then `"properties"`; round-tripped through a Go map it comes back out
// alphabetized ($schema, properties, required, type), moving "type":"object" away from where the
// server itself put it. litellm's own local function-calling translation for a model that has no
// native tool-calling support (llama3.2 via ollama, every runnable example in this suite) turned
// out to be sensitive to exactly that: an otherwise byte-for-byte identical request whose tool
// schemas were re-ordered this way made llama3.2 reliably answer with prose describing a fake tool
// call instead of a genuine one, for schemas with more than one property (search_files, see
// example/depth/mcp) -- not a plausible-sounding theory but a reproducible, isolated finding.
// json.RawMessage carries a tool's schema through this whole pipeline byte-for-byte unchanged, the
// same "relay faithfully" principle stratium-pep's own mcp.go package doc states for JSON-RPC
// frames, applied here to a different payload.
type ToolSpec struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// ToolCall is the model's request to invoke one.
type ToolCall struct {
	Name string
	Args map[string]any
}

// Result is what the surface answered. Allowed=false with a Reason is a
// POLICY answer, not a transport error -- a transport error is returned
// separately, because "the PDP said no" and "the network broke" must never
// be confused: one is the example working, the other is the example broken.
type Result struct {
	Allowed bool
	Reason  string
	Output  string
}

// Transport is how a tool call actually travels. Implemented once per
// surface; the agent loop never learns which one it has.
type Transport interface {
	Tools() []ToolSpec
	Call(context.Context, ToolCall) (Result, error)
}
