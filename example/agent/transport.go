package agent

import (
	"context"
	"encoding/json"
)

// ToolSpec is one tool as advertised to the model.
//
// Schema is a raw JSON Schema object, not map[string]any, on FIDELITY grounds alone: this whole
// suite's own principle for a proxy is "relay faithfully, never re-encode" (stratium-pep's own
// mcp.go package doc, stated there for JSON-RPC frames) -- a tool's schema deserves the identical
// discipline. A Go map has no key order, and json.Marshal on map[string]any always re-serializes
// its keys ALPHABETICALLY regardless of insertion order. A tool's real inputSchema, decoded from an
// upstream MCP server's own tools/list response, typically opens with `"$schema"` then
// `"type":"object"` then `"properties"`; round-tripped through a Go map it comes back out
// alphabetized ($schema, properties, required, type) -- a different document than the one the
// server declared, even though every key/value pair survived. That alone is reason enough:
// forwarding a re-ordered schema to the model is not what an honest relay does, independent of
// whether any model happens to mind. (One local model did, during development, for a
// multi-property schema -- see agent.LLM.ToolChoice's own doc comment -- but this field's
// justification does not rest on that observation.) json.RawMessage carries a tool's schema through
// this whole pipeline byte-for-byte unchanged, closing that gap.
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
