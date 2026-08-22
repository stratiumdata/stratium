package agent

import "context"

// ToolSpec is one tool as advertised to the model.
type ToolSpec struct {
	Name        string
	Description string
	Schema      map[string]any // JSON Schema for the arguments object
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
