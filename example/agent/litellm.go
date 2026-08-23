package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// LLM talks to LiteLLM's OpenAI-compatible /chat/completions endpoint. Plain
// net/http rather than an SDK: the request is small, and a dependency here
// would be one more thing a reader has to trust to understand the example.
type LLM struct {
	BaseURL string // e.g. http://localhost:4000
	Model   string
	HTTP    *http.Client

	// ToolChoice, when non-empty, is sent as an OpenAI tool_choice forcing exactly this named
	// tool, on every turn, instead of leaving tool selection to the model (the default, empty
	// string, omits tool_choice entirely -- today's unchanged "auto" behavior every existing
	// example already relies on). This is a MODEL-RELIABILITY knob, never a policy one: forcing
	// which tool the model ATTEMPTS never predetermines whether the surface under test ALLOWS or
	// DENIES that attempt -- the real PDP still decides that live, exactly as it would for a call
	// the model chose on its own.
	//
	// It exists for example/depth/mcp's two forced probes, as insurance alongside the
	// json.RawMessage schema fix (ToolSpec's own doc comment, transport.go), not a workaround for
	// it: that fix is what made this suite's schemas honest; ToolChoice is a separate, unrelated
	// lever that removes free-form tool SELECTION as a variable entirely, for the two probes that
	// exist specifically to prove which tool a delegation does or doesn't hold at a given depth.
	// Cheap to set, harmless when unset (every other example leaves it empty), and never a
	// substitute for fixing an actual defect -- see this field's own callers for why it is used
	// only where forcing genuinely helps rather than papering over one.
	ToolChoice string
}

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"-"`

	RawToolCalls []rawToolCall `json:"tool_calls,omitempty"`
}

type rawToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // a JSON *string*, per the OpenAI shape
	} `json:"function"`
}

// toolDef/toolFunction are typed, not map[string]any, on the same FIDELITY grounds ToolSpec's own
// Schema field is (transport.go): a plain map[string]any marshals its keys SORTED ALPHABETICALLY
// regardless of insertion order, so a map-shaped {"type":"function","function":{...}} would
// silently go out on the wire as {"function":{...},"type":"function"} -- not the shape this file's
// own code above expresses. Declared struct fields keep the order this file actually writes.
// (One local model answered with prose instead of a genuine tool call more often when a tool's own
// object was reordered this way, observed during development on a multi-property schema -- see
// agent.LLM.ToolChoice's own doc comment for how this suite responds to that kind of model
// variance. That observation is not why this type exists; a request whose shape does not match
// what the code sending it says it sends is a defect regardless of whether any model minds.)
// Parameters is json.RawMessage for the identical reason one level down -- see ToolSpec's own
// Schema field for the fuller story.
type toolDef struct {
	Type     string       `json:"type"`
	Function toolFunction `json:"function"`
}

type toolFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

func (l *LLM) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (Message, error) {
	body := map[string]any{
		"model":       l.Model,
		"messages":    msgs,
		"temperature": 0,
	}
	if len(tools) > 0 {
		var ts []toolDef
		for _, t := range tools {
			ts = append(ts, toolDef{Type: "function", Function: toolFunction{
				Name: t.Name, Description: t.Description, Parameters: t.Schema}})
		}
		body["tools"] = ts
		if l.ToolChoice != "" {
			body["tool_choice"] = map[string]any{"type": "function", "function": map[string]string{"name": l.ToolChoice}}
		}
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return Message{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		l.BaseURL+"/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return Message{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := l.HTTP
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return Message{}, fmt.Errorf("litellm: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Choices []struct{ Message Message } `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Message{}, fmt.Errorf("litellm: decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return Message{}, fmt.Errorf("litellm: no choices in response")
	}

	m := out.Choices[0].Message
	for _, rc := range m.RawToolCalls {
		args := map[string]any{}
		// A model that emits malformed arguments must not silently degrade to
		// a call with an empty args map -- that reads as a deliberate call
		// with no arguments, not the parse failure it actually was. Surface
		// it as an error instead: this whole loop exists to make governance
		// visible, and a swallowed parse error is the same failure family.
		if err := json.Unmarshal([]byte(rc.Function.Arguments), &args); err != nil {
			return Message{}, fmt.Errorf("litellm: tool call %q: malformed arguments %q: %w",
				rc.Function.Name, rc.Function.Arguments, err)
		}
		m.ToolCalls = append(m.ToolCalls, ToolCall{Name: rc.Function.Name, Args: args})
	}
	return m, nil
}
