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
	// the model chose on its own. It exists because llama3.2's own free-form tool selection for at
	// least one real tool schema in this suite (search_files, offered alongside the upstream MCP
	// filesystem server's full 14-tool catalog -- see example/depth/mcp) was confirmed, empirically
	// and repeatedly, to drift between fully reliable and fully unreliable across otherwise
	// byte-for-byte identical requests over time, with no code-path difference behind the drift --
	// consistent with llama.cpp's own documented lack of bit-for-bit reproducibility under
	// multi-threaded CPU inference, not a bug this client can fix by construction. Forcing the one
	// tool a given conversation exists to probe removes that source of flakiness from the parts of
	// this suite that would otherwise need many retries to catch a live pass.
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

// toolDef/toolFunction are typed, not map[string]any, so that json.Marshal emits "type" before
// "function" in that declared field order -- a plain map[string]any would marshal with its keys
// SORTED ALPHABETICALLY instead ("function" before "type"), regardless of insertion order. That
// reordering is not cosmetic: confirmed empirically against a live litellm/ollama, an otherwise
// byte-for-byte identical request whose per-tool object leads with "function" instead of "type"
// makes llama3.2 reliably answer a tool call as prose text in its own message content instead of a
// genuine tool_calls entry, for at least one real tool schema in this suite (search_files, see
// example/depth/mcp) -- the exact "model answered in prose" failure mode Report.Print already
// warns is "a model limitation, not an enforcement failure." This ordering fix removes one
// self-inflicted cause of it. Parameters is json.RawMessage, not map[string]any, for the identical
// reason one level down -- see ToolSpec's own Schema field (transport.go) for the fuller story.
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
