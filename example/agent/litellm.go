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

func (l *LLM) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (Message, error) {
	body := map[string]any{
		"model":       l.Model,
		"messages":    msgs,
		"temperature": 0,
	}
	if len(tools) > 0 {
		var ts []map[string]any
		for _, t := range tools {
			ts = append(ts, map[string]any{"type": "function", "function": map[string]any{
				"name": t.Name, "description": t.Description, "parameters": t.Schema}})
		}
		body["tools"] = ts
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
		_ = json.Unmarshal([]byte(rc.Function.Arguments), &args)
		m.ToolCalls = append(m.ToolCalls, ToolCall{Name: rc.Function.Name, Args: args})
	}
	return m, nil
}
