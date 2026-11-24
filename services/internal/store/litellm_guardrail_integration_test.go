//go:build integration

package store_test

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// These proofs run against litellm-guarded: a real LiteLLM proxy with
// deploy/litellm/stratium_guardrail.py loaded, in front of a mock model and
// a mock MCP server that each offer one read tool and one write tool
// (deploy/docker/litellm/mock_llm.py, mock_mcp.py). The proxy asks pdp-mcp
// for a delegation holding the two read tools only.
//
// deploy/litellm's own tests call the guardrail classes directly. Only a
// running proxy shows that LiteLLM loads them, calls them on every route
// below, and delivers what they return.

const (
	// Fixed in docker-compose.yml: the proxy reads them at start-up.
	litellmAgentID   = "6c1e7e11-0000-4000-8000-000000000001"
	litellmSubject   = "litellm-guarded@example.com"
	litellmMasterKey = "sk-local-dev-only"

	litellmChatRefusal = `[Stratium refused guarded_write: tool \"guarded_write\" not in delegation approved_tools`
	litellmUnchecked   = "are not checked yet"
)

var litellmSeed sync.Once

// litellmGuarded seeds the proxy's agent and policy once and returns the
// proxy's base URL.
func litellmGuarded(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("STRATIUM_IT_LITELLM_GUARDED_ADDR")
	if addr == "" || mcpTenant == "" {
		t.Fatal("STRATIUM_IT_LITELLM_GUARDED_ADDR and STRATIUM_IT_MCP_TENANT_ID must be set: run via `make integration`")
	}
	litellmSeed.Do(func() {
		seedAgent(t, mcpTenant, uuid.MustParse(litellmAgentID), "integration-agent-litellm-guarded", models.TrustTierPlatformTrusted)
		seedPolicy(t, mcpTenant, "litellm-guarded-permit",
			fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, litellmSubject), "allow")
	})
	return "http://" + addr
}

// litellmPost sends body to the proxy with the master key and returns the
// status and the whole reply, streamed or not.
func litellmPost(t *testing.T, url, body string, headers ...string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request to %s: %v", url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+litellmMasterKey)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply from %s: %v", url, err)
	}
	return resp.StatusCode, string(raw)
}

// The model proposes guarded_read and guarded_write in one reply. The client
// receives the first and, in place of the second, the PDP's reason as text.
func TestIntegration_LiteLLMGuardrail_ChatKeepsGrantedCallAndRemovesRefused(t *testing.T) {
	base := litellmGuarded(t)
	for _, tc := range []struct{ name, stream string }{{"whole", "false"}, {"streamed", "true"}} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := litellmPost(t, base+"/v1/chat/completions",
				`{"model":"mock","stream":`+tc.stream+`,"messages":[{"role":"user","content":"hi"}]}`)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200: %s", status, body)
			}
			if !strings.Contains(body, `"name":"guarded_read"`) {
				t.Errorf("the granted call guarded_read is missing from the reply: %s", body)
			}
			if strings.Contains(body, `"name":"guarded_write"`) {
				t.Errorf("the refused call guarded_write reached the client: %s", body)
			}
			if !strings.Contains(body, litellmChatRefusal) {
				t.Errorf("the reply does not carry the PDP's reason for refusing guarded_write: %s", body)
			}
		})
	}
}

// A granted MCP call runs. A refused one comes back as a tool error with the
// PDP's reason, and the upstream server's own text shows it did not run.
//
// Neither call is preceded by tools/list, on purpose. LiteLLM then asks the
// guardrail about each tool's description first, in the shape of a call with
// no arguments, and a guardrail that decided that question would give
// LiteLLM's own "unavailable after MCP guardrail checks" in place of the
// PDP's reason.
func TestIntegration_LiteLLMGuardrail_MCPRunsGrantedCallAndRefusesTheOther(t *testing.T) {
	base := litellmGuarded(t)
	call := func(tool, args string) string {
		t.Helper()
		status, body := litellmPost(t, base+"/mcp",
			`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+tool+`","arguments":`+args+`}}`,
			"x-litellm-api-key", "Bearer "+litellmMasterKey,
			"Accept", "application/json, text/event-stream")
		if status != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200: %s", tool, status, body)
		}
		return body
	}

	read := call("guarded-read_file", `{"path":"/tmp/notes.txt"}`)
	if !strings.Contains(read, "read_file ran on /tmp/notes.txt") || !strings.Contains(read, `"isError":false`) {
		t.Errorf("the granted call did not run: %s", read)
	}

	write := call("guarded-write_file", `{"path":"/tmp/notes.txt","content":"x"}`)
	if strings.Contains(write, "write_file ran") {
		t.Fatalf("the refused call ran on the upstream server: %s", write)
	}
	if !strings.Contains(write, `"isError":true`) ||
		!strings.Contains(write, `guarded-write_file refused: tool \"guarded-write_file\" not in delegation approved_tools`) {
		t.Errorf("the refusal is not a tool error carrying the PDP's reason: %s", write)
	}
}

// Replies the guardrail cannot read tool calls from are refused with 501
// rather than passed on unchecked. The mock model proposes its tool calls on
// these routes too, so a reply that named one would be an unchecked call.
func TestIntegration_LiteLLMGuardrail_RoutesItCannotReadAreRefused(t *testing.T) {
	base := litellmGuarded(t)
	anthropic := []string{"anthropic-version", "2023-06-01"}
	for _, tc := range []struct {
		name, path, body string
		headers          []string
	}{
		{"messages", "/v1/messages", `{"model":"mock","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}`, anthropic},
		{"messages streamed", "/v1/messages", `{"model":"mock","max_tokens":50,"stream":true,"messages":[{"role":"user","content":"hi"}]}`, anthropic},
		{"responses", "/v1/responses", `{"model":"mock","input":"hi"}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := litellmPost(t, base+tc.path, tc.body, tc.headers...)
			if status != http.StatusNotImplemented || !strings.Contains(body, litellmUnchecked) {
				t.Errorf("status = %d, want 501 saying tool calls %s: %s", status, litellmUnchecked, body)
			}
			if strings.Contains(body, "guarded_read") || strings.Contains(body, "guarded_write") {
				t.Errorf("an unchecked tool call reached the client: %s", body)
			}
		})
	}
}
