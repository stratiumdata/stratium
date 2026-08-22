package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeTransport records what it was asked and answers from a script.
type fakeTransport struct {
	results map[string]Result
	errs    map[string]error // keyed by tool name; checked before results
	seen    []ToolCall
}

func (f *fakeTransport) Tools() []ToolSpec {
	return []ToolSpec{{Name: "read", Description: "read a file",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string"}}}}}
}

func (f *fakeTransport) Call(_ context.Context, c ToolCall) (Result, error) {
	f.seen = append(f.seen, c)
	if err, ok := f.errs[c.Name]; ok {
		return Result{}, err
	}
	return f.results[c.Args["path"].(string)], nil
}

// litellmStub replays a fixed sequence of assistant messages, so the loop is
// exercised without a model.
func litellmStub(t *testing.T, replies []string) *httptest.Server {
	t.Helper()
	i := 0
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i >= len(replies) {
			t.Fatalf("stub called %d times, only %d replies scripted", i+1, len(replies))
		}
		body := replies[i]
		i++
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
}

const replyCallsRead = `{"choices":[{"message":{"role":"assistant","tool_calls":[
  {"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":\"/d/secret-x\"}"}}]}}]}`
const replyDone = `{"choices":[{"message":{"role":"assistant","content":"That one is classified, so I stopped."}}]}`

func TestRun_DeniedCallIsRecordedAndFedBackToTheModel(t *testing.T) {
	srv := litellmStub(t, []string{replyCallsRead, replyDone})
	defer srv.Close()

	ft := &fakeTransport{results: map[string]Result{
		"/d/secret-x": {Allowed: false, Reason: "exceeds delegation cap CONFIDENTIAL"}}}

	rep := Run(context.Background(), &LLM{BaseURL: srv.URL, Model: "m", HTTP: srv.Client()},
		ft, "read the file", []Expectation{{Tool: "read", ArgContains: "secret-", Want: Deny}}, io.Discard)

	if len(ft.seen) != 1 {
		t.Fatalf("transport saw %d calls, want 1", len(ft.seen))
	}
	if rep.ExitCode() != 0 {
		t.Errorf("ExitCode() = %d, want 0 — the deny was expected", rep.ExitCode())
	}
}

// The denial's REASON must reach the model, or it cannot react to its own
// governance -- which is the entire point of using a real model here.
func TestRun_DenialReasonIsSentBackAsAToolMessage(t *testing.T) {
	var second map[string]any
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i == 1 {
			json.NewDecoder(r.Body).Decode(&second)
		}
		body := replyCallsRead
		if i == 1 {
			body = replyDone
		}
		i++
		io.WriteString(w, body)
	}))
	defer srv.Close()

	ft := &fakeTransport{results: map[string]Result{
		"/d/secret-x": {Allowed: false, Reason: "exceeds delegation cap CONFIDENTIAL"}}}
	Run(context.Background(), &LLM{BaseURL: srv.URL, Model: "m", HTTP: srv.Client()},
		ft, "read it", nil, io.Discard)

	raw, _ := json.Marshal(second)
	if !strings.Contains(string(raw), "exceeds delegation cap CONFIDENTIAL") {
		t.Errorf("the denial reason never reached the model:\n%s", raw)
	}
}

// A transport error is the example being broken (network down, process
// dead), not the PDP answering. It must abort the run immediately -- proven
// here by scripting only ONE reply, so a second Chat call fails the stub --
// and must leave the matching expectation NEVER TRIED rather than satisfied.
// If the loop instead recorded a zero-valued Result{Allowed:false} as a
// decision, the Deny expectation below would be wrongly satisfied and
// ExitCode() would come back 0 on a stack that enforced nothing.
func TestRun_TransportErrorAbortsAndRecordsNoDecision(t *testing.T) {
	srv := litellmStub(t, []string{replyCallsRead})
	defer srv.Close()

	ft := &fakeTransport{errs: map[string]error{"read": errors.New("connection reset by peer")}}

	rep := Run(context.Background(), &LLM{BaseURL: srv.URL, Model: "m", HTTP: srv.Client()},
		ft, "read the file", []Expectation{{Tool: "read", ArgContains: "secret-", Want: Deny}}, io.Discard)

	if len(ft.seen) != 1 {
		t.Fatalf("transport saw %d calls, want 1 -- the loop must abort on error, not continue", len(ft.seen))
	}
	if rep.ExitCode() == 0 {
		t.Fatal("ExitCode() = 0 after a transport error; the expectation was never tried and must fail")
	}
}

func TestRun_ProseOnlyTurnIsInconclusive(t *testing.T) {
	srv := litellmStub(t, []string{replyDone})
	defer srv.Close()
	rep := Run(context.Background(), &LLM{BaseURL: srv.URL, Model: "m", HTTP: srv.Client()},
		&fakeTransport{results: map[string]Result{}}, "hello", nil, io.Discard)
	if rep.inconclusive != 1 {
		t.Errorf("inconclusive = %d, want 1", rep.inconclusive)
	}
}
