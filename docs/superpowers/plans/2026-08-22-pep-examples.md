# PEP Examples Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `example/{hook,mcp,proxy,extauthz}/` — three runnable programs sharing one agent that reasons through a local Ollama model via LiteLLM, plus a configuration-only `hook` directory.

**Architecture:** A new Go module at `example/`, added to `go.work`. `example/agent` owns the model loop and the enforcement tally and knows nothing about any surface; each `example/<surface>/main.go` supplies a `Transport` saying how a tool call travels. One `session-start` issues one delegation whose token is carried three different ways.

**Tech Stack:** Go 1.25, gRPC, plain `net/http` against LiteLLM's OpenAI-compatible API, hand-rolled JSON-RPC over stdio for MCP. No new third-party dependencies beyond what `services` already uses.

**Spec:** `docs/superpowers/specs/2026-08-22-pep-examples-design.md`

## Global Constraints

- **Go module:** `example/` is its OWN module (`module stratium/example`), added to `go.work`. The repo root has no `go.mod`, so `example/` cannot be part of the `stratium` module.
- **Assert on PEP decisions only.** Never assert on model output. A turn with no tool call is `INCONCLUSIVE` and does not fail the run.
- **`gpt-4o` is deliberately unreachable in LiteLLM.** The denial must carry a PDP reason, never a connection error. Any code or doc that could confuse the two must say which one it got.
- **The agent's own reasoning traffic goes DIRECT to LiteLLM, never through Envoy.** Only the `ask_model` tool takes the policed path. Routing both deadlocks the extauthz example.
- **`CallCount` is dialled DIRECTLY at `grpc-target`, bypassing the proxy.** It is a side channel on purpose.
- **Examples are not in `make test`.** They need Ollama, a pulled model and a live stack. Only `example/agent`'s unit tests run there.
- Tests for the module run from `example/`: `cd example && go test ./...`

---

### Task 1: Make the gRPC target client importable from outside `services`

**Files:**
- Move: `services/internal/grpctarget/` → `services/pkg/grpctarget/`
- Modify: `proto/target/v1/target.proto:25` (`option go_package`)
- Modify: `services/cmd/grpc-target/main.go`, `services/internal/store/proxy_integration_test.go`, `services/internal/store/store_integration_test.go` (import paths)

**Interfaces:**
- Consumes: nothing.
- Produces: `stratium/pkg/grpctarget`, exporting `NewTargetServiceClient(grpc.ClientConnInterface) TargetServiceClient` with `Fetch(ctx, *EchoRequest, ...) (*EchoResponse, error)`, `Purge(...)` the same, and `CallCount(ctx, *CallCountRequest, ...) (*CallCountResponse, error)`. `EchoRequest{Message string}`, `CallCountResponse{Count int64}`.

**Why:** Go forbids importing `…/internal/…` from another module. `example/` is another module, so the proxy example cannot use these stubs where they are. `services/pkg/` already holds `audit`, `classification` and `models` — it is this repo's public surface, and generated client stubs a consumer needs belong there.

- [ ] **Step 1: Move the package and update the proto's go_package**

```bash
cd /path/to/stratium-data
git mv services/internal/grpctarget services/pkg/grpctarget
```

In `proto/target/v1/target.proto` line 25:

```diff
-option go_package = "stratium/internal/grpctarget;grpctarget";
+option go_package = "stratium/pkg/grpctarget;grpctarget";
```

- [ ] **Step 2: Update the three importers**

```bash
grep -rl '"stratium/internal/grpctarget"' services --include='*.go' \
  | xargs sed -i '' 's|"stratium/internal/grpctarget"|"stratium/pkg/grpctarget"|'
```

- [ ] **Step 3: Verify the build and the existing tests still pass**

Run: `cd services && go build ./... && go vet ./... && go test ./...`
Expected: all packages `ok`. No behaviour changed — this is a move.

- [ ] **Step 4: Verify the generated files still match their source**

Run: `make proto && git diff --stat services/pkg/grpctarget`
Expected: no diff. If `protoc` is unavailable, skip and note it — the `go_package` edit and the directory move are consistent by construction.

- [ ] **Step 5: Commit**

```bash
git add -A services proto
git commit -m "refactor: move grpctarget to pkg so consumers outside the module can use it"
```

---

### Task 2: The `example` module and the agent's types, report and prechecks

**Files:**
- Create: `example/go.mod`, `example/README.md`
- Create: `example/agent/transport.go`, `example/agent/report.go`, `example/agent/precheck.go`
- Create: `example/agent/report_test.go`, `example/agent/precheck_test.go`
- Modify: `go.work`
- Create: `.gitignore` entry for `example/.session.json`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type ToolSpec struct { Name, Description string; Schema map[string]any }`
  - `type ToolCall struct { Name string; Args map[string]any }`
  - `type Result struct { Allowed bool; Reason, Output string }`
  - `type Transport interface { Tools() []ToolSpec; Call(context.Context, ToolCall) (Result, error) }`
  - `type Outcome int` with `Allow` and `Deny`
  - `type Expectation struct { Tool, ArgContains string; Want Outcome }`
  - `type Report struct { … }` with `func (r *Report) Record(ToolCall, Result)`, `func (r *Report) NoToolCall()`, `func (r *Report) Print(io.Writer)`, `func (r *Report) ExitCode() int`
  - `func Precheck(checks ...Check) error`, `type Check struct { Name string; Probe func() error; Fix string }`

- [ ] **Step 1: Create the module and register it in the workspace**

```bash
mkdir -p example/agent
cd example && go mod init stratium/example && cd ..
```

`go.work` becomes:

```
go 1.25.0

use ./services
use ./example
```

Append to `.gitignore`:

```
# the examples' shared delegation — bearer authority, never committed
/example/.session.json
```

- [ ] **Step 2: Write the failing report test**

```go
// example/agent/report_test.go
package agent

import (
	"bytes"
	"strings"
	"testing"
)

func TestReport_MatchingOutcomesPass(t *testing.T) {
	r := NewReport([]Expectation{
		{Tool: "read_text_file", ArgContains: "notes.txt", Want: Allow},
		{Tool: "read_text_file", ArgContains: "secret-", Want: Deny},
	})
	r.Record(ToolCall{Name: "read_text_file", Args: map[string]any{"path": "/d/notes.txt"}},
		Result{Allowed: true, Output: "hi"})
	r.Record(ToolCall{Name: "read_text_file", Args: map[string]any{"path": "/d/secret-x/a"}},
		Result{Allowed: false, Reason: "exceeds delegation cap"})

	if got := r.ExitCode(); got != 0 {
		t.Fatalf("ExitCode() = %d, want 0", got)
	}
}

// The failure that matters most: something we expected to be DENIED went
// through. That is enforcement not working, and it must be loud.
func TestReport_ExpectedDenyButAllowedFails(t *testing.T) {
	r := NewReport([]Expectation{{Tool: "purge", ArgContains: "", Want: Deny}})
	r.Record(ToolCall{Name: "purge", Args: map[string]any{"message": "x"}},
		Result{Allowed: true, Output: "ok"})

	if got := r.ExitCode(); got == 0 {
		t.Fatal("ExitCode() = 0 for a denied-expectation that was ALLOWED; must be non-zero")
	}
	var b bytes.Buffer
	r.Print(&b)
	if !strings.Contains(b.String(), "expected DENY, was ALLOWED") {
		t.Errorf("Print() does not name the mismatch:\n%s", b.String())
	}
}

// The mirror: something we expected to work was refused. Also a failure --
// an over-broad policy is a bug too, and silently tolerating it would let
// the examples "pass" on a stack that denies everything.
func TestReport_ExpectedAllowButDeniedFails(t *testing.T) {
	r := NewReport([]Expectation{{Tool: "fetch", ArgContains: "", Want: Allow}})
	r.Record(ToolCall{Name: "fetch", Args: nil}, Result{Allowed: false, Reason: "nope"})
	if got := r.ExitCode(); got == 0 {
		t.Fatal("ExitCode() = 0 for an allowed-expectation that was DENIED; must be non-zero")
	}
}

// A model that answers in prose instead of calling a tool is a MODEL problem.
// It must be reported and must not fail the run.
func TestReport_NoToolCallIsInconclusiveNotFailure(t *testing.T) {
	r := NewReport(nil)
	r.NoToolCall()
	r.NoToolCall()
	if got := r.ExitCode(); got != 0 {
		t.Fatalf("ExitCode() = %d for inconclusive turns, want 0", got)
	}
	var b bytes.Buffer
	r.Print(&b)
	if !strings.Contains(b.String(), "2 inconclusive") {
		t.Errorf("Print() does not report inconclusive turns:\n%s", b.String())
	}
}

// Unmet expectations are failures: if the model never attempted the denied
// call, the example proved nothing about enforcement.
func TestReport_UnmetExpectationFails(t *testing.T) {
	r := NewReport([]Expectation{{Tool: "purge", ArgContains: "", Want: Deny}})
	if got := r.ExitCode(); got == 0 {
		t.Fatal("ExitCode() = 0 with an expectation never exercised; must be non-zero")
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd example && go test ./agent/ -run TestReport -v`
Expected: FAIL — `undefined: NewReport`.

- [ ] **Step 4: Write `transport.go` and `report.go`**

```go
// example/agent/transport.go
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
```

```go
// example/agent/report.go
package agent

import (
	"fmt"
	"io"
	"strings"
)

type Outcome int

const (
	Allow Outcome = iota
	Deny
)

func (o Outcome) String() string {
	if o == Allow {
		return "ALLOW"
	}
	return "DENY"
}

// Expectation is one enforcement claim the example makes. ArgContains
// distinguishes two calls to the same tool -- reading notes.txt from reading
// secret-x/plans.txt -- by substring against any string argument. Empty
// matches any arguments.
type Expectation struct {
	Tool        string
	ArgContains string
	Want        Outcome
}

type observation struct {
	call    ToolCall
	result  Result
	matched *Expectation
}

type Report struct {
	want         []Expectation
	met          []bool
	observations []observation
	inconclusive int
}

func NewReport(want []Expectation) *Report {
	return &Report{want: want, met: make([]bool, len(want))}
}

// Record files one decision. An observation matching no expectation is kept
// and printed but never fails the run: the model is free to try things we did
// not predict, and refusing to run because it was creative would be absurd.
func (r *Report) Record(c ToolCall, res Result) {
	obs := observation{call: c, result: res}
	for i := range r.want {
		if r.want[i].matches(c) {
			r.met[i] = true
			obs.matched = &r.want[i]
			break
		}
	}
	r.observations = append(r.observations, obs)
}

func (r *Report) NoToolCall() { r.inconclusive++ }

func (e Expectation) matches(c ToolCall) bool {
	if e.Tool != c.Name {
		return false
	}
	if e.ArgContains == "" {
		return true
	}
	for _, v := range c.Args {
		if s, ok := v.(string); ok && strings.Contains(s, e.ArgContains) {
			return true
		}
	}
	return false
}

func (r *Report) mismatches() []string {
	var out []string
	for _, o := range r.observations {
		if o.matched == nil {
			continue
		}
		got := Deny
		if o.result.Allowed {
			got = Allow
		}
		if got != o.matched.Want {
			out = append(out, fmt.Sprintf("  MISMATCH  %-24s expected %s, was %s",
				o.call.Name, o.matched.Want, got))
		}
	}
	for i, met := range r.met {
		if !met {
			out = append(out, fmt.Sprintf("  NEVER TRIED  %-21s expected %s — the model did not attempt it, so nothing was proven",
				r.want[i].Tool, r.want[i].Want))
		}
	}
	return out
}

func (r *Report) Print(w io.Writer) {
	bad := r.mismatches()
	fmt.Fprintf(w, "\nenforcement: %d/%d as expected\n", len(r.want)-len(r.unmetOrWrong()), len(r.want))
	for _, line := range bad {
		fmt.Fprintln(w, line)
	}
	if r.inconclusive > 0 {
		fmt.Fprintf(w, "  %d inconclusive turn(s) — the model answered in prose instead of calling a tool.\n", r.inconclusive)
		fmt.Fprintf(w, "  That is a model limitation, not an enforcement failure. A larger model calls tools more reliably.\n")
	}
}

func (r *Report) unmetOrWrong() []string { return r.mismatches() }

func (r *Report) ExitCode() int {
	if len(r.mismatches()) > 0 {
		return 1
	}
	return 0
}
```

- [ ] **Step 5: Run to verify the report tests pass**

Run: `cd example && go test ./agent/ -run TestReport -v`
Expected: PASS, all five.

- [ ] **Step 6: Write the failing precheck test**

```go
// example/agent/precheck_test.go
package agent

import (
	"errors"
	"strings"
	"testing"
)

// A missing prerequisite must never read like a Stratium denial. The error
// names the thing and the fix.
func TestPrecheck_FailureNamesTheFix(t *testing.T) {
	err := Precheck(
		Check{Name: "ollama", Probe: func() error { return nil }, Fix: "start ollama"},
		Check{Name: "litellm", Probe: func() error { return errors.New("connection refused") },
			Fix: "docker compose up -d litellm"},
	)
	if err == nil {
		t.Fatal("Precheck() = nil with a failing check")
	}
	for _, want := range []string{"litellm", "connection refused", "docker compose up -d litellm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestPrecheck_AllPassing(t *testing.T) {
	if err := Precheck(Check{Name: "x", Probe: func() error { return nil }}); err != nil {
		t.Fatalf("Precheck() = %v, want nil", err)
	}
}
```

- [ ] **Step 7: Run to verify it fails**

Run: `cd example && go test ./agent/ -run TestPrecheck -v`
Expected: FAIL — `undefined: Precheck`.

- [ ] **Step 8: Write `precheck.go`**

```go
// example/agent/precheck.go
package agent

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Check is one prerequisite. Fix is the exact command that resolves it.
type Check struct {
	Name  string
	Probe func() error
	Fix   string
}

// Precheck runs every check and reports ALL failures at once, not just the
// first: a reader with three things missing should learn that in one run
// rather than three.
func Precheck(checks ...Check) error {
	var b strings.Builder
	failed := 0
	for _, c := range checks {
		if err := c.Probe(); err != nil {
			failed++
			fmt.Fprintf(&b, "\n  %s: %v", c.Name, err)
			if c.Fix != "" {
				fmt.Fprintf(&b, "\n      fix: %s", c.Fix)
			}
		}
	}
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%d prerequisite(s) not met — this is setup, not a policy denial:%s", failed, b.String())
}

// DialCheck probes a TCP address. Used for ollama, litellm and the surfaces.
func DialCheck(addr string) func() error {
	return func() error {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}
```

- [ ] **Step 9: Run the whole agent package**

Run: `cd example && go test ./agent/ -v && go vet ./...`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add go.work .gitignore example/
git commit -m "feat(example): module skeleton, transport types, enforcement report"
```

---

### Task 3: The LiteLLM client and the agent loop

**Files:**
- Create: `example/agent/litellm.go`, `example/agent/agent.go`
- Create: `example/agent/agent_test.go`

**Interfaces:**
- Consumes: `Transport`, `Report`, `ToolSpec`, `ToolCall`, `Result` from Task 2.
- Produces:
  - `type LLM struct { BaseURL, Model string; HTTP *http.Client }`
  - `func (l *LLM) Chat(ctx context.Context, msgs []Message, tools []ToolSpec) (Message, error)`
  - `type Message struct { Role, Content, ToolCallID string; ToolCalls []ToolCall }`
  - `func Run(ctx context.Context, l *LLM, t Transport, task string, want []Expectation, out io.Writer) *Report`

- [ ] **Step 1: Write the failing loop test**

```go
// example/agent/agent_test.go
package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeTransport records what it was asked and answers from a script.
type fakeTransport struct {
	results map[string]Result
	seen    []ToolCall
}

func (f *fakeTransport) Tools() []ToolSpec {
	return []ToolSpec{{Name: "read", Description: "read a file",
		Schema: map[string]any{"type": "object", "properties": map[string]any{
			"path": map[string]any{"type": "string"}}}}}
}

func (f *fakeTransport) Call(_ context.Context, c ToolCall) (Result, error) {
	f.seen = append(f.seen, c)
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
	if !contains(string(raw), "exceeds delegation cap CONFIDENTIAL") {
		t.Errorf("the denial reason never reached the model:\n%s", raw)
	}
}

func contains(h, n string) bool { return len(h) >= len(n) && (func() bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
})() }

func TestRun_ProseOnlyTurnIsInconclusive(t *testing.T) {
	srv := litellmStub(t, []string{replyDone})
	defer srv.Close()
	rep := Run(context.Background(), &LLM{BaseURL: srv.URL, Model: "m", HTTP: srv.Client()},
		&fakeTransport{results: map[string]Result{}}, "hello", nil, io.Discard)
	if rep.inconclusive != 1 {
		t.Errorf("inconclusive = %d, want 1", rep.inconclusive)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd example && go test ./agent/ -run TestRun -v`
Expected: FAIL — `undefined: LLM`, `undefined: Run`.

- [ ] **Step 3: Write `litellm.go`**

```go
// example/agent/litellm.go
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
```

- [ ] **Step 4: Write `agent.go`**

```go
// example/agent/agent.go
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

const maxTurns = 6

// Run drives the model until it stops calling tools. It knows nothing about
// which surface it is on -- that is entirely Transport's business, and it is
// why one agent demonstrates three enforcement points.
func Run(ctx context.Context, l *LLM, t Transport, task string, want []Expectation, out io.Writer) *Report {
	rep := NewReport(want)
	msgs := []Message{
		{Role: "system", Content: "You are an agent with tools. Use them to complete the task. " +
			"If a tool call is refused, say so plainly and do not retry it."},
		{Role: "user", Content: task},
	}

	for turn := 0; turn < maxTurns; turn++ {
		reply, err := l.Chat(ctx, msgs, t.Tools())
		if err != nil {
			fmt.Fprintf(out, "  model unreachable: %v\n", err)
			return rep
		}
		if reply.Content != "" {
			fmt.Fprintf(out, "  model> %s\n", reply.Content)
		}
		if len(reply.ToolCalls) == 0 {
			rep.NoToolCall()
			return rep
		}
		msgs = append(msgs, reply)

		for i, call := range reply.ToolCalls {
			res, err := t.Call(ctx, call)
			if err != nil {
				// A transport error is the example being broken, not policy
				// answering. Never record it as a decision.
				fmt.Fprintf(out, "  ERROR  %s: %v\n", call.Name, err)
				return rep
			}
			rep.Record(call, res)

			args, _ := json.Marshal(call.Args)
			if res.Allowed {
				fmt.Fprintf(out, "  ALLOW  %-18s %s\n", call.Name, args)
			} else {
				fmt.Fprintf(out, "  DENY   %-18s %s\n         %s\n", call.Name, args, res.Reason)
			}

			content := res.Output
			if !res.Allowed {
				content = "DENIED by policy: " + res.Reason
			}
			id := ""
			if i < len(reply.RawToolCalls) {
				id = reply.RawToolCalls[i].ID
			}
			msgs = append(msgs, Message{Role: "tool", ToolCallID: id, Content: content})
		}
	}
	return rep
}
```

- [ ] **Step 5: Run to verify the tests pass**

Run: `cd example && go test ./agent/ -v`
Expected: PASS, all tests including Task 2's.

- [ ] **Step 6: Commit**

```bash
git add example/agent
git commit -m "feat(example): LiteLLM client and the surface-agnostic agent loop"
```

---

### Task 4: LiteLLM in compose, behind Envoy

**Files:**
- Create: `deploy/docker/litellm/config.yaml`
- Modify: `deploy/docker/docker-compose.yml`
- Modify: the Envoy config under `deploy/docker/` (add a route to `litellm:4000`)

**Interfaces:**
- Consumes: nothing.
- Produces: a `litellm` service on port 4000 offering models `llama3.2` and `gpt-4o`, reachable directly at its published port and through Envoy at Envoy's published port.

- [ ] **Step 1: Write the LiteLLM config**

```yaml
# deploy/docker/litellm/config.yaml
model_list:
  # Served by the host's Ollama. host.docker.internal is mapped via
  # extra_hosts in docker-compose.yml so this works on Linux too.
  - model_name: llama3.2
    litellm_params:
      model: ollama/llama3.2
      api_base: http://host.docker.internal:11434

  # Declared and DELIBERATELY UNREACHABLE. The examples expect policy to
  # refuse this model before reachability is ever consulted. If it were
  # reachable, an example passing would not prove policy did anything; if it
  # were absent, LiteLLM would 400 and the denial would come from the wrong
  # component. Unreachable-but-declared is the only shape that makes the
  # PDP's answer the reason the call fails.
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_base: http://127.0.0.1:1
      api_key: not-a-real-key

litellm_settings:
  drop_params: true
```

- [ ] **Step 2: Add the compose service**

```yaml
  litellm:
    image: ghcr.io/berriai/litellm:main-latest
    command: ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
    volumes:
      - ./litellm/config.yaml:/etc/litellm/config.yaml:ro
    extra_hosts:
      - "host.docker.internal:host-gateway"
    ports:
      - "4000"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request;urllib.request.urlopen('http://127.0.0.1:4000/health/liveliness')"]
      interval: 5s
      timeout: 3s
      retries: 20
```

- [ ] **Step 3: Route Envoy at it**

Add a cluster `litellm` targeting `litellm:4000` and a route matching prefix
`/chat/completions` to that cluster, in the listener that already carries the
`ext_authz` filter. Do **not** set `failure_mode_allow` — the default is
deny-on-error and the design depends on it.

- [ ] **Step 4: Bring it up and verify both paths**

```bash
docker compose -f deploy/docker/docker-compose.yml up -d litellm --wait
LITELLM="localhost:$(docker compose -f deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"

# direct: the allowed model answers
curl -sS -o /dev/null -w 'direct llama3.2 -> %{http_code}\n' -X POST "http://$LITELLM/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"say hi"}]}'
```

Expected: `direct llama3.2 -> 200`. If it is not 200, Ollama is not running or
the model is not pulled — `ollama pull llama3.2`.

- [ ] **Step 5: Commit**

```bash
git add deploy/docker
git commit -m "feat(example): add litellm to compose, fronted by envoy"
```

---

### Task 5: `example/mcp` — the agent that never learns Stratium exists

**Files:**
- Create: `example/mcp/main.go`, `example/mcp/mcpclient.go`, `example/mcp/README.md`

**Interfaces:**
- Consumes: `agent.Run`, `agent.LLM`, `agent.Transport`, `agent.Precheck`, `agent.DialCheck`.
- Produces: nothing later tasks use.

- [ ] **Step 1: Write the stdio JSON-RPC client**

`mcpclient.go` starts `stratium-pep mcp` with `exec.Command`, writes
newline-delimited JSON-RPC requests to its stdin and reads responses from its
stdout. It implements three calls: `initialize`, `tools/list`, `tools/call`.
`tools/list` maps each entry's `name`, `description` and `inputSchema` onto
`agent.ToolSpec`. `tools/call` returns `agent.Result{Allowed:true, Output:…}`
on a result, and `agent.Result{Allowed:false, Reason: err.Message}` on a
JSON-RPC error — a policy denial arrives as an error, and only the surface
knows to read it as a decision rather than a fault.

- [ ] **Step 2: Write `main.go`**

It prechecks Ollama, LiteLLM, the PDP port and `npx`; registers a
`/tmp/example-data/secret-` label rule at `nato SECRET` and caps the agent at
`CONFIDENTIAL`; seeds `/tmp/example-data/notes.txt` and
`/tmp/example-data/secret-x/plans.txt`; runs `session-start`; then calls
`agent.Run` with:

```go
task := "Read /tmp/example-data/notes.txt and tell me what it says. " +
    "Then read /tmp/example-data/secret-x/plans.txt and tell me what that says."

want := []agent.Expectation{
    {Tool: "read_text_file", ArgContains: "notes.txt", Want: agent.Allow},
    {Tool: "read_text_file", ArgContains: "secret-x",  Want: agent.Deny},
}
```

- [ ] **Step 3: Run it**

Run: `cd example && go run ./mcp`
Expected: an `ALLOW` for `notes.txt`, a `DENY` for `secret-x/plans.txt` whose
reason contains `exceeds delegation cap`, and `enforcement: 2/2 as expected`.

- [ ] **Step 4: Write the README**

It must state the substitution test explicitly: replace `stratium-pep mcp` with
`npx -y @modelcontextprotocol/server-filesystem /tmp/example-data` in
`main.go`, re-run, and observe both reads succeed. The agent source does not
change. That is the integration story.

- [ ] **Step 5: Commit**

```bash
git add example/mcp
git commit -m "feat(example): mcp — an agent that speaks plain MCP through the PEP"
```

---

### Task 6: `example/proxy` — the service never heard the request

**Files:**
- Create: `example/proxy/main.go`, `example/proxy/README.md`
- Modify: `example/go.mod` (adds `google.golang.org/grpc`, `stratium`)

**Interfaces:**
- Consumes: `stratium/pkg/grpctarget` (Task 1), the agent package.
- Produces: nothing later tasks use.

- [ ] **Step 1: Wire the module dependency**

```bash
cd example
go mod edit -require=stratium@v0.0.0
go mod tidy   # go.work resolves stratium to ../services
```

- [ ] **Step 2: Write `main.go`**

Two clients: one to the **proxy** for the tools, one **direct to
`grpc-target`** for `CallCount`.

```go
viaProxy := grpctarget.NewTargetServiceClient(proxyConn)
direct   := grpctarget.NewTargetServiceClient(targetConn) // NOT through the proxy

// The token rides in gRPC metadata; this surface has no session file.
ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
```

Tools offered: `fetch` and `purge`, each taking `{"message": string}`. `Call`
maps a gRPC `PermissionDenied` to `Result{Allowed:false, Reason: st.Message()}`
and any other error to a transport error.

```go
want := []agent.Expectation{
    {Tool: "fetch", Want: agent.Allow},
    {Tool: "purge", Want: agent.Deny},
}
```

- [ ] **Step 3: Add the CallCount proof**

Read the count **before** and **after** the run, over the direct connection,
and print the delta:

```go
fmt.Printf("\n  grpc-target received %d call(s) during this run.\n", after-before)
fmt.Println("  Read directly from the service, NOT through the proxy: a proxy that")
fmt.Println("  forwards and then errors has already leaked the request, and a caller")
fmt.Println("  reading only its own response cannot tell that apart from a refusal.")
```

- [ ] **Step 4: Run it**

Run: `cd example && go run ./proxy`
Expected: `ALLOW fetch`, `DENY purge` with `not in delegation approved_tools`,
`enforcement: 2/2`, and a received-call delta of **1** — the `Fetch` only.

- [ ] **Step 5: Write the README, then commit**

```bash
git add example/proxy example/go.mod example/go.sum
git commit -m "feat(example): proxy — and proof the denied call never arrived"
```

---

### Task 7: `example/extauthz` — the agent's own cognition, policed

**Files:**
- Create: `example/extauthz/main.go`, `example/extauthz/README.md`

**Interfaces:**
- Consumes: the agent package.
- Produces: nothing later tasks use.

- [ ] **Step 1: Seed one catalog row per model name**

So that `llama3.2` and `gpt-4o` are nameable tools a delegation either holds or
does not. `session-start` requests only `llama3.2`.

- [ ] **Step 2: Write `main.go`**

One tool, `ask_model`, taking `{"model": string, "prompt": string}`. Its `Call`
issues an HTTP POST to **Envoy's** published port with
`Authorization: Bearer <token>`, and maps `403` to
`Result{Allowed:false, Reason: <body>}`.

**The `LLM` the agent reasons with points DIRECTLY at LiteLLM, not at Envoy.**
Add this comment verbatim above it:

```go
// The agent's own reasoning goes direct to LiteLLM, bypassing Envoy on
// purpose. Only the ask_model TOOL takes the policed path. Route both through
// Envoy and this example deadlocks the moment the deny fires: the agent needs
// a model call in order to tell you its model call was refused.
```

```go
task := "Ask the llama3.2 model what 2+2 is. Then ask the gpt-4o model the same thing. " +
    "Report what each said, or why you could not."

want := []agent.Expectation{
    {Tool: "ask_model", ArgContains: "llama3.2", Want: agent.Allow},
    {Tool: "ask_model", ArgContains: "gpt-4o",   Want: agent.Deny},
}
```

- [ ] **Step 3: Assert the denial came from policy, not from unreachability**

`gpt-4o` is deliberately unreachable, so a `502` would also look like failure.
The example must distinguish them:

```go
if resp.StatusCode == http.StatusBadGateway {
    return agent.Result{}, fmt.Errorf(
        "gpt-4o returned 502 — that is LiteLLM failing to reach the upstream, NOT a policy denial. " +
            "Envoy let the request through, which means ext_authz did not refuse it. " +
            "Check the delegation does not hold the gpt-4o tool")
}
```

- [ ] **Step 4: Run it**

Run: `cd example && go run ./extauthz`
Expected: `ALLOW ask_model {"model":"llama3.2"…}`, `DENY ask_model
{"model":"gpt-4o"…}` with a PDP reason, `enforcement: 2/2`, and the model
narrating that it could not reach the second one.

- [ ] **Step 5: Write the README, then commit**

```bash
git add example/extauthz
git commit -m "feat(example): extauthz — policing which model an agent may call"
```

---

### Task 8: `example/hook` and the top-level README

**Files:**
- Create: `example/hook/README.md`, `example/hook/settings.json`, `example/hook/transcript.md`
- Create: `example/README.md`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

- [ ] **Step 1: Write `settings.json`**

The two-hook block from `docs/pep/hook.md`, with an absolute-path placeholder
and a comment in the README explaining why a bare name is unsafe.

- [ ] **Step 2: Capture a real transcript**

Install the hooks, launch Claude Code through `deploy/stratium run claude`, ask
it to read a labelled path, and paste the actual exchange — including the
refusal and the model's reaction — into `transcript.md`. It must be a real
capture, not a reconstruction.

- [ ] **Step 3: Write `example/hook/README.md`**

Why this directory has no program: `hook` is a configuration contract for a
harness that already exists, and a hand-written client implementing it would
demonstrate the contract rather than the product, and would drift from what
Claude Code actually sends.

- [ ] **Step 4: Write `example/README.md`**

A table of the four directories and what each proves; the shared preconditions;
and the one sentence a reader most needs — **one `session-start` issues one
delegation, and the same token is carried three different ways**: as a session
file for `mcp`, as gRPC metadata for `proxy`, as an HTTP header for `extauthz`.

- [ ] **Step 5: Verify everything still builds, then commit**

Run: `cd example && go build ./... && go vet ./... && go test ./agent/`
Run: `cd services && go test ./...`

```bash
git add example/hook example/README.md
git commit -m "docs(example): hook configuration, transcript, and the suite README"
```

---

## Self-Review

**Spec coverage.** Every spec section maps to a task: layout → 2 and 8; the
shared agent → 2 and 3; the three transports → 5, 6, 7; LiteLLM and Envoy → 4;
credentials → 2 (gitignore, session path) and each transport task; preconditions
→ 2 (`Precheck`) applied in 5–7; testing → 2 and 3; `example/hook` → 8.

**One task the spec did not anticipate.** Task 1 exists because
`grpctarget` lives under `services/internal/`, and Go forbids importing an
`internal` package from a different module. `example/` must be its own module —
the repo root has no `go.mod` — so without the move, Task 6 cannot compile. The
spec assumed the stubs were reachable.

**Placeholder scan.** No TBD/TODO. Tasks 5–8 describe some files in prose rather
than full listings — `mcpclient.go`, the READMEs, the Envoy route — but each
names the exact calls, the exact mapping, and the exact expectations, and the
code they must integrate with is given in full. The verbatim comment in Task 7
Step 2 is required text, not an illustration.

**Type consistency.** `Result{Allowed, Reason, Output}`, `ToolCall{Name, Args}`
and `Expectation{Tool, ArgContains, Want}` are spelled identically in Tasks 2, 3,
5, 6 and 7. `Run(ctx, *LLM, Transport, string, []Expectation, io.Writer) *Report`
has one signature, defined in Task 3 and called unchanged in 5–7. `NewReport`,
`Record`, `NoToolCall`, `Print` and `ExitCode` match between the tests in Task 2
and the implementation in the same task.

**One rough edge left deliberately.** `Report.unmetOrWrong` is a thin alias for
`mismatches` used only by `Print`'s arithmetic. It exists to keep the count and
the detail lines derived from one source; if a reviewer prefers, collapse them —
but do not let the printed tally and the printed mismatches be computed
separately, or they will disagree.
