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

// The systemic failure ReasonContains exists to catch: a Deny for the WRONG
// reason must fail just as loudly as an unexpected Allow. Without this, a
// spawn failure, a missing file, or a tool-not-held refusal would all satisfy
// a bare Want: Deny, even though the example's whole point is that this
// specific call was refused for this specific reason.
func TestReport_DenyWithWrongReasonFails(t *testing.T) {
	r := NewReport([]Expectation{{Tool: "purge", Want: Deny, ReasonContains: "not in delegation approved_tools"}})
	r.Record(ToolCall{Name: "purge", Args: map[string]any{"message": "x"}},
		Result{Allowed: false, Reason: "some unrelated denial"})

	if got := r.ExitCode(); got == 0 {
		t.Fatal("ExitCode() = 0 for a DENY that happened for the wrong reason; must be non-zero")
	}
	var b bytes.Buffer
	r.Print(&b)
	if !strings.Contains(b.String(), "not in delegation approved_tools") || !strings.Contains(b.String(), "some unrelated denial") {
		t.Errorf("Print() does not name both the expected and actual reason:\n%s", b.String())
	}
}

// Confirmed live: a model that retries an already-denied call can be served
// the second refusal from stratium-pep's own decision cache, which answers
// with a generic "cached decision ... does not retain the original policy
// reason text" message rather than repeating the real one. ReasonContains
// must not flag that repeat as a MISMATCH -- only the FIRST observation that
// proves the expectation is reason-checked; the run still exits 0 as long as
// the classification-cap reason showed up at least once.
func TestReport_CachedRepeatDenialIsNotReasonChecked(t *testing.T) {
	r := NewReport([]Expectation{{Tool: "read_text_file", Want: Deny, ReasonContains: "exceeds delegation cap"}})
	r.Record(ToolCall{Name: "read_text_file", Args: map[string]any{"path": "/d/secret-x/a"}},
		Result{Allowed: false, Reason: "resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"})
	r.Record(ToolCall{Name: "read_text_file", Args: map[string]any{"path": "/d/secret-x/a"}},
		Result{Allowed: false, Reason: "stratium-pep: cached decision: this exact request was denied (served from cache, without contacting the PDP; the cache does not retain the original policy reason text)"})

	if got := r.ExitCode(); got != 0 {
		var b bytes.Buffer
		r.Print(&b)
		t.Fatalf("ExitCode() = %d for a cached repeat of an already-proven deny; want 0:\n%s", got, b.String())
	}
}
