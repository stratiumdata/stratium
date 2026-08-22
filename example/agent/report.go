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

// verb is the past-tense form used for what a call actually got ("was
// ALLOWED"/"was DENIED"), distinct from String()'s noun form used for what
// was expected ("expected ALLOW"/"expected DENY"). Two separate renderings
// because the mismatch line reads as English, not as two copies of the same
// enum value.
func (o Outcome) verb() string {
	if o == Allow {
		return "ALLOWED"
	}
	return "DENIED"
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
				o.call.Name, o.matched.Want, got.verb()))
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
	fmt.Fprintf(w, "\nenforcement: %d/%d as expected\n", len(r.want)-len(bad), len(r.want))
	for _, line := range bad {
		fmt.Fprintln(w, line)
	}
	if r.inconclusive > 0 {
		fmt.Fprintf(w, "  %d inconclusive turn(s) — the model answered in prose instead of calling a tool.\n", r.inconclusive)
		fmt.Fprintf(w, "  That is a model limitation, not an enforcement failure. A larger model calls tools more reliably.\n")
	}
}

func (r *Report) ExitCode() int {
	if len(r.mismatches()) > 0 {
		return 1
	}
	return 0
}
