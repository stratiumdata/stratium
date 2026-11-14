package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

// probeCall records one (tool, tier) pair Clamp asked allows about. Tests
// use the log to pin exactly what was probed, not just what came back —
// that is what catches a walk-down that skips a tier, or one that keeps
// probing after an error instead of stopping.
type probeCall struct {
	tool string
	tier models.ActionTier
}

// clampFixture is a scriptable allows callback: fixed answers for tier and
// tool probes, plus a log of every call it received. Tiers and tools not
// present in the maps deny by default (Go's zero value for bool is false),
// which matches the fail-closed posture Clamp itself must have.
type clampFixture struct {
	tiers    map[models.ActionTier]bool
	tierErrs map[models.ActionTier]error
	tools    map[string]bool
	toolErrs map[string]error

	calls []probeCall
}

func (f *clampFixture) allows(tool string, tier models.ActionTier) (bool, error) {
	f.calls = append(f.calls, probeCall{tool: tool, tier: tier})
	if tool == "" {
		if err, ok := f.tierErrs[tier]; ok {
			return false, err
		}
		return f.tiers[tier], nil
	}
	if err, ok := f.toolErrs[tool]; ok {
		return false, err
	}
	return f.tools[tool], nil
}

func equalTools(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func equalCalls(a, b []probeCall) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

// Every dimension permitted: the request survives unchanged, Removed empty.
func TestClamp_EverythingPermittedYieldsRequestUnchanged(t *testing.T) {
	f := &clampFixture{
		tiers: map[models.ActionTier]bool{models.ActionTierDestructive: true},
		tools: map[string]bool{"Read": true, "Bash": true},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive, Tools: []string{"Read", "Bash"}}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if got.MaxActionTier != models.ActionTierDestructive {
		t.Errorf("MaxActionTier = %v, want unchanged %v", got.MaxActionTier, models.ActionTierDestructive)
	}
	if !equalTools(got.Tools, req.Tools) {
		t.Errorf("Tools = %v, want unchanged %v", got.Tools, req.Tools)
	}
	if len(got.Removed) != 0 {
		t.Errorf("Removed = %+v, want empty", got.Removed)
	}
}

// A denied tool is dropped from the grant and recorded, without disturbing
// a tool that survived or a tier that was already permitted.
func TestClamp_DeniedToolDroppedAndRecorded(t *testing.T) {
	f := &clampFixture{
		tiers: map[models.ActionTier]bool{models.ActionTierReadOnly: true},
		tools: map[string]bool{"Read": true, "Bash": false},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierReadOnly, Tools: []string{"Read", "Bash"}}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if !equalTools(got.Tools, []string{"Read"}) {
		t.Fatalf("Tools = %v, want [Read] (Bash denied)", got.Tools)
	}
	if len(got.Removed) != 1 {
		t.Fatalf("Removed = %+v, want exactly one entry", got.Removed)
	}
	if r := got.Removed[0]; r.Dimension != "tool" || r.Value != "Bash" || r.Reason != ClampReasonDenied {
		t.Fatalf("Removed[0] = %+v, want {Dimension:tool Value:Bash Reason:denied}", r)
	}
}

// A principal permitted INTERNAL_MODIFY who requests DESTRUCTIVE gets
// INTERNAL_MODIFY, not REASONING — dropping to zero on any denial would
// make the gate technically correct and practically useless. The call log
// pins that the walk steps one tier at a time (DESTRUCTIVE, EXTERNAL_COMMS,
// INTERNAL_MODIFY) rather than skipping straight to a lower one: a mutant
// that jumps two tiers at a time would land on the same grant here by
// coincidence (EXTERNAL_COMMS is denied either way), so only the call
// sequence — not the final answer — catches it.
func TestClamp_TooHighTierWalksDownOneStepAtATime(t *testing.T) {
	f := &clampFixture{
		tiers: map[models.ActionTier]bool{
			models.ActionTierDestructive:    false,
			models.ActionTierExternalComms:  false,
			models.ActionTierInternalModify: true,
		},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if got.MaxActionTier != models.ActionTierInternalModify {
		t.Fatalf("MaxActionTier = %v, want INTERNAL_MODIFY (walked down from DESTRUCTIVE)", got.MaxActionTier)
	}
	if len(got.Removed) != 1 || got.Removed[0].Dimension != "tier" || got.Removed[0].Reason != ClampReasonDenied {
		t.Fatalf("Removed = %+v, want exactly one {tier denied} entry", got.Removed)
	}

	want := []probeCall{
		{tool: "", tier: models.ActionTierDestructive},
		{tool: "", tier: models.ActionTierExternalComms},
		{tool: "", tier: models.ActionTierInternalModify},
	}
	if !equalCalls(f.calls, want) {
		t.Fatalf("probe calls = %+v, want %+v (one tier at a time, no skipping)", f.calls, want)
	}
}

// A probe error on the tier dimension drops straight to REASONING and
// records why — and stops the walk rather than trying a lower, easier
// question: unanswerable is not license to go ask something else.
func TestClamp_ProbeErrorDropsTierAndRecordsReason(t *testing.T) {
	boom := errors.New("engine unavailable")
	f := &clampFixture{tierErrs: map[models.ActionTier]error{models.ActionTierDestructive: boom}}
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if got.MaxActionTier != models.ActionTierReasoning {
		t.Fatalf("MaxActionTier = %v, want REASONING (a probe error must not grant)", got.MaxActionTier)
	}
	if len(got.Removed) != 1 {
		t.Fatalf("Removed = %+v, want exactly one entry", got.Removed)
	}
	if r := got.Removed[0]; r.Dimension != "tier" || r.Reason != ClampReasonProbeError || r.Detail != boom.Error() {
		t.Fatalf("Removed[0] = %+v, want {Dimension:tier Reason:probe-error Detail:%q}", r, boom.Error())
	}
	if len(f.calls) != 1 {
		t.Fatalf("probe calls = %+v, want exactly one: an error must stop the walk, not send it "+
			"hunting for an easier tier", f.calls)
	}
}

// A probe error on a tool is dropped and recorded the same way, and a
// genuine denial and a probe error must be distinguishable in Removed —
// they need different operator responses (an outage to fix vs. a decision
// to challenge or accept).
func TestClamp_ProbeErrorAndDenialAreDistinguishableInRemoved(t *testing.T) {
	boom := errors.New("timeout")
	f := &clampFixture{
		tiers:    map[models.ActionTier]bool{models.ActionTierReadOnly: true},
		tools:    map[string]bool{"Read": false},
		toolErrs: map[string]error{"Bash": boom},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierReadOnly, Tools: []string{"Read", "Bash"}}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if len(got.Removed) != 2 {
		t.Fatalf("Removed = %+v, want exactly two entries", got.Removed)
	}
	byValue := make(map[string]ClampRemoval, 2)
	for _, r := range got.Removed {
		byValue[r.Value] = r
	}
	read, bash := byValue["Read"], byValue["Bash"]
	if read.Dimension != "tool" || read.Reason != ClampReasonDenied {
		t.Errorf("Read removal = %+v, want {Dimension:tool Reason:denied}", read)
	}
	if bash.Dimension != "tool" || bash.Reason != ClampReasonProbeError || bash.Detail != boom.Error() {
		t.Errorf("Bash removal = %+v, want {Dimension:tool Reason:probe-error Detail:%q}", bash, boom.Error())
	}
	if read.Reason == bash.Reason {
		t.Fatal("a genuine denial and a probe error must not carry the same Reason")
	}
}

// A request permitted at nothing yields REASONING and an empty tool list
// rather than an error: Y4 is clamp-silently-and-record, not fail the
// creation.
func TestClamp_NothingPermittedYieldsReasoningAndEmptyToolsNotError(t *testing.T) {
	f := &clampFixture{} // every tier and tool denies by default
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive, Tools: []string{"Read", "Bash"}}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp() error = %v, want nil: a fully-denied request is narrowed, not rejected", err)
	}
	if got.MaxActionTier != models.ActionTierReasoning {
		t.Fatalf("MaxActionTier = %v, want REASONING", got.MaxActionTier)
	}
	if len(got.Tools) != 0 {
		t.Fatalf("Tools = %v, want empty", got.Tools)
	}
	if len(got.Removed) != 3 { // tier, Read, Bash
		t.Fatalf("Removed = %+v, want 3 entries (tier, Read, Bash)", got.Removed)
	}
}

// REASONING is the walk's unconditional floor and must never itself be
// probed: models.ActionTier's zero value is deliberately the
// least-privileged member, so requesting it needs no answer from allows at
// all, and a request already at the floor removes nothing.
func TestClamp_RequestingReasoningNeverProbesTheTierDimension(t *testing.T) {
	f := &clampFixture{}
	req := RequestedScope{MaxActionTier: models.ActionTierReasoning}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	if got.MaxActionTier != models.ActionTierReasoning {
		t.Fatalf("MaxActionTier = %v, want REASONING", got.MaxActionTier)
	}
	if len(got.Removed) != 0 {
		t.Fatalf("Removed = %+v, want empty: REASONING is reached, never denied", got.Removed)
	}
	if len(f.calls) != 0 {
		t.Fatalf("probe calls = %+v, want none: REASONING must never be probed", f.calls)
	}
}

// Tool probes ask about the zero-value tier, mirroring GrantProbe.Tool's own
// "empty when probing the tier ceiling" convention: the tool and tier
// dimensions are orthogonal probes, and this pins the exact contract so
// Task 3's allows implementation has something concrete to code against.
func TestClamp_ToolProbesUseTheZeroValueTier(t *testing.T) {
	f := &clampFixture{tools: map[string]bool{"Read": true}}
	req := RequestedScope{Tools: []string{"Read"}} // MaxActionTier left at its zero value: REASONING

	if _, err := Clamp(context.Background(), req, f.allows); err != nil {
		t.Fatalf("Clamp: %v", err)
	}
	want := probeCall{tool: "Read", tier: models.ActionTierReasoning}
	if len(f.calls) != 1 || f.calls[0] != want {
		t.Fatalf("probe calls = %+v, want exactly [%+v]", f.calls, want)
	}
}

// Clamping an already-clamped scope changes nothing: re-feeding a granted
// scope back in as a request must reproduce it exactly, with an empty
// Removed the second time. If this does not hold, the granted scope is not
// a fixed point and its meaning would depend on how many times it passed
// through the clamp.
func TestClamp_Idempotent(t *testing.T) {
	f := &clampFixture{
		tiers: map[models.ActionTier]bool{
			models.ActionTierDestructive:    false,
			models.ActionTierExternalComms:  false,
			models.ActionTierInternalModify: true,
		},
		tools: map[string]bool{"Read": true, "Write": true, "Bash": false},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive, Tools: []string{"Read", "Write", "Bash"}}

	first, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("first Clamp: %v", err)
	}
	if len(first.Removed) == 0 {
		t.Fatal("first clamp removed nothing, so this test cannot prove idempotence means anything")
	}

	second, err := Clamp(context.Background(),
		RequestedScope{MaxActionTier: first.MaxActionTier, Tools: first.Tools}, f.allows)
	if err != nil {
		t.Fatalf("second Clamp: %v", err)
	}

	if second.MaxActionTier != first.MaxActionTier {
		t.Errorf("MaxActionTier changed on re-clamp: %v -> %v", first.MaxActionTier, second.MaxActionTier)
	}
	if !equalTools(second.Tools, first.Tools) {
		t.Errorf("Tools changed on re-clamp: %v -> %v", first.Tools, second.Tools)
	}
	if len(second.Removed) != 0 {
		t.Fatalf("re-clamping an already-clamped scope removed more: %+v", second.Removed)
	}
}

// A caller whose context is already cancelled gets an error immediately,
// without paying for a single probe call.
func TestClamp_CancelledContextErrorsWithoutProbing(t *testing.T) {
	f := &clampFixture{tiers: map[models.ActionTier]bool{models.ActionTierReadOnly: true}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Clamp(ctx, RequestedScope{MaxActionTier: models.ActionTierReadOnly}, f.allows)
	if err == nil {
		t.Fatal("Clamp() error = nil, want non-nil for an already-cancelled context")
	}
	if len(f.calls) != 0 {
		t.Fatalf("probe calls = %+v, want none: a cancelled context must be checked before any probing", f.calls)
	}
}
