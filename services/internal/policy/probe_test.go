// This file lives in the external policy_test package, not the internal
// policy package, because it needs the real Cedar engine
// (internal/policy/cedar) to compile policies for Probe to evaluate, and
// cedar imports policy. An internal test file (package policy) importing
// cedar would close that into an import cycle — the same reasoning
// engine_test.go documents for why its fakeEngine lives out here too.
package policy_test

import (
	"context"
	"errors"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/policy/cedar"
)

// prepareCedar compiles policies with the real Cedar engine — the same one
// Task 4 wires into production — rather than a fake, so Probe's tests prove
// it works against a real engine's real match-and-error semantics.
func prepareCedar(t *testing.T, policies []policy.StoredPolicy) policy.CompiledPolicySet {
	t.Helper()
	set, err := cedar.New().Prepare(context.Background(), policies)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return set
}

func TestProbe_PermitForPrincipalAllows(t *testing.T) {
	set := prepareCedar(t, []policy.StoredPolicy{
		{ID: "p1", Name: "alice-can-bash", Text: `permit(principal == User::"alice", action == Action::"Bash", resource);`},
	})

	got, err := policy.Probe(context.Background(), set, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "Bash",
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !got {
		t.Fatal("Probe() = false, want true: a permit matching this principal must allow")
	}
}

func TestProbe_ForbidDenies(t *testing.T) {
	set := prepareCedar(t, []policy.StoredPolicy{
		{ID: "p1", Name: "deny-all", Text: `forbid(principal, action, resource);`},
	})

	got, err := policy.Probe(context.Background(), set, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "Bash",
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got {
		t.Fatal("Probe() = true, want false: a forbid must deny")
	}
}

func TestProbe_NoMatchingPolicyDeniesByDefault(t *testing.T) {
	set := prepareCedar(t, []policy.StoredPolicy{
		{ID: "p1", Name: "only-bob", Text: `permit(principal == User::"bob", action, resource);`},
	})

	got, err := policy.Probe(context.Background(), set, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "Bash",
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got {
		t.Fatal("Probe() = true, want false: no policy matched alice, default-deny must apply")
	}
}

// TestProbe_DenyOverridesAnAllowWhenBothMatch pins that Probe reuses
// authz.FoldVerdicts's deny-overrides fold rather than a simpler "any allow
// wins" combiner. With both a matching permit and a matching forbid, the
// correct answer is deny; a hand-rolled "any allow wins" rule would answer
// true instead, since it would find the permit and stop there. Neither of
// the single-policy tests above can catch that substitution — this one
// exists specifically so it can't slip in unnoticed.
func TestProbe_DenyOverridesAnAllowWhenBothMatch(t *testing.T) {
	set := prepareCedar(t, []policy.StoredPolicy{
		{ID: "permit-1", Name: "alice-can-bash", Text: `permit(principal == User::"alice", action, resource);`},
		{ID: "forbid-1", Name: "block-everyone", Text: `forbid(principal, action, resource);`},
	})

	got, err := policy.Probe(context.Background(), set, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "Bash",
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got {
		t.Fatal("Probe() = true with both a matching permit and a matching forbid, want false (deny-overrides)")
	}
}

// errSet is a policy.CompiledPolicySet stub that always errors. It stands in
// for a real engine's Evaluate failing outright — something today's Cedar
// engine never does (compiledSet.Evaluate in cedar/evaluate.go always
// returns a nil error), so a fake is the only way to reach this path.
type errSet struct{ err error }

func (e errSet) Evaluate(context.Context, policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	return nil, e.err
}

func TestProbe_EngineErrorDeniesAndReturnsError(t *testing.T) {
	wantErr := errors.New("boom: engine unavailable")

	got, err := policy.Probe(context.Background(), errSet{err: wantErr}, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "Bash",
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Probe() err = %v, want it to wrap %v: an engine error must be surfaced, not swallowed", err, wantErr)
	}
	if got {
		t.Fatal("Probe() = true on an engine error, want false: unanswerable is not a grant")
	}
}

// TestProbe_ResourceScopedPolicyDoesNotAllowResourcelessProbe pins the
// under-granting behaviour spec §3.8 G6 (amended 2026-08-10) accepts
// deliberately: a probe carries no resource, because at delegation-creation
// time there is none. A policy conditioned on the resource — here, alice may
// act only on a resource classified "hr" — therefore does not match a
// resourceless probe, and Probe must report deny, not allow, even though
// alice plainly holds this authority at runtime for the right resource.
//
// This is NOT a bug. Do not "fix" it by giving Probe a wildcard or
// any-resource match: that reopens exactly the ABAC enumeration problem G6
// exists to avoid (see the spec) — a resource-conditional grant would then
// have to be checked against every possible resource to know whether it
// clamps, which has no general solution across policy engines. The design
// response is not to widen the probe; it is that the clamp built on Probe
// only ever asks about resource-INDEPENDENT dimensions (the tier ceiling and
// the tool set), and leaves resource scope to the runtime principal leg,
// which has the concrete resource and evaluates every action anyway.
func TestProbe_ResourceScopedPolicyDoesNotAllowResourcelessProbe(t *testing.T) {
	set := prepareCedar(t, []policy.StoredPolicy{
		{
			ID:   "p1",
			Name: "alice-can-act-on-hr-resources",
			Text: `permit(principal == User::"alice", action, resource) when { resource.classification == "hr" };`,
		},
	})

	got, err := policy.Probe(context.Background(), set, policy.GrantProbe{
		Principal: authz.Principal{Subject: "alice"},
		Tool:      "read",
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got {
		t.Fatal("Probe() = true for a resource-scoped policy against a resourceless probe, want false " +
			"(deliberate under-granting — see spec §3.8 G6 — do not turn this into a wildcard match)")
	}
}
