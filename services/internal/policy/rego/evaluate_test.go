package rego

import (
	"context"
	"fmt"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
)

func prepare(t *testing.T, policies []policy.StoredPolicy) policy.CompiledPolicySet {
	t.Helper()
	set, err := New().Prepare(context.Background(), policies)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return set
}

// Permit-yields-allow, forbid-yields-deny (AllowAll/DenyAll), and the
// Source/PolicyID provenance on the resulting verdict are checked by
// policytest.EngineContract, run against every engine including this one —
// duplicating them here would just be the same assertion twice under a
// different name (see cedar/evaluate_test.go's identical note).

// TestEvaluate_AgentTrustTierReadableFromInputDrivesDeny stands in for spec
// rule Y3, "deny Unverified agents on financial tools" — simplified to just
// the trust-tier condition, the same simplification cedar's own equivalent
// test makes, since what's under test here is input visibility, not resource
// classification.
func TestEvaluate_AgentTrustTierReadableFromInputDrivesDeny(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "block-unverified-agents", Text: `package stratium.policy

deny if {
	input.agent.trust_tier == "UNVERIFIED"
}`},
	})

	t.Run("unverified agent is denied", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Agent: authz.AgentInfo{TrustTier: models.TrustTierUnverified},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})

	t.Run("certified agent is not matched by the rule", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Agent: authz.AgentInfo{TrustTier: models.TrustTierCertified},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0 (rule must actually read the tier, not always fire): %+v", len(verdicts), verdicts)
		}
	})
}

// TestEvaluate_ClassificationCapReadableFromInputDrivesDeny mirrors
// cedar's TestEvaluate_ClassificationCapReadableFromContextDrivesForbid,
// proving delegation.classification_caps reads through with the same key
// name and the same map-indexing shape in Rego as it does in Cedar.
func TestEvaluate_ClassificationCapReadableFromInputDrivesDeny(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "block-restricted-pii", Text: `package stratium.policy

deny if {
	input.delegation.classification_caps["pii"] == "restricted"
}`},
	})

	t.Run("restricted cap is denied", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Delegation: policy.DelegationContext{ClassificationCaps: map[string]string{"pii": "restricted"}},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})

	t.Run("unrestricted cap is not matched by the rule", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Delegation: policy.DelegationContext{ClassificationCaps: map[string]string{"pii": "none"}},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("absent caps map does not error (nil-safety of stringMapOrEmpty)", func(t *testing.T) {
		// ClassificationCaps left nil: without stringMapOrEmpty's
		// normalization this would reach Rego as `null`, and indexing null
		// with ["pii"] is undefined rather than false — this subtest exists
		// so that difference has somewhere to fail if it regresses.
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})
}

// TestEvaluate_DerivedTierSupportsOrdinalComparison is the property that
// justifies mapping derived_tier as a JSON number rather than its String()
// form (see the package doc): a tier-ceiling policy needs a real >=
// comparison, which only works if the mapped value is numeric. Mirrors
// cedar's TestEvaluate_DerivedTierReadableFromContextDrivesForbid, including
// its two-policy shape (a tier cap alongside a base allow-all) so the
// "probe below the cap" subtest has something to positively assert instead
// of only asserting the cap's absence.
func TestEvaluate_DerivedTierSupportsOrdinalComparison(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{
			ID:   "cap",
			Name: "deny-at-or-above-destructive",
			Text: fmt.Sprintf(`package stratium.policy

deny if {
	input.derived_tier >= %d
}`, int(models.ActionTierDestructive)),
		},
		{ID: "base", Name: "allow-all", Text: `package stratium.policy

allow := true`},
	})

	effectsByID := func(verdicts []authz.PolicyVerdict) map[string]authz.Effect {
		m := make(map[string]authz.Effect, len(verdicts))
		for _, v := range verdicts {
			m[v.PolicyID] = v.Effect
		}
		return m
	}

	t.Run("probe at the capped tier is denied", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			DerivedTier: models.ActionTierDestructive,
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		effect, capFired := effectsByID(verdicts)["cap"]
		if !capFired || effect != authz.EffectDeny {
			t.Fatalf("got %+v, want the cap policy to fire and deny a probe at the capped tier", verdicts)
		}
	})

	t.Run("probe below the capped tier is allowed", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			DerivedTier: models.ActionTierInternalModify,
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		byID := effectsByID(verdicts)
		if _, capFired := byID["cap"]; capFired {
			t.Fatalf("got %+v, want the cap policy not to match below the capped tier "+
				"(it must actually read the tier numerically, not always fire)", verdicts)
		}
		if byID["base"] != authz.EffectAllow {
			t.Fatalf("got %+v, want the base policy to allow a probe below the capped tier", verdicts)
		}
	})
}

// TestEvaluate_PrincipalActionResourceReadableFromInput is the positive
// control for the three input fields that have no Cedar naming to mirror
// (Cedar exposes principal/action/resource through its entity and scope
// system, not as context attributes — see the package doc). Each subtest
// changes exactly one field away from the matching value, proving the rule
// actually reads all three rather than firing regardless of them.
func TestEvaluate_PrincipalActionResourceReadableFromInput(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "bob-bash-restricted", Text: `package stratium.policy

allow if {
	input.principal.subject == "bob"
	input.action.tool == "Bash"
	input.resource.classification == "restricted"
}`},
	})

	matching := policy.EvaluationInput{
		Principal: authz.Principal{Subject: "bob"},
		Action:    authz.Action{Tool: "Bash"},
		Resource:  map[string]string{"classification": "restricted"},
	}

	t.Run("all three fields match", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), matching)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly one EffectAllow verdict", verdicts)
		}
	})

	t.Run("wrong subject does not match", func(t *testing.T) {
		in := matching
		in.Principal = authz.Principal{Subject: "alice"}
		verdicts, err := set.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("wrong tool does not match", func(t *testing.T) {
		in := matching
		in.Action = authz.Action{Tool: "Read"}
		verdicts, err := set.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("wrong resource classification does not match", func(t *testing.T) {
		in := matching
		in.Resource = map[string]string{"classification": "public"}
		verdicts, err := set.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})
}

// TestEvaluate_NeitherRuleDefinedYieldsNoVerdict is required by the task
// brief directly. The fixture defines a real, matching rule that is neither
// allow nor deny — not merely an empty package — so a decision function that
// (incorrectly) treated "the compiled document is non-empty" as a match,
// rather than checking specifically for the allow/deny keys, would fail
// this test where an empty-package fixture could not have caught it.
func TestEvaluate_NeitherRuleDefinedYieldsNoVerdict(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "unrelated-helper-rule", Text: `package stratium.policy

matched_something if {
	true
}`},
	})

	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 0 {
		t.Fatalf("got %d verdicts, want 0 (a policy defining neither allow nor deny must not match): %+v", len(verdicts), verdicts)
	}
}

// TestEvaluate_BothAllowAndDenyTrueYieldsDeny pins the one exception the
// task brief grants to "no engine implements combining": a single policy
// whose own allow and deny rules are both true resolves to deny. This is
// mutation target (c) from the task brief — an engine that resolved this to
// allow instead would pass every other test in this package and still be
// wrong exactly here.
func TestEvaluate_BothAllowAndDenyTrueYieldsDeny(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "self-contradictory", Text: `package stratium.policy

allow := true
deny := true`},
	})

	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want exactly 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Fatalf("Effect = %v, want EffectDeny (a policy asserting both allow and deny must resolve to deny)", verdicts[0].Effect)
	}
}
