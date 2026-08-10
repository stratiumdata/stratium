package cedar

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

func TestEvaluate_PermitYieldsAllow(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "allow-all", Text: "permit(principal, action, resource);", Priority: 7},
	})

	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
		Principal: authz.Principal{Subject: "alice"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	v := verdicts[0]
	if v.Effect != authz.EffectAllow {
		t.Errorf("Effect = %v, want EffectAllow", v.Effect)
	}
	if v.Source != "cedar" {
		t.Errorf("Source = %q, want %q", v.Source, "cedar")
	}
	if v.PolicyID != "p1" {
		t.Errorf("PolicyID = %q, want %q", v.PolicyID, "p1")
	}
	if v.Priority != 7 {
		t.Errorf("Priority = %d, want 7 (recorded, not acted on)", v.Priority)
	}
}

func TestEvaluate_ForbidYieldsDeny(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "deny-all", Text: "forbid(principal, action, resource);"},
	})

	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
		Principal: authz.Principal{Subject: "alice"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny", verdicts[0].Effect)
	}
}

func TestEvaluate_NonMatchingPolicyYieldsNoVerdict(t *testing.T) {
	// Scoped to a specific principal, which also doubles as proof that the
	// principal entity mapping (type User, ID = Subject) is real: "bob"
	// matches, "alice" does not.
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "only-bob", Text: `permit(principal == User::"bob", action, resource);`},
	})

	t.Run("matching principal", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Principal: authz.Principal{Subject: "bob"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1 (positive control — mapping must be exercised for real)", len(verdicts))
		}
	})

	t.Run("non-matching principal", func(t *testing.T) {
		verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
			Principal: authz.Principal{Subject: "alice"},
		})
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})
}

func TestEvaluate_AgentTrustTierReadableFromContextDrivesForbid(t *testing.T) {
	// The Y3 rule this stands in for: "deny Unverified agents on financial
	// tools" — simplified to just the trust-tier condition, since the
	// mapping under test is context visibility, not resource classification.
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "block-unverified-agents", Text: `forbid(principal, action, resource) when { context.agent.trust_tier == "UNVERIFIED" };`},
	})

	t.Run("unverified agent is forbidden", func(t *testing.T) {
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

func TestEvaluate_ClassificationCapReadableFromContextDrivesForbid(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "block-restricted-pii", Text: `forbid(principal, action, resource) when { context.delegation.classification_caps["pii"] == "restricted" };`},
	})

	t.Run("restricted cap is forbidden", func(t *testing.T) {
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
}

// TestEvaluate_DerivedTierReadableFromContextDrivesForbid is the
// prerequisite Part 2's tier walk-down depends on: a tier-ceiling policy —
// forbid at or above a tier, permit otherwise — must actually read
// context.derived_tier, not just have it silently present and unread.
//
// Without the mapping, referencing context.derived_tier is a reference to
// an absent record attribute, which Cedar treats as an evaluation error —
// and Evaluate treats an evaluation error the same as a non-match (see this
// package's doc comment), so "cap" simply never appears in verdicts. The
// first subtest below checks presence with the two-value map form
// (effect, ok := byID["cap"]) rather than comparing byID["cap"] to
// authz.EffectDeny directly: authz.Effect's zero value IS EffectDeny (by
// design, for the runtime decision path — see that type's doc comment), so
// a bare equality check cannot tell "cap fired and denied" apart from "cap
// never fired at all" — exactly the silent-pass this test exists to rule
// out. Caught in review by running this test against a deliberately
// unmapped buildRequest before trusting it.
func TestEvaluate_DerivedTierReadableFromContextDrivesForbid(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{
			ID:   "cap",
			Name: "forbid-at-or-above-destructive",
			Text: fmt.Sprintf(`forbid(principal, action, resource) when { context.derived_tier >= %d };`,
				int(models.ActionTierDestructive)),
		},
		{ID: "base", Name: "allow-all", Text: "permit(principal, action, resource);"},
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
				"(it must actually read the tier, not always fire)", verdicts)
		}
		if byID["base"] != authz.EffectAllow {
			t.Fatalf("got %+v, want the base policy to allow a probe below the capped tier", verdicts)
		}
	})
}

// TestEvaluate_PriorityDoesNotChangeOutcome constructs a high-priority
// permit against a low-priority forbid. Spec Y7 removed
// first-applicable-by-priority; deny-overrides (applied downstream by
// authz.FoldVerdicts, not this package) replaced it. If Evaluate sorted,
// filtered, or short-circuited on Priority, the low-priority forbid could go
// missing from the result. It must not: both verdicts come back, regardless
// of order — Cedar's own PolicySet is a map, so relying on returned order
// would itself be a latent bug this test also guards against.
func TestEvaluate_PriorityDoesNotChangeOutcome(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "low-forbid", Name: "low-priority-forbid", Text: "forbid(principal, action, resource);", Priority: 1},
		{ID: "high-permit", Name: "high-priority-permit", Text: "permit(principal, action, resource);", Priority: 100},
	})

	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
		Principal: authz.Principal{Subject: "alice"},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 2 {
		t.Fatalf("got %d verdicts, want 2 (both must survive regardless of priority): %+v", len(verdicts), verdicts)
	}

	byID := make(map[string]authz.Effect, len(verdicts))
	for _, v := range verdicts {
		byID[v.PolicyID] = v.Effect
	}
	if got, want := byID["low-forbid"], authz.EffectDeny; got != want {
		t.Errorf("low-forbid effect = %v, want %v", got, want)
	}
	if got, want := byID["high-permit"], authz.EffectAllow; got != want {
		t.Errorf("high-permit effect = %v, want %v", got, want)
	}
}
