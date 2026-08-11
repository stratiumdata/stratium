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

// Permit-yields-allow, forbid-yields-deny, and the Source/PolicyID
// provenance on the resulting verdict used to be checked here individually.
// They now live in policytest.EngineContract (the "AllowAll"/"DenyAll" and
// "verdict provenance" properties), which every engine — not just Cedar —
// is run against; keeping a duplicate here would just be the same assertion
// twice under two different names.

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

// Priority's round-trip onto the verdict, and re-prioritising a policy set
// leaving every verdict's effect unchanged, used to be checked here — a
// high-priority permit against a low-priority forbid, asserting both
// survived regardless of order (Cedar's own PolicySet is a map, so the
// order was never something to assert on directly). Both properties now
// live in policytest.EngineContract's "priority" checks, run against every
// engine, with the same order-independent-by-sorting comparison this test
// used to do inline.
