package jsonpolicy

import (
	"context"
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

func mustEvaluate(t *testing.T, set policy.CompiledPolicySet, in policy.EvaluationInput) []authz.PolicyVerdict {
	t.Helper()
	verdicts, err := set.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return verdicts
}

// Permit-yields-allow, forbid-yields-deny, and Source/PolicyID provenance
// are checked by policytest.EngineContract, run against every engine
// including this one — duplicating them here would just be the same
// assertion twice under a different name (see cedar/evaluate_test.go's
// identical note).

// TestEvaluate_EmptyMatchMatchesEverything is the task brief's own required
// "an empty match matching" test, exercised directly against match.matches
// rather than only indirectly through the contract's AllowAll fixture — the
// same input battery used elsewhere in this file (a zero-value and a fully
// populated EvaluationInput) proves the empty object matches regardless of
// what is being asked, not merely regardless of what this suite's other
// fixtures happen to ask.
func TestEvaluate_EmptyMatchMatchesEverything(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "allow-all", Text: `{"effect": "allow", "match": {}}`},
	})

	for _, tc := range []struct {
		name string
		in   policy.EvaluationInput
	}{
		{"zero-value input", policy.EvaluationInput{}},
		{"fully populated input", policy.EvaluationInput{
			Principal:   authz.Principal{Subject: "someone", Attributes: map[string]string{"department": "eng"}},
			Action:      authz.Action{Tool: "Bash"},
			DerivedTier: models.ActionTierDestructive,
			Resource:    map[string]string{"id": "res-1"},
			Agent:       authz.AgentInfo{TrustTier: models.TrustTierCertified},
			Delegation:  policy.DelegationContext{Purpose: "quarterly-close"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := mustEvaluate(t, set, tc.in)
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
	}
}

// TestEvaluate_MatchKeysAreANDed pins the package doc's "every key inside
// match is ANDed" rule directly: a policy naming both subject and tool must
// require both, not either.
func TestEvaluate_MatchKeysAreANDed(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "finance-bash-only", Text: `{"effect": "allow", "match": {
			"subject": {"attr": "department", "equals": "finance"},
			"tool": {"equals": "Bash"}
		}}`},
	})

	cases := []struct {
		name       string
		department string
		tool       string
		wantMatch  bool
	}{
		{"both match", "finance", "Bash", true},
		{"only subject matches", "finance", "Read", false},
		{"only tool matches", "eng", "Bash", false},
		{"neither matches", "eng", "Read", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{
				Principal: authz.Principal{Attributes: map[string]string{"department": tc.department}},
				Action:    authz.Action{Tool: tc.tool},
			})
			gotMatch := len(verdicts) == 1
			if gotMatch != tc.wantMatch {
				t.Fatalf("got %d verdicts (match=%v), want match=%v: %+v", len(verdicts), gotMatch, tc.wantMatch, verdicts)
			}
		})
	}
}

// TestEvaluate_AbsentKeyIsNotAConstraint is TestEvaluate_MatchKeysAreANDed's
// complement: a policy naming only subject must match regardless of every
// OTHER dimension's value — an absent key must never silently become a
// constraint of its own (e.g. "tool must be the empty string").
func TestEvaluate_AbsentKeyIsNotAConstraint(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "finance-only", Text: `{"effect": "allow", "match": {
			"subject": {"attr": "department", "equals": "finance"}
		}}`},
	})

	for _, tc := range []struct {
		name string
		in   policy.EvaluationInput
	}{
		{"other dimensions at zero value", policy.EvaluationInput{
			Principal: authz.Principal{Attributes: map[string]string{"department": "finance"}},
		}},
		{"other dimensions fully populated", policy.EvaluationInput{
			Principal:   authz.Principal{Attributes: map[string]string{"department": "finance"}},
			Action:      authz.Action{Tool: "Bash"},
			DerivedTier: models.ActionTierDestructive,
			Agent:       authz.AgentInfo{TrustTier: models.TrustTierUnverified},
			Delegation:  policy.DelegationContext{Purpose: "anything-at-all"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdicts := mustEvaluate(t, set, tc.in)
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1 (subject matched; every other dimension is absent from match and must not block it): %+v", len(verdicts), verdicts)
			}
		})
	}
}

func TestEvaluate_SubjectAttr(t *testing.T) {
	t.Run("equals", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "finance-only", Text: `{"effect": "allow", "match": {"subject": {"attr": "department", "equals": "finance"}}}`},
		})
		t.Run("matches", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"department": "finance"}}})
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("does not match", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"department": "eng"}}})
			if len(verdicts) != 0 {
				t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("absent attribute does not match (nil-safe map read)", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{})
			if len(verdicts) != 0 {
				t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
			}
		})
	})

	t.Run("in", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "finance-or-legal", Text: `{"effect": "allow", "match": {"subject": {"attr": "department", "in": ["finance", "legal"]}}}`},
		})
		t.Run("matches first member", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"department": "finance"}}})
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("matches second member", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"department": "legal"}}})
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("does not match a non-member", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"department": "eng"}}})
			if len(verdicts) != 0 {
				t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
			}
		})
	})
}

func TestEvaluate_Tool(t *testing.T) {
	t.Run("in", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "read-only-tools", Text: `{"effect": "allow", "match": {"tool": {"in": ["Read", "Grep"]}}}`},
		})
		t.Run("matches a member", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Grep"}})
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("does not match a non-member", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}})
			if len(verdicts) != 0 {
				t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
			}
		})
	})

	t.Run("equals", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "bash-only", Text: `{"effect": "allow", "match": {"tool": {"equals": "Bash"}}}`},
		})
		t.Run("matches", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}})
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
		})
		t.Run("does not match", func(t *testing.T) {
			verdicts := mustEvaluate(t, set, policy.EvaluationInput{Action: authz.Action{Tool: "Read"}})
			if len(verdicts) != 0 {
				t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
			}
		})
	})
}

// TestEvaluate_AgentTrustTier stands in for spec rule Y3, "deny Unverified
// agents on financial tools" — simplified to just the trust-tier condition,
// the same simplification cedar's and rego's own equivalent tests make,
// since what is under test here is input visibility, not resource
// classification.
func TestEvaluate_AgentTrustTier(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "block-unverified-agents", Text: `{"effect": "deny", "match": {"agent": {"attr": "trust_tier", "equals": "UNVERIFIED"}}}`},
	})

	t.Run("unverified agent is denied", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{Agent: authz.AgentInfo{TrustTier: models.TrustTierUnverified}})
		if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
			t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
		}
	})

	t.Run("certified agent is not matched by the rule", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{Agent: authz.AgentInfo{TrustTier: models.TrustTierCertified}})
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0 (rule must actually read the tier, not always fire): %+v", len(verdicts), verdicts)
		}
	})
}

func TestEvaluate_DelegationPurpose(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "quarterly-close-only", Text: `{"effect": "allow", "match": {"delegation": {"attr": "purpose", "equals": "quarterly-close"}}}`},
	})

	t.Run("matching purpose", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{Delegation: policy.DelegationContext{Purpose: "quarterly-close"}})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("different purpose does not match", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{Delegation: policy.DelegationContext{Purpose: "ad-hoc"}})
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})
}

// TestEvaluate_DerivedTierAtMost covers the in-range ceiling behaviour:
// matching at and under the ceiling, not matching above it. It used to also
// carry the subtest that forced tierMatch.matches' integer-vs-string
// comparison apart (an out-of-lattice at_most: 10, since every in-range
// pair is single-digit and lexicographic order agrees with numeric order
// there) — review correctly flagged that value as itself a vacuous-in-the-
// other-direction defect (an at_most above the highest tier can never
// filter anything out, functionally identical to omitting derived_tier
// entirely) and asked for it to be rejected by Validate. Now that
// tierMatch.validate does reject it, that subtest's own fixture no longer
// prepares, so the integer-vs-string property is pinned directly against
// tierMatch.matches instead — see TestTierMatch_MatchesComparesNumerically
// in schema_test.go — rather than through this engine-level Evaluate path.
func TestEvaluate_DerivedTierAtMost(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "at-most-internal-modify", Text: `{"effect": "allow", "match": {"derived_tier": {"at_most": 2}}}`},
	})

	t.Run("tier at the ceiling matches", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{DerivedTier: models.ActionTierInternalModify})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("tier under the ceiling matches", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{DerivedTier: models.ActionTierReasoning})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}
	})

	t.Run("tier above the ceiling does not match", func(t *testing.T) {
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{DerivedTier: models.ActionTierDestructive})
		if len(verdicts) != 0 {
			t.Fatalf("got %d verdicts, want 0: %+v", len(verdicts), verdicts)
		}
	})

	// Positive control for the range check added in review: the highest
	// legal at_most (4, models.ActionTierDestructive) is not itself
	// rejected — only values outside [0, 4] are — and still both validates
	// and matches the tier it names exactly.
	t.Run("at_most at the top of the valid range still matches", func(t *testing.T) {
		top := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "at-most-destructive", Text: `{"effect": "allow", "match": {"derived_tier": {"at_most": 4}}}`},
		})
		verdicts := mustEvaluate(t, top, policy.EvaluationInput{DerivedTier: models.ActionTierDestructive})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}
	})
}
