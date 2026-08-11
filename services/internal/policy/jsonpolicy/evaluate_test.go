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

// TestEvaluate_DerivedTierAtMost is the property that justifies
// tierMatch.matches comparing tier and AtMost as real integers rather than
// as strings — see that method's own doc comment. The "ceiling above the
// tier lattice" subtest is the one that actually forces integer and
// lexicographic comparison apart: every real models.ActionTier value is a
// single digit (0-4), so an AtMost also confined to that range would agree
// under either comparison, and a string-comparison mutant would slip
// through undetected by the other subtests alone.
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

	t.Run("ceiling above the tier lattice matches the highest tier (numeric, not lexicographic, comparison)", func(t *testing.T) {
		// at_most: 10 has no ActionTier that could exceed it — this is only
		// reachable because the schema permits any JSON integer under
		// at_most, not just 0-4. "4" <= "10" is FALSE lexicographically
		// (leading '4' > leading '1') but 4 <= 10 is true numerically: a
		// string-comparison mutant fails this specific case while passing
		// every subtest above, where every value involved is a single digit.
		above := prepare(t, []policy.StoredPolicy{
			{ID: "p1", Name: "at-most-ten", Text: `{"effect": "allow", "match": {"derived_tier": {"at_most": 10}}}`},
		})
		verdicts := mustEvaluate(t, above, policy.EvaluationInput{DerivedTier: models.ActionTierDestructive})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1 (DESTRUCTIVE=4 is numerically <= 10): %+v", len(verdicts), verdicts)
		}
	})
}

// TestEvaluate_EffectComesFromPolicyTextNotStoredPolicy pins a design choice
// recorded in Prepare's own doc comment: the verdict's effect is derived
// from the JSON text's own "effect" key — the same choice Cedar and Rego
// make for their own languages' native effect syntax — never from
// StoredPolicy.Effect. StoredPolicy.Effect is deliberately set to the
// opposite of what the text says, so a Prepare that read the wrong field
// would produce the wrong verdict here specifically, rather than merely
// agreeing by fixture coincidence the way policytest's own AllowAll/DenyAll
// checks do (those fixtures keep both fields in agreement by construction —
// see Fixtures' own doc comment).
func TestEvaluate_EffectComesFromPolicyTextNotStoredPolicy(t *testing.T) {
	set := prepare(t, []policy.StoredPolicy{
		{ID: "p1", Name: "text-says-deny", Text: `{"effect": "deny", "match": {}}`, Effect: "allow"},
	})
	verdicts := mustEvaluate(t, set, policy.EvaluationInput{})
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
	}
	if verdicts[0].Effect != authz.EffectDeny {
		t.Fatalf("Effect = %v, want EffectDeny (must come from the policy text's own \"effect\" key, not StoredPolicy.Effect)", verdicts[0].Effect)
	}
}
