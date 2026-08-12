package rego

import (
	"context"
	"fmt"
	"strings"
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

// conflictingDenyText defines `deny` twice: true if derived_tier is above
// the tier-2 line, false if the agent is CERTIFIED. Both bodies can hold at
// once — a tenant authoring bug, not a syntax error — and OPA can only
// detect that a specific request triggers it once the real values are
// known, at Eval time (confirmed against this exact OPA release before
// writing this test: the module compiles cleanly via PrepareForEval; only
// Eval, given a request where both conditions hold, returns a non-nil
// *topdown.Error, "eval_conflict_error: complete rules must not produce
// multiple outputs").
const conflictingDenyText = `package stratium.policy

deny := true if { input.derived_tier > 2 }
deny := false if { input.agent.trust_tier == "CERTIFIED" }`

// TestEvaluate_NotEqualsOnAbsentAttributeFailsOpen pins the exact trap
// engine.go's package doc ("Absence is undefined, not false") documents,
// against the real engine: input.principal.attributes.mfa is a key OPA
// leaves undefined when Principal.Attributes carries no "mfa" entry at all
// (stringMapOrEmpty makes the map itself present and empty, never null, but
// an empty map still has no "mfa" key), and Rego's != builtin — unlike
// `not X == Y` — requires both operands defined to produce a value, so the
// whole rule body goes undefined and the rule contributes no verdict at
// all: indistinguishable, to this package's own Evaluate, from a deny rule
// that legitimately never applies. A sibling allow-all policy (every real
// tenant's principal leg groups more than one policy — see policy.Multi)
// is what turns "this one policy stayed silent" into an observable
// fail-open outcome once authz.FoldVerdicts (outside this package) folds
// the two verdicts together.
func TestEvaluate_NotEqualsOnAbsentAttributeFailsOpen(t *testing.T) {
	absentMFA := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}}
	presentButFalseMFA := policy.EvaluationInput{
		Principal: authz.Principal{Subject: "alice", Attributes: map[string]string{"mfa": "false"}},
	}
	denyUnlessMFA := func(body string) string {
		return fmt.Sprintf("package stratium.policy\n\ndeny if {\n\t%s\n}", body)
	}
	const notEqualsBody = `input.principal.attributes.mfa != "true"`
	const notEqualBody = `not input.principal.attributes.mfa == "true"`

	t.Run("!= silently does not fire when the attribute is absent (fails OPEN)", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "deny-leg", Name: "deny-unless-mfa", Text: denyUnlessMFA(notEqualsBody)},
			{ID: "allow-leg", Name: "allow-all", Text: "package stratium.policy\n\nallow := true"},
		})
		verdicts, err := set.Evaluate(context.Background(), absentMFA)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		// Only the allow-all sibling may show up: the != deny rule must
		// produce no verdict at all (undefined, not true) when mfa is
		// absent. A fold over this slice would land on ALLOW.
		if len(verdicts) != 1 || verdicts[0].PolicyID != "allow-leg" || verdicts[0].Effect != authz.EffectAllow {
			t.Fatalf("got %+v, want exactly the allow-all verdict (the != deny rule must stay silent when mfa is absent)", verdicts)
		}
	})

	t.Run("not X == Y correctly denies when the attribute is absent (fails CLOSED)", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{
			{ID: "deny-leg", Name: "deny-unless-mfa", Text: denyUnlessMFA(notEqualBody)},
			{ID: "allow-leg", Name: "allow-all", Text: "package stratium.policy\n\nallow := true"},
		})
		verdicts, err := set.Evaluate(context.Background(), absentMFA)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		byID := make(map[string]authz.Effect, len(verdicts))
		for _, v := range verdicts {
			byID[v.PolicyID] = v.Effect
		}
		if byID["deny-leg"] != authz.EffectDeny {
			t.Fatalf("got %+v, want deny-leg to fire EffectDeny (not X == Y must treat an absent attribute as not-equal)", verdicts)
		}
	})

	// Control: with mfa actually present, but "false" rather than "true",
	// both spellings must deny — proving the divergence above is specific
	// to absence, not a general difference in what the two spellings mean.
	t.Run("control: both spellings deny when mfa is present but false", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body string
		}{
			{"!=", notEqualsBody},
			{"not ... ==", notEqualBody},
		} {
			t.Run(tc.name, func(t *testing.T) {
				set := prepare(t, []policy.StoredPolicy{
					{ID: "deny-leg", Name: "deny-unless-mfa", Text: denyUnlessMFA(tc.body)},
				})
				verdicts, err := set.Evaluate(context.Background(), presentButFalseMFA)
				if err != nil {
					t.Fatalf("Evaluate: %v", err)
				}
				if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
					t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
				}
			})
		}
	})
}

// TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy covers the review-
// found Critical: a policy that fails to evaluate for a given request (a
// genuine Eval error, not merely "no rule fired") must produce a deny
// verdict naming that policy, not be silently discarded via `continue` the
// way this method used to treat every Eval error, indistinguishably from a
// true non-match.
func TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy(t *testing.T) {
	// Both deny bodies hold: derived_tier (4, Destructive) is above 2, and
	// the agent is CERTIFIED — the conflict conflictingDenyText documents.
	conflicting := policy.EvaluationInput{
		DerivedTier: models.ActionTierDestructive,
		Agent:       authz.AgentInfo{TrustTier: models.TrustTierCertified},
	}

	t.Run("conflicting rule bodies deny and name the policy", func(t *testing.T) {
		const wantID = "conflict-policy"
		set := prepare(t, []policy.StoredPolicy{{ID: wantID, Name: "self-conflicting", Text: conflictingDenyText}})

		verdicts, err := set.Evaluate(context.Background(), conflicting)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want exactly 1 (a deny): %+v", len(verdicts), verdicts)
		}
		v := verdicts[0]
		if v.Effect != authz.EffectDeny {
			t.Errorf("Effect = %v, want EffectDeny — an evaluation failure must deny, not be silently dropped", v.Effect)
		}
		if v.PolicyID != wantID {
			t.Errorf("PolicyID = %q, want %q", v.PolicyID, wantID)
		}
		// The Reason must carry OPA's own message, not a generic string —
		// otherwise an operator cannot tell this apart from any other deny.
		if !strings.Contains(v.Reason, "eval_conflict_error") || !strings.Contains(v.Reason, "complete rules must not produce multiple outputs") {
			t.Errorf("Reason does not carry rego's underlying error message: %q", v.Reason)
		}
	})

	// Positive control: the identical policy text, given a request that
	// triggers only ONE of the two deny bodies, evaluates cleanly — proving
	// the case above is a real, request-dependent conflict and not this
	// policy simply always erroring.
	t.Run("the same policy evaluates cleanly when only one body's condition holds", func(t *testing.T) {
		set := prepare(t, []policy.StoredPolicy{{ID: "p1", Name: "self-conflicting", Text: conflictingDenyText}})

		t.Run("only the tier condition holds: denies, no error", func(t *testing.T) {
			verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
				DerivedTier: models.ActionTierDestructive,
				Agent:       authz.AgentInfo{TrustTier: models.TrustTierUnverified},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
				t.Fatalf("got %+v, want exactly one EffectDeny verdict", verdicts)
			}
		})

		t.Run("only the trust-tier condition holds: no verdict, no error", func(t *testing.T) {
			verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
				DerivedTier: models.ActionTierReadOnly,
				Agent:       authz.AgentInfo{TrustTier: models.TrustTierCertified},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if len(verdicts) != 0 {
				t.Fatalf("got %+v, want zero verdicts (deny resolves to false, which is not a match)", verdicts)
			}
		})
	})

	// One broken policy must not suppress a healthy neighbor's verdict —
	// the same "does not blame/silence the neighbor" property this
	// package's own malformed-policy tests already require of Prepare,
	// checked here for Evaluate instead.
	t.Run("a healthy policy alongside the broken one still produces its own verdict", func(t *testing.T) {
		const brokenID, healthyID = "broken-neighbor", "healthy-neighbor"
		set := prepare(t, []policy.StoredPolicy{
			{ID: brokenID, Name: "self-conflicting", Text: conflictingDenyText},
			{ID: healthyID, Name: "allow-all", Text: `package stratium.policy

allow := true`},
		})

		verdicts, err := set.Evaluate(context.Background(), conflicting)
		if err != nil {
			t.Fatalf("Evaluate: %v", err)
		}
		if len(verdicts) != 2 {
			t.Fatalf("got %d verdicts, want 2 (one deny for the broken policy, one allow for the healthy one): %+v", len(verdicts), verdicts)
		}

		byID := make(map[string]authz.PolicyVerdict, len(verdicts))
		for _, v := range verdicts {
			byID[v.PolicyID] = v
		}
		if v, ok := byID[brokenID]; !ok || v.Effect != authz.EffectDeny {
			t.Errorf("broken policy verdict = %+v, ok=%v, want a present EffectDeny verdict", v, ok)
		}
		if v, ok := byID[healthyID]; !ok || v.Effect != authz.EffectAllow {
			t.Errorf("healthy policy verdict = %+v, ok=%v, want a present EffectAllow verdict — the broken policy must not have suppressed it", v, ok)
		}
	})
}
