package cedar

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/pkg/models"
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

// TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy covers the review-
// found Critical: a policy whose `when`/`unless` condition raises a genuine
// Cedar evaluation error (diag.Errors non-empty) must produce a deny
// verdict naming that policy, not be silently discarded the way a true
// non-match is. Both cases below are real Cedar evaluation errors, not
// contrived Go values — confirmed against this exact cedar-go release
// before writing this test: each policy parses and prepares cleanly (the
// error is a property of the request, not the text) and Cedar's own
// Diagnostic reports zero Reasons and exactly one Error for each.
func TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy(t *testing.T) {
	// derived_tier is mapped as a Cedar Long (see request.go); comparing it
	// to a string literal is a type error only Cedar's evaluator can catch,
	// once it actually walks the expression against a request.
	const typeErrorText = `forbid(principal, action, resource) when { context.derived_tier > "2" };`
	// context has no "nope" field (see buildRequest) — Cedar records raise
	// an evaluation error for an absent attribute, unlike Rego's
	// undefined-on-missing-key semantics.
	const missingAttrText = `forbid(principal, action, resource) when { context.nope == "x" };`

	anyInput := policy.EvaluationInput{Principal: authz.Principal{Subject: "alice"}, DerivedTier: models.ActionTierDestructive}

	t.Run("type error denies and names the policy", func(t *testing.T) {
		const wantID = "type-error-policy"
		set := prepare(t, []policy.StoredPolicy{{ID: wantID, Name: "bad-comparison", Text: typeErrorText}})

		verdicts, err := set.Evaluate(context.Background(), anyInput)
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
		// The Reason must carry Cedar's own message, not a generic string —
		// otherwise an operator cannot tell this apart from any other deny.
		if !strings.Contains(v.Reason, "type error") || !strings.Contains(v.Reason, "expected comparable value") {
			t.Errorf("Reason does not carry cedar's underlying error message: %q", v.Reason)
		}
	})

	t.Run("missing attribute denies and names the policy", func(t *testing.T) {
		const wantID = "missing-attr-policy"
		set := prepare(t, []policy.StoredPolicy{{ID: wantID, Name: "bad-attribute", Text: missingAttrText}})

		verdicts, err := set.Evaluate(context.Background(), anyInput)
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
		if !strings.Contains(v.Reason, "record does not have the attribute") || !strings.Contains(v.Reason, "nope") {
			t.Errorf("Reason does not carry cedar's underlying error message: %q", v.Reason)
		}
	})

	// One broken policy must not suppress a healthy neighbor's verdict —
	// the same "does not blame/silence the neighbor" property this
	// package's own malformed-policy tests already require of Prepare,
	// checked here for Evaluate instead.
	t.Run("a healthy policy alongside the broken one still produces its own verdict", func(t *testing.T) {
		const brokenID, healthyID = "broken-neighbor", "healthy-neighbor"
		set := prepare(t, []policy.StoredPolicy{
			{ID: brokenID, Name: "bad-attribute", Text: missingAttrText},
			{ID: healthyID, Name: "always-permit", Text: "permit(principal, action, resource);"},
		})

		verdicts, err := set.Evaluate(context.Background(), anyInput)
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
