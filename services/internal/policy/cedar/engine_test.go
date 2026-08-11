package cedar

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
	"stratium/pkg/models"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed:  "permit(principal, action, resource) when { unbalanced ][",
		WellFormed: "permit(principal, action, resource);",
		AllowAll:   "permit(principal, action, resource);",
		DenyAll:    "forbid(principal, action, resource);",
		DeadForms:  deadForms(),
	})
}

// deadFormReferenceInput is the one EvaluationInput every DeadForm.Live text
// below is written against — deliberately the same reference values named
// in the task 2 brief (trust_tier=CERTIFIED, derived_tier=DESTRUCTIVE,
// purpose=quarterly-close, a resource carrying id and classification), so
// the fixtures below and the brief's own worked examples describe the same
// request throughout.
var deadFormReferenceInput = policy.EvaluationInput{
	Principal:   authz.Principal{Subject: "alice"},
	Agent:       authz.AgentInfo{TrustTier: models.TrustTierCertified},
	DerivedTier: models.ActionTierDestructive,
	Delegation: policy.DelegationContext{
		Purpose: "quarterly-close",
		// Deliberately not EXTERNAL_COMMS by coincidence with DerivedTier's
		// own DESTRUCTIVE: distinct tiers on distinct fields, the same
		// reasoning policytest's own probeInputs doc comment gives for why
		// its probe fields are never accidentally equal to one another —
		// two fields sharing a value can mask one being read in place of
		// the other.
		MaxActionTier: models.ActionTierExternalComms,
	},
	Resource: map[string]string{"id": "res-1", "classification": "restricted"},
}

// deadForms is the nine dead shapes Task 2 now rejects at authoring time —
// see deadform.go's package doc for why these nine (of the thirteen the
// task brief audited) needed new checks, and the task report for the full
// classification of all thirteen. Every Dead text is verified (in
// deadform_test.go, and empirically before this file was written) to have
// validated, prepared, and produced zero verdicts against
// deadFormReferenceInput before this task; every Live text is its minimal
// correction, differing only in the one respect its own dead form is named
// for.
func deadForms() []policytest.DeadForm {
	return []policytest.DeadForm{
		{
			Name:      "wrong-case enum",
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == "Certified" };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "ordinal instead of name",
			// A rule ported from Rego, where derived_tier's own comparisons
			// use the bare ordinal — see rego/engine.go's package doc — but
			// trust_tier stays a String on both sides of this port, never an
			// ordinal Long; "2" is CERTIFIED's ordinal (models.tier.go), not
			// its name.
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == "2" };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "padded literal",
			Dead:      `permit(principal, action, resource) when { context.agent.trust_tier == " CERTIFIED " };`,
			Live:      `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "name instead of ordinal",
			// The mirror image of "ordinal instead of name": a rule ported
			// from XACML, which spells every tier by name (see
			// xacml/schema.go's actionTierValues) — but derived_tier is a
			// Cedar Long here (request.go's buildRequest), never a String.
			Dead:      `permit(principal, action, resource) when { context.derived_tier == "DESTRUCTIVE" };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) when { context.derived_tier == %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "out-of-lattice ceiling",
			Dead:      `permit(principal, action, resource) when { context.derived_tier > 99 };`,
			Live:      fmt.Sprintf(`permit(principal, action, resource) when { context.derived_tier >= %d };`, int(models.ActionTierDestructive)),
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "unknown entity type",
			Dead:      `permit(principal == Usr::"alice", action, resource);`,
			Live:      `permit(principal == User::"alice", action, resource);`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "wrong principal type",
			Dead:      `permit(principal is Resource, action, resource);`,
			Live:      `permit(principal is User, action, resource);`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name:      "contradiction",
			Dead:      `permit(principal, action, resource) when { 1 == 2 };`,
			Live:      `permit(principal, action, resource) when { 1 == 1 };`,
			LiveInput: deadFormReferenceInput,
		},
		{
			Name: "vacuous empty set",
			// Cedar's scope grammar rejects an empty entity list outright
			// (principal in [] does not even parse — confirmed empirically),
			// so the form that actually reaches Prepare unrejected today is
			// an empty Set.contains(...) call, the idiom an author reaching
			// for "is this tier one of these" would actually write (Cedar's
			// `in` operator itself only tests entity-hierarchy membership,
			// not generic set membership — see the task report).
			Dead:      `permit(principal, action, resource) when { [].contains(context.agent.trust_tier) };`,
			Live:      `permit(principal, action, resource) when { ["CERTIFIED", "PLATFORM_TRUSTED"].contains(context.agent.trust_tier) };`,
			LiveInput: deadFormReferenceInput,
		},
	}
}

// TestPrepare_MalformedPolicyErrorNamesTheOffenderByName covers what
// policytest.EngineContract's "prepare on malformed text fails and names
// the offending policy's ID" property does not: Cedar's error already names
// the offender by ID there, checked engine-independently against every
// engine. This test is only for the Name half, which is Cedar's own
// formatting choice (see Prepare's fmt.Errorf call site, which interpolates
// sp.Name alongside sp.ID) — a courtesy to an operator who recognizes
// policies by name, not a promise every future engine must keep.
func TestPrepare_MalformedPolicyErrorNamesTheOffenderByName(t *testing.T) {
	ctx := context.Background()
	policies := []policy.StoredPolicy{
		{ID: "good-1", Name: "always-permit", Text: "permit(principal, action, resource);"},
		{ID: "bad-owner-7", Name: "quarantine-rule", Text: "permit(principal, action, resource) when { unbalanced ]["},
	}

	_, err := New().Prepare(ctx, policies)
	if err == nil {
		t.Fatal("Prepare accepted a malformed policy, want an error")
	}
	if !strings.Contains(err.Error(), "quarantine-rule") {
		t.Errorf("error does not name the offending policy's name: %v", err)
	}
	// And it must not, say, blame the well-formed policy that happens to
	// share the same Prepare call.
	if strings.Contains(err.Error(), "always-permit") {
		t.Errorf("error blames the well-formed policy's name instead of the malformed one's: %v", err)
	}
}

func TestPrepare_RejectsTextWithoutExactlyOneStatement(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		text string
	}{
		{"empty text", ""},
		{"two statements", "permit(principal, action, resource);\nforbid(principal, action, resource);"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policies := []policy.StoredPolicy{{ID: "p1", Name: "multi", Text: tc.text}}
			if _, err := New().Prepare(ctx, policies); err == nil {
				t.Fatalf("Prepare accepted text with != 1 statement (%q), want an error", tc.text)
			}
		})
	}
}

// TestValidate_MirrorsPrepareOnMalformedText used to check that Cedar's
// Validate and Prepare treat the same malformed text the same way. Both
// halves of that claim are now proven by policytest.EngineContract, which
// runs "unbalanced ][" (this test's own fixture, verbatim) through both
// Validate ("validate" property) and Prepare ("prepare on malformed text"
// property) already — this test would only be checking the same input
// against the same two code paths a second time.
