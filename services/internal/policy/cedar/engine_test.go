package cedar

import (
	"context"
	"strings"
	"testing"

	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
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
	})
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
