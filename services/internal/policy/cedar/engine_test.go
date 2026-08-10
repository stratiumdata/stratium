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
	policytest.EngineContract(t, New())
}

func TestPrepare_MalformedPolicyNamesTheOffender(t *testing.T) {
	ctx := context.Background()
	policies := []policy.StoredPolicy{
		{ID: "good-1", Name: "always-permit", Text: "permit(principal, action, resource);"},
		{ID: "bad-owner-7", Name: "quarantine-rule", Text: "permit(principal, action, resource) when { unbalanced ]["},
	}

	_, err := New().Prepare(ctx, policies)
	if err == nil {
		t.Fatal("Prepare accepted a malformed policy, want an error")
	}

	// An operator with fifty policies needs to know which one is broken, not
	// that "a policy" is. The error must name the offending policy well
	// enough to find it — both its ID (the thing an operator would look up)
	// and its name are checked so a message naming only one of them still
	// fails loudly here rather than passing by accident.
	if !strings.Contains(err.Error(), "bad-owner-7") {
		t.Errorf("error does not name the offending policy's ID: %v", err)
	}
	if !strings.Contains(err.Error(), "quarantine-rule") {
		t.Errorf("error does not name the offending policy's name: %v", err)
	}
	// And it must not, say, blame the well-formed policy that happens to
	// share the same Prepare call.
	if strings.Contains(err.Error(), "good-1") || strings.Contains(err.Error(), "always-permit") {
		t.Errorf("error blames the well-formed policy instead of the malformed one: %v", err)
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

func TestValidate_MirrorsPrepareOnMalformedText(t *testing.T) {
	ctx := context.Background()
	const malformed = "permit(principal, action, resource) when { unbalanced ]["
	if err := New().Validate(ctx, malformed); err == nil {
		t.Fatal("Validate accepted malformed text, want an error")
	}
}
