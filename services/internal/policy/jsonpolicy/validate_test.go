package jsonpolicy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"stratium/internal/policy"
)

// TestValidate_MissingMatchIsRejected is mutation target (a) from the task
// brief: a missing match block must be a validation error, never silently
// treated as match-all.
func TestValidate_MissingMatchIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow"}`)
	if err == nil {
		t.Fatal("Validate accepted text with no match key, want an error — a missing match block is a validation error, not match-all")
	}
}

// TestValidate_EmptyMatchIsAccepted is the positive control for the test
// above: match being ABSENT is rejected, but match being PRESENT and empty
// ({}) is the documented match-everything case and must validate cleanly.
// Without this, a Validate that rejected every match shape — including {} —
// would also pass the missing-match case for the wrong reason.
func TestValidate_EmptyMatchIsAccepted(t *testing.T) {
	if err := New().Validate(context.Background(), `{"effect": "allow", "match": {}}`); err != nil {
		t.Fatalf("Validate rejected an empty match object: %v", err)
	}
}

// TestValidate_UnknownTopLevelKeyIsRejected is half of mutation target (b):
// an unknown key at the document's own top level.
func TestValidate_UnknownTopLevelKeyIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {}, "priority": 1}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown top-level key ("priority"), want an error`)
	}
}

// TestValidate_UnknownMatchKeyIsRejected is half of mutation target (b): a
// key inside match that isn't one of the five the schema defines.
func TestValidate_UnknownMatchKeyIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"resource": {"attr": "id", "equals": "x"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown match key ("resource" is not subject/tool/derived_tier/agent/delegation), want an error`)
	}
}

// TestValidate_UnknownOperatorIsRejected is the task brief's own required
// "an unknown operator rejected" test — an operator name that is not one of
// equals/in/at_most.
func TestValidate_UnknownOperatorIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"subject": {"attr": "department", "startsWith": "fin"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown operator ("startsWith" is not equals/in/at_most), want an error`)
	}
}

// TestValidate_TypoedOperatorIsRejected is the same property as
// TestValidate_UnknownOperatorIsRejected under the specific shape this
// task's mutation testing targets: a typo that leaves BOTH real operators
// absent (here, "eqauls" instead of "equals") must fail valueMatch's
// "exactly one operator" check, not be silently dropped as an unrecognized
// key while the constraint quietly becomes "match anything with this attr
// present" — the worst failure this engine could have.
func TestValidate_TypoedOperatorIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"subject": {"attr": "department", "eqauls": "finance"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted a typo'd operator key ("eqauls"), want an error`)
	}
}

// TestValidate_UnknownKeyAlongsideValidOperatorIsRejected isolates
// DisallowUnknownFields from the "exactly one operator" check above:
// TestValidate_UnknownOperatorIsRejected and TestValidate_TypoedOperatorIsRejected
// both happen to leave the constraint with ZERO operators once the bad key
// is dropped, so they would still fail (for the unrelated "exactly one
// operator required" reason) even if unknown-field rejection were broken —
// mutation testing found this directly: removing
// dec.DisallowUnknownFields() left those two tests green. This fixture adds
// the unknown key ("typo") ALONGSIDE an already-complete, valid "equals"
// operator, so the constraint would be entirely well-formed once the extra
// key is dropped — the one shape that can only be caught by unknown-field
// rejection itself, not by any other validation rule as a side effect.
func TestValidate_UnknownKeyAlongsideValidOperatorIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"subject": {"attr": "department", "equals": "finance", "typo": "x"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown key ("typo") alongside an otherwise well-formed constraint, want an error`)
	}
}

func TestValidate_BothOperatorsSetIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"tool": {"equals": "Read", "in": ["Read", "Grep"]}}}`)
	if err == nil {
		t.Fatal("Validate accepted a constraint with both equals and in set, want an error (exactly one operator is required)")
	}
}

func TestValidate_NeitherOperatorSetIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"tool": {}}}`)
	if err == nil {
		t.Fatal("Validate accepted a constraint with neither equals nor in set, want an error")
	}
}

// TestValidate_EmptyInListIsRejected guards a review finding: "in": []
// decodes to a non-nil, zero-length slice, so it satisfies neither
// TestValidate_BothOperatorsSetIsRejected's check (Equals is nil) nor
// TestValidate_NeitherOperatorSetIsRejected's (In is non-nil) — it slipped
// through both existing checks as a third, unguarded shape. Membership in
// the empty set is false for every value, so a constraint built from it can
// never match anything, ever: the same "reads as a working rule, is
// actually permanently dead" defect as a missing match block, just far less
// visible on a read-through, since the JSON looks complete.
//
// Tested on both valueMatch's two access paths — tool (embeds valueMatch
// directly) and subject (embeds it via attrMatch) — because attrMatch could
// in principle shadow or skip the embedded check; proving both call sites
// independently is what rules that out rather than assuming the embedding
// forwards correctly.
func TestValidate_EmptyInListIsRejected(t *testing.T) {
	t.Run("tool", func(t *testing.T) {
		err := New().Validate(context.Background(), `{"effect": "allow", "match": {"tool": {"in": []}}}`)
		if err == nil {
			t.Fatal(`Validate accepted "tool": {"in": []}, want an error (an empty in list can never match)`)
		}
	})
	t.Run("subject (via attrMatch's embedded valueMatch)", func(t *testing.T) {
		err := New().Validate(context.Background(), `{"effect": "allow", "match": {"subject": {"attr": "department", "in": []}}}`)
		if err == nil {
			t.Fatal(`Validate accepted "subject": {"attr": ..., "in": []}, want an error (an empty in list can never match)`)
		}
	})

	// Positive control: a non-empty in list is not collateral damage from
	// the fix above — it must still validate. TestEvaluate_Tool's "in"
	// subtest (evaluate_test.go) is the sibling positive control for
	// "still matches", so this checks only the Validate half.
	t.Run("non-empty in list is still accepted", func(t *testing.T) {
		err := New().Validate(context.Background(), `{"effect": "allow", "match": {"tool": {"in": ["Read"]}}}`)
		if err != nil {
			t.Fatalf("Validate rejected a well-formed non-empty in list: %v", err)
		}
	})
}

// TestValidate_AtMostOnNonInteger is the task brief's own required test:
// "at_most on a non-integer rejected at Prepare rather than silently
// failing to match at evaluation." Both a JSON string and a fractional
// number are distinct type mismatches an int-typed Go field rejects at
// decode time, before evaluation ever runs.
func TestValidate_AtMostOnNonInteger(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"string", `{"effect": "allow", "match": {"derived_tier": {"at_most": "2"}}}`},
		{"fraction", `{"effect": "allow", "match": {"derived_tier": {"at_most": 2.5}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := New().Validate(context.Background(), tc.text); err == nil {
				t.Fatalf("Validate accepted a non-integer at_most (%s), want an error", tc.name)
			}
		})
	}

	// Positive control: an integer at_most must still validate normally, so
	// the checks above are rejecting the type mismatch specifically, not
	// at_most in general.
	t.Run("integer is accepted", func(t *testing.T) {
		if err := New().Validate(context.Background(), `{"effect": "allow", "match": {"derived_tier": {"at_most": 2}}}`); err != nil {
			t.Fatalf("Validate rejected a well-formed integer at_most: %v", err)
		}
	})
}

// TestValidate_AtMostOutOfRangeIsRejected guards a review finding: a
// negative at_most (e.g. -1) and one above models.ActionTierDestructive
// both decode as legal ints — TestValidate_AtMostOnNonInteger only checks
// the JSON *type*, not the numeric *range* — so both used to validate,
// prepare, and then never behave as their author likely intended. The two
// directions are rejected for different reasons (see tierMatch.validate's
// own doc comment: negative can never match, above the highest tier can
// only ever match everything), but both are checked here, each as its own
// subtest, so removing either half of the underlying range check is caught
// by exactly one of them rather than being masked by the other.
func TestValidate_AtMostOutOfRangeIsRejected(t *testing.T) {
	t.Run("negative", func(t *testing.T) {
		err := New().Validate(context.Background(), `{"effect": "allow", "match": {"derived_tier": {"at_most": -1}}}`)
		if err == nil {
			t.Fatal("Validate accepted at_most: -1, want an error (no real tier is negative — this constraint could never match)")
		}
	})
	t.Run("above the highest tier", func(t *testing.T) {
		err := New().Validate(context.Background(), `{"effect": "allow", "match": {"derived_tier": {"at_most": 5}}}`)
		if err == nil {
			t.Fatal("Validate accepted at_most: 5, want an error (models.ActionTierDestructive is 4, the highest tier; 5 can only ever match everything)")
		}
	})

	// Positive control: the boundary values themselves — 0 and 4, both
	// inside the valid range — are not collateral damage from the range
	// check. TestEvaluate_DerivedTierAtMost's own "at_most at the top of
	// the valid range still matches" subtest is the sibling positive
	// control for "still matches"; this checks only the Validate half, and
	// covers both ends of the range.
	t.Run("boundary values are still accepted", func(t *testing.T) {
		for _, atMost := range []int{0, 4} {
			text := fmt.Sprintf(`{"effect": "allow", "match": {"derived_tier": {"at_most": %d}}}`, atMost)
			if err := New().Validate(context.Background(), text); err != nil {
				t.Errorf("Validate rejected at_most: %d (a valid boundary value): %v", atMost, err)
			}
		}
	})
}

func TestValidate_MissingAtMostIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"derived_tier": {}}}`)
	if err == nil {
		t.Fatal("Validate accepted a derived_tier constraint with no at_most, want an error")
	}
}

// TestValidate_UnknownAgentAttrIsRejected guards agent.attr's closed
// allow-list (see agentAttrValue's own doc comment): "enabled" is a real
// AgentInfo field but is not one this schema's match vocabulary exposes, so
// it must be rejected the same way a genuine typo would be — not silently
// accepted as "the attribute always resolves to the empty string, which
// never equals anything," a policy that reads as working but is quietly
// dead.
func TestValidate_UnknownAgentAttrIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"agent": {"attr": "enabled", "equals": "true"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown agent attr ("enabled" is not in the closed allow-list — see the package doc), want an error`)
	}
}

func TestValidate_UnknownDelegationAttrIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"delegation": {"attr": "depth", "equals": "1"}}}`)
	if err == nil {
		t.Fatal(`Validate accepted an unknown delegation attr ("depth" is not in the closed allow-list — see the package doc), want an error`)
	}
}

func TestValidate_EmptyAttrIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {"subject": {"attr": "", "equals": "finance"}}}`)
	if err == nil {
		t.Fatal("Validate accepted an empty attr name, want an error")
	}
}

// TestValidate_UnknownEffectIsRejected checks the brief's ABNF literally:
// "effect": "allow" | "deny" — exactly those two strings, nothing else.
func TestValidate_UnknownEffectIsRejected(t *testing.T) {
	cases := []struct {
		name   string
		effect string
	}{
		{"empty", ""},
		{"wrong case", "ALLOW"},
		{"different vocabulary", "permit"},
		{"trailing whitespace", "allow "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := fmt.Sprintf(`{"effect": %q, "match": {}}`, tc.effect)
			if err := New().Validate(context.Background(), text); err == nil {
				t.Fatalf("Validate accepted effect %q, want an error (only exactly \"allow\" or \"deny\" are legal)", tc.effect)
			}
		})
	}
}

func TestValidate_TrailingContentIsRejected(t *testing.T) {
	err := New().Validate(context.Background(), `{"effect": "allow", "match": {}} {"effect": "deny", "match": {}}`)
	if err == nil {
		t.Fatal("Validate accepted two JSON values concatenated, want an error — a StoredPolicy is one policy")
	}
}

// TestPrepare_NamesMalformedPolicy pins the same property
// policytest.EngineContract already checks (testPrepareNamesMalformedPolicy)
// against a schema-specific malformed shape: a syntactically valid JSON
// *object* that fails this schema's own semantic validation (a missing match
// block), rather than the shared contract's plain JSON syntax error. A
// Prepare that checked only the JSON decode error and skipped
// policyDoc-level validation would still be caught here, even though it
// would pass the contract's own Fixtures.Malformed (a real syntax error)
// undetected.
func TestPrepare_NamesMalformedPolicy(t *testing.T) {
	const (
		malformedID = "malformed-under-test"
		neighborID  = "well-formed-neighbor"
	)
	policies := []policy.StoredPolicy{
		{ID: neighborID, Name: "neighbor", Language: language, Text: `{"effect": "allow", "match": {}}`, Effect: "allow", Priority: 1, Version: 1},
		{ID: malformedID, Name: "quarantine-me", Language: language, Text: `{"effect": "allow"}`, Effect: "deny", Priority: 1, Version: 1},
	}
	_, err := New().Prepare(context.Background(), policies)
	if err == nil {
		t.Fatal("Prepare accepted a policy set containing a policy with no match block, want an error")
	}
	if !strings.Contains(err.Error(), malformedID) {
		t.Errorf("Prepare error does not name the offending policy's ID %q: %v", malformedID, err)
	}
	if strings.Contains(err.Error(), neighborID) {
		t.Errorf("Prepare error blames the well-formed neighbor %q instead of (or as well as) the offender: %v", neighborID, err)
	}
}
