package cedar

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
)

// firstWhenBody parses text (expected to be exactly one policy with exactly
// one "when" clause) and returns that clause's body as the same
// json.RawMessage shape checkDeadForms itself extracts and passes to each
// leaf check — deriving test input from cedar-go's own real parser and
// marshaler, the same as production code does, rather than hand-writing raw
// JSON that could silently drift from what cedar-go actually emits.
func firstWhenBody(t *testing.T, text string) json.RawMessage {
	t.Helper()
	parsed, err := parseOne("test", text)
	if err != nil {
		t.Fatalf("parseOne(%q): %v", text, err)
	}
	body, err := parsed.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	var doc policyJSON
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, c := range doc.Conditions {
		if c.Kind == "when" {
			return c.Body
		}
	}
	t.Fatalf("text %q has no when clause", text)
	return nil
}

// TestCheckEmptySetMembership_BothShapes directly exercises both branches
// checkEmptySetMembership recognizes. Mutation testing this package (see
// the task report) found that the Fixtures.DeadForms entry for "vacuous
// empty set" — [].contains(...) only — left the `in []` branch completely
// unexercised: disabling it caused no test anywhere to fail. This test
// closes that gap directly, rather than adding a second DeadForms entry for
// a shape the task's own thirteen audited forms don't separately name.
func TestCheckEmptySetMembership_BothShapes(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		wantErr bool
	}{
		{"in empty set is rejected", `permit(principal, action, resource) when { resource in [] };`, true},
		{"contains on empty set is rejected", `permit(principal, action, resource) when { [].contains(context.agent.trust_tier) };`, true},
		// Positive controls: the same two shapes with a non-empty set must
		// not be rejected by this check — without these, a checker that
		// rejected every `in` or `.contains(...)` outright would also pass
		// the two cases above.
		{"in non-empty set is accepted", `permit(principal, action, resource) when { resource in [User::"bob"] };`, false},
		{"contains on non-empty set is accepted", `permit(principal, action, resource) when { ["CERTIFIED"].contains(context.agent.trust_tier) };`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkEmptySetMembership(firstWhenBody(t, tc.text))
			if tc.wantErr && err == nil {
				t.Errorf("checkEmptySetMembership(%q) = nil, want an error", tc.text)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("checkEmptySetMembership(%q) = %v, want nil", tc.text, err)
			}
		})
	}
}

// TestCheckTierVocabulary_OperandOrderIndependent guards pathAndLiteral's
// own reason for existing: Cedar's == does not care which side of the
// operator the path or the literal is written on, so an author who wrote
// the comparison backwards ("Certified" == context.agent.trust_tier)  must
// be caught exactly the same as the conventional order. A check that only
// ever inspected b.Left would silently miss every policy written this way.
func TestCheckTierVocabulary_OperandOrderIndependent(t *testing.T) {
	const reversed = `permit(principal, action, resource) when { "Certified" == context.agent.trust_tier };`
	if err := checkTierVocabulary(firstWhenBody(t, reversed)); err == nil {
		t.Errorf("checkTierVocabulary(%q) = nil, want an error (reversed operand order must still be caught)", reversed)
	}
}

// TestCheckLiteralContradiction_NonScalarLiteralsDoNotPanic guards a real
// bug found during this task's own mutation testing, not a hypothetical
// one: `User::"a" == User::"b"` is ordinary, valid Cedar — an entity-UID
// literal compared for equality inside a when clause, not a scope clause —
// and it marshals to {"Value": {"__entity": {...}}} on both sides.
// literalValue happily decodes that to a Go map[string]any, and an earlier
// version of checkLiteralContradiction compared the two decoded values with
// == unconditionally; Go panics comparing two uncomparable map values.
// Confirmed empirically before the scalarLiteral guard was added: this
// exact fixture crashed the test binary. Every check in this file must
// reject-or-accept every syntactically valid Cedar policy; none may panic
// on one, since Validate exists specifically to run on arbitrary,
// untrusted-shaped policy author input.
func TestCheckLiteralContradiction_NonScalarLiteralsDoNotPanic(t *testing.T) {
	tests := []string{
		`permit(principal, action, resource) when { User::"a" == User::"b" };`,
		`permit(principal, action, resource) when { [1, 2] == [1, 2] };`,
		`permit(principal, action, resource) when { {a: 1} == {a: 1} };`,
	}
	for _, text := range tests {
		t.Run(text, func(t *testing.T) {
			// The assertion is simply that this returns rather than panics
			// — checkLiteralContradiction declines to reason about
			// non-scalar literal equality at all (see its own doc comment
			// for why), so nil is the only correct answer here regardless
			// of what a full entity/collection-equality analysis would
			// eventually conclude.
			if err := checkLiteralContradiction(firstWhenBody(t, text)); err != nil {
				t.Errorf("checkLiteralContradiction(%q) = %v, want nil (this check does not reason about non-scalar literals)", text, err)
			}
		})
	}

	// The same property matters end to end, through the real entry point
	// every StoredPolicy actually goes through — not only when
	// checkLiteralContradiction is called directly above.
	t.Run("Validate does not panic on an entity-literal comparison", func(t *testing.T) {
		if err := (Engine{}).Validate(context.Background(), `permit(principal, action, resource) when { User::"a" == User::"b" };`); err != nil {
			t.Errorf("Validate = %v, want nil", err)
		}
	})
}

// TestConjuncts_StopsAtOrAndNot pins the safety property deadform.go's
// package doc calls "required, not merely conservative": conjuncts must
// unwrap && all the way down, but must treat || and ! as opaque leaves
// rather than recursing into them. Getting this backwards — even
// accidentally recursing one level into an || — would make checkDeadForms
// reject policies that are still genuinely satisfiable through their other
// disjunct, which this task's fail-closed constraint explicitly forbids.
// This applies identically to "when" and "unless" clause bodies (see
// deadform.go's package doc, "Why only through &&, for either clause
// kind") — the last two subtests below pin both.
func TestConjuncts_StopsAtOrAndNot(t *testing.T) {
	t.Run("&& decomposes into its two conjuncts", func(t *testing.T) {
		body := firstWhenBody(t, `permit(principal, action, resource) when { 1 == 1 && 2 == 2 };`)
		if got := len(conjuncts(body)); got != 2 {
			t.Fatalf("got %d conjuncts, want 2", got)
		}
	})

	t.Run("|| is not decomposed", func(t *testing.T) {
		body := firstWhenBody(t, `permit(principal, action, resource) when { 1 == 2 || 3 == 3 };`)
		if got := len(conjuncts(body)); got != 1 {
			t.Fatalf("got %d conjuncts, want 1 (|| must not be unwrapped)", got)
		}
	})

	t.Run("! is not decomposed", func(t *testing.T) {
		body := firstWhenBody(t, `permit(principal, action, resource) when { !(1 == 2) };`)
		if got := len(conjuncts(body)); got != 1 {
			t.Fatalf("got %d conjuncts, want 1 (! must not be unwrapped)", got)
		}
	})

	// The property that actually matters end to end, not just the internal
	// conjuncts() helper: a dead subexpression buried inside an || must not
	// make checkDeadForms reject the whole (still genuinely live) policy.
	t.Run("a dead conjunct under || does not reject the policy", func(t *testing.T) {
		text := `permit(principal, action, resource) when { context.agent.trust_tier == "CERTIFIED" || 1 == 2 };`
		parsed, err := parseOne("test", text)
		if err != nil {
			t.Fatalf("parseOne: %v", err)
		}
		if err := checkDeadForms(parsed); err != nil {
			t.Errorf("checkDeadForms rejected a policy with a live || arm: %v (over-rejection: the contradiction is buried inside ||, where the other arm can still make the policy match)", err)
		}
	})

	// The unless-side twin of the subtest above, and the "give it a test
	// either way" half of this task's Critical fix: a dead disjunct inside
	// an unless body must not be rejected either. Derived independently,
	// not assumed identical to the when-side case: an unless body Y is
	// only a fail-open widening when Y is always false (see deadform.go's
	// package doc), and `real || dead` is not always false — it is exactly
	// as true as `real` alone, so this exception still genuinely narrows
	// the policy whenever `real` holds. Rejecting it here would be the
	// same over-rejection the when-side subtest above guards against, one
	// clause kind over.
	t.Run("a dead conjunct under || inside unless does not reject the policy", func(t *testing.T) {
		text := `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" || 1 == 2 };`
		parsed, err := parseOne("test", text)
		if err != nil {
			t.Fatalf("parseOne: %v", err)
		}
		if err := checkDeadForms(parsed); err != nil {
			t.Errorf("checkDeadForms rejected a policy with a live || arm inside unless: %v (over-rejection: the other disjunct can still make the exception trigger)", err)
		}
	})
}

// TestCheckDeadForms_RejectsDeadConjunctInUnlessClauses pins this task's
// Critical fix: a dead (always-false) conjunct inside an "unless" body used
// to be silently accepted — an earlier version of this file reasoned it was
// a harmless no-op ("unless{1==2} means unless{false}, i.e. no constraint
// at all"). That reasoning was correct about whether the clause holds and
// wrong about what that means: unless{false} does not add "no constraint,"
// it deletes whatever restriction the author intended the clause to
// express — a fail-open widening, not a no-op. See deadform.go's package
// doc, "Why only through &&, for either clause kind," for the full
// derivation this test pins.
func TestCheckDeadForms_RejectsDeadConjunctInUnlessClauses(t *testing.T) {
	text := `permit(principal, action, resource) unless { 1 == 2 };`
	parsed, err := parseOne("test", text)
	if err != nil {
		t.Fatalf("parseOne: %v", err)
	}
	if err := checkDeadForms(parsed); err == nil {
		t.Errorf("checkDeadForms accepted %q, want an error — unless{1==2} means unless{false}, which deletes this policy's own restriction instead of narrowing it", text)
	}

	// The same property through the real entry point every StoredPolicy
	// actually goes through, not only when checkDeadForms is called
	// directly above — Prepare must reject it too, naming the offender.
	_, err = (Engine{}).Prepare(context.Background(), []policy.StoredPolicy{
		{ID: "unless-contradiction", Name: "unless-contradiction", Text: text, Priority: 1, Version: 1},
	})
	if err == nil {
		t.Fatal("Prepare accepted a dead conjunct inside an unless clause, want an error")
	}
	if !strings.Contains(err.Error(), "unless-contradiction") {
		t.Errorf("Prepare error does not name the offending policy: %v", err)
	}
}

// TestCheckDeadForms_UnlessReachesEveryLeafCheck proves the fix generalizes
// to all four leaf checks, not only checkLiteralContradiction (the one
// TestCheckDeadForms_RejectsDeadConjunctInUnlessClauses above exercises).
// checkTierVocabulary and checkDerivedTierComparison are pinned under
// unless by the "unless:"-prefixed entries in Fixtures.DeadForms
// (engine_test.go) via the shared contract; checkEmptySetMembership has no
// dedicated DeadForms entry of its own (see
// TestCheckEmptySetMembership_BothShapes' own doc comment for why one
// shape of it doesn't get a second contract entry either), so without this
// test, checkEmptySetMembership never being reached for an unless body at
// all would cause no test anywhere to fail.
func TestCheckDeadForms_UnlessReachesEveryLeafCheck(t *testing.T) {
	text := `permit(principal, action, resource) unless { [].contains(context.agent.trust_tier) };`
	parsed, err := parseOne("test", text)
	if err != nil {
		t.Fatalf("parseOne: %v", err)
	}
	if err := checkDeadForms(parsed); err == nil {
		t.Errorf("checkDeadForms accepted %q, want an error (checkEmptySetMembership must be reached for unless bodies too)", text)
	}
}

// TestCheckDeadForms_UnlessExceptionStillNarrowsBothWays is the positive
// control for the fix above: a REAL (non-dead) unless clause must still
// narrow a permit policy in both directions — refusing to match when its
// exception applies, matching normally when it does not. Without this,
// rejecting the dead form alone would not distinguish "the checker now
// correctly rejects dead unless bodies" from "the checker now rejects
// unless clauses in general," which would itself be a different
// over-rejection bug.
func TestCheckDeadForms_UnlessExceptionStillNarrowsBothWays(t *testing.T) {
	text := `permit(principal, action, resource) unless { context.agent.trust_tier == "CERTIFIED" };`
	set, err := (Engine{}).Prepare(context.Background(), []policy.StoredPolicy{
		{ID: "p1", Name: "real-exception", Text: text, Priority: 1, Version: 1},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	for _, tc := range []struct {
		name        string
		trustTier   models.AgentTrustTier
		wantMatched bool
	}{
		{"exception applies: a CERTIFIED agent does not match", models.TrustTierCertified, false},
		{"exception does not apply: an UNVERIFIED agent matches", models.TrustTierUnverified, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{
				Agent: authz.AgentInfo{TrustTier: tc.trustTier},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if matched := len(verdicts) > 0; matched != tc.wantMatched {
				t.Errorf("got %d verdicts (matched=%v), want matched=%v", len(verdicts), matched, tc.wantMatched)
			}
		})
	}
}
