package cedar

import (
	"context"
	"encoding/json"
	"testing"

	"stratium/internal/policy"
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
}

// TestCheckDeadForms_SkipsUnlessClauses pins why "unless" bodies are never
// inspected (see deadform.go's package doc): unless {X} requires !X, so a
// dead (always-false) X makes that unless clause vacuously true — a no-op,
// not a reason the policy can never match. Applying the "when" logic to
// "unless" unmodified would invert this and reject a policy that is, in
// fact, perfectly satisfiable.
func TestCheckDeadForms_SkipsUnlessClauses(t *testing.T) {
	text := `permit(principal, action, resource) unless { 1 == 2 };`
	parsed, err := parseOne("test", text)
	if err != nil {
		t.Fatalf("parseOne: %v", err)
	}
	if err := checkDeadForms(parsed); err != nil {
		t.Errorf("checkDeadForms rejected %q: %v (unless{1==2} means unless{false}, i.e. no constraint at all — this policy unconditionally permits)", text, err)
	}

	// Positive control: prove the fixture actually means what the comment
	// above claims, not just that checkDeadForms stayed quiet for some
	// unrelated reason — the unless-wrapped contradiction must still
	// evaluate to a real, matching verdict.
	set, err := (Engine{}).Prepare(context.Background(), []policy.StoredPolicy{
		{ID: "p1", Name: "unless-contradiction", Text: text, Effect: "allow", Priority: 1, Version: 1},
	})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1 — unless{1==2} does not narrow this policy at all", len(verdicts))
	}
}
