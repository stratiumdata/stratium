package policy_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
)

// fakeEngine is a trivial PolicyEngine that exists only to prove
// EngineContract actually exercises the contract, before any real engine
// (Cedar, Task 4) exists to run it against. "Compiling" a policy set means
// validating each policy's text with the same balancedDelimiters check
// Validate uses, then snapshotting it — the contract requires Prepare to
// fail on malformed text and name the offending ID, same as any real
// engine, so this fake cannot skip that property just because doing so
// used to be free. "Evaluating" means turning each StoredPolicy's Text into
// a verdict via effectOfText — the same "derive effect from text, not from
// a separate stored field" choice every real engine makes (StoredPolicy no
// longer even has an Effect field to read instead, since nothing did); it
// otherwise ignores EvaluationInput entirely — there is no condition
// language here to evaluate it against.
//
// This lives in an external (package policy_test) file rather than an
// internal one because it calls policytest.EngineContract, and policytest
// itself imports policy for the interfaces it tests against. An internal
// test file (package policy) importing policytest would close that into an
// import cycle: policy -> policytest -> policy. Living in policy_test
// breaks the cycle the same way any other caller of policytest does — it is
// just an ordinary importer of both packages.
type fakeEngine struct{}

func (fakeEngine) Language() string { return "fake" }

func (fakeEngine) Prepare(_ context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	// Defensive copy: a caller that mutates the slice it passed in after
	// Prepare returns must not be able to change what a concurrently running
	// Evaluate sees. Built element-by-element, rather than copy() over a
	// pre-sized slice, so the malformed check below can bail out before
	// snapshotting the rest.
	snapshot := make([]policy.StoredPolicy, 0, len(policies))
	for _, p := range policies {
		if !balancedDelimiters(p.Text) {
			return nil, fmt.Errorf("fake: prepare policy %s (%q): malformed policy text (unbalanced delimiters): %q", p.ID, p.Name, p.Text)
		}
		if isVacuousEmptySet(p.Text) {
			return nil, fmt.Errorf("fake: prepare policy %s (%q): vacuous empty set (contains \"[]\", can never match): %q", p.ID, p.Name, p.Text)
		}
		snapshot = append(snapshot, p)
	}
	return fakeCompiledSet{policies: snapshot}, nil
}

func (fakeEngine) Validate(_ context.Context, text string) error {
	if !balancedDelimiters(text) {
		return fmt.Errorf("fake: malformed policy text (unbalanced delimiters): %q", text)
	}
	if isVacuousEmptySet(text) {
		return fmt.Errorf("fake: vacuous empty set (contains \"[]\", can never match): %q", text)
	}
	return nil
}

// isVacuousEmptySet reports whether text contains a literal empty bracket
// pair "[]" — balanced, so balancedDelimiters alone accepts it, but with
// nothing inside. This gives the fake's otherwise purely syntactic notion of
// "malformed" a second, semantic failure shape of its own: this trivial
// language's own miniature version of jsonpolicy's real "in": [] defect
// (schema.go) — text that reads as a working condition and can never match
// anything. policytest.EngineContract now requires every engine, including
// this fake one, to declare at least one such shape (see
// policytest.Fixtures.DeadForms); without this check, fakeEngine would have
// nothing behind it to reject, since its Evaluate ignores EvaluationInput
// entirely and every balanced-delimiter text it accepts already produces a
// verdict unconditionally.
func isVacuousEmptySet(text string) bool {
	return strings.Contains(text, "[]")
}

// balancedDelimiters stands in for real parsing. Every language this
// interface will eventually front (Cedar, Rego, JSON, XACML) treats
// mismatched (), {}, [] as a syntax error, so this is a cheap and honest way
// for a fake to tell "clearly broken" text from text worth taking seriously.
//
// ponytail: a real engine parses its own grammar; this exists only to give
// the fake a non-trivial notion of "malformed" for the contract test above.
func balancedDelimiters(text string) bool {
	pairs := map[rune]rune{')': '(', '}': '{', ']': '['}
	var stack []rune
	for _, r := range text {
		switch r {
		case '(', '{', '[':
			stack = append(stack, r)
		case ')', '}', ']':
			if len(stack) == 0 || stack[len(stack)-1] != pairs[r] {
				return false
			}
			stack = stack[:len(stack)-1]
		}
	}
	return len(stack) == 0
}

// fakeCompiledSet is fakeEngine's CompiledPolicySet: an immutable snapshot
// that concurrent Evaluate calls only ever read.
type fakeCompiledSet struct {
	policies []policy.StoredPolicy
}

func (f fakeCompiledSet) Evaluate(_ context.Context, _ policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	if len(f.policies) == 0 {
		return nil, nil
	}
	verdicts := make([]authz.PolicyVerdict, len(f.policies))
	for i, p := range f.policies {
		verdicts[i] = authz.PolicyVerdict{
			Effect:   effectOfText(p.Text),
			Reason:   "fake: " + p.Name,
			Source:   "fake",
			PolicyID: p.ID,
			Priority: p.Priority,
		}
	}
	return verdicts, nil
}

// effectOfText derives a verdict's effect from this fake language's own
// text, the same choice every real engine's own effectOf makes (jsonpolicy,
// xacml) or its equivalent parse step (Cedar's permit/forbid, Rego's allow/
// deny rules): "deny" appearing in the text means deny, anything else means
// allow. This fake DSL has no real grammar to speak of — every fixture text
// across this package and policytest/contract.go is just a label like "fake:
// allow-all" or "fake: deny-all" — but the property under test
// (policytest.EngineContract's AllowAll/DenyAll checks) is specifically that
// an engine's verdict tracks its policy text, so the fake has to earn that
// the same way a real engine would rather than being told the answer
// out-of-band.
func effectOfText(text string) authz.Effect {
	if strings.Contains(text, "deny") {
		return authz.EffectDeny
	}
	return authz.EffectAllow
}

func TestFakeEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, fakeEngine{}, policytest.Fixtures{
		Malformed:  "fake: (unbalanced",
		WellFormed: "fake: well-formed",
		AllowAll:   "fake: allow-all",
		DenyAll:    "fake: deny-all",
		DeadForms: []policytest.DeadForm{
			{
				Name:      "vacuous empty set",
				Dead:      "fake: matches nothing []",
				Live:      "fake: matches something [x]",
				LiveInput: policy.EvaluationInput{},
			},
		},
	})
}
