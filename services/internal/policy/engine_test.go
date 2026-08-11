package policy_test

import (
	"context"
	"fmt"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
)

// fakeEngine is a trivial PolicyEngine that exists only to prove
// EngineContract actually exercises the contract, before any real engine
// (Cedar, Task 4) exists to run it against. "Compiling" a policy set means
// snapshotting it; "evaluating" means turning each StoredPolicy's Effect
// into a verdict. It ignores EvaluationInput entirely — there is no
// condition language here to evaluate it against.
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
	// Evaluate sees.
	snapshot := make([]policy.StoredPolicy, len(policies))
	copy(snapshot, policies)
	return fakeCompiledSet{policies: snapshot}, nil
}

func (fakeEngine) Validate(_ context.Context, text string) error {
	if !balancedDelimiters(text) {
		return fmt.Errorf("fake: malformed policy text (unbalanced delimiters): %q", text)
	}
	return nil
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
		effect := authz.EffectDeny
		if p.Effect == "allow" {
			effect = authz.EffectAllow
		}
		verdicts[i] = authz.PolicyVerdict{
			Effect:   effect,
			Reason:   "fake: " + p.Name,
			Source:   "fake",
			PolicyID: p.ID,
			Priority: p.Priority,
		}
	}
	return verdicts, nil
}

func TestFakeEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, fakeEngine{}, policytest.Fixtures{
		Malformed:  "fake: (unbalanced",
		WellFormed: "fake: well-formed",
		AllowAll:   "fake: allow-all",
		DenyAll:    "fake: deny-all",
	})
}
