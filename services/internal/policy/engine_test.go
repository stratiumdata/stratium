package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"stratium/internal/authz"
)

// EngineContract is the reusable conformance suite every PolicyEngine
// implementation must pass. It exercises the three properties a later engine
// will be judged against:
//
//  1. Prepare on a nil or empty policy list succeeds and evaluates to zero
//     verdicts — no policies is not an error.
//  2. A prepared CompiledPolicySet is safe for concurrent Evaluate calls (run
//     this package under -race; that is what actually checks it).
//  3. Validate rejects malformed policy text.
//
// Task 4's Cedar engine, and the further engines after it, call this same
// function against their own PolicyEngine rather than each inventing their
// own version of these checks.
func EngineContract(t *testing.T, engine PolicyEngine) {
	ctx := context.Background()

	t.Run("prepare with no policies evaluates to zero verdicts, not an error", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			policies []StoredPolicy
		}{
			{"nil", nil},
			{"empty", []StoredPolicy{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				set, err := engine.Prepare(ctx, tc.policies)
				if err != nil {
					t.Fatalf("Prepare(%s) returned an error, want success: %v", tc.name, err)
				}
				if set == nil {
					t.Fatal("Prepare returned a nil CompiledPolicySet alongside a nil error")
				}

				verdicts, err := set.Evaluate(ctx, EvaluationInput{})
				if err != nil {
					t.Fatalf("Evaluate on an empty prepared set returned an error, want success: %v", err)
				}
				if len(verdicts) != 0 {
					t.Fatalf("Evaluate on an empty prepared set returned %d verdicts, want 0", len(verdicts))
				}
			})
		}
	})

	t.Run("validate", func(t *testing.T) {
		// Validate takes only text — no StoredPolicy, no store handle — so
		// there is no way for it to persist anything by construction. Nothing
		// beyond the signature needs asserting for the "without persisting"
		// half of the contract.
		t.Run("rejects malformed text", func(t *testing.T) {
			const malformed = "permit(principal, action, resource) when { unbalanced ]["
			if err := engine.Validate(ctx, malformed); err == nil {
				t.Fatal("Validate accepted malformed text, want an error")
			}
		})

		t.Run("accepts well-formed text", func(t *testing.T) {
			// A positive control: without this, a Validate that always errors
			// would also pass the "rejects malformed text" case above.
			const wellFormed = "permit(principal, action, resource);"
			if err := engine.Validate(ctx, wellFormed); err != nil {
				t.Fatalf("Validate rejected well-formed text: %v", err)
			}
		})
	})

	t.Run("a prepared set is safe for concurrent evaluate", func(t *testing.T) {
		policies := []StoredPolicy{
			{ID: "p1", Name: "allow-all", Language: engine.Language(), Text: "permit(principal, action, resource);", Effect: "allow", Priority: 1, Version: 1},
			{ID: "p2", Name: "deny-all", Language: engine.Language(), Text: "forbid(principal, action, resource);", Effect: "deny", Priority: 2, Version: 1},
		}
		set, err := engine.Prepare(ctx, policies)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}

		const goroutines = 64
		const perGoroutine = 50
		in := EvaluationInput{Principal: authz.Principal{Subject: "concurrent-user"}}

		var wg sync.WaitGroup
		errs := make(chan error, goroutines)
		wg.Add(goroutines)
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				for i := 0; i < perGoroutine; i++ {
					verdicts, err := set.Evaluate(ctx, in)
					if err != nil {
						errs <- fmt.Errorf("Evaluate: %w", err)
						return
					}
					if len(verdicts) != len(policies) {
						errs <- fmt.Errorf("Evaluate returned %d verdicts, want %d", len(verdicts), len(policies))
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// fakeEngine is a trivial PolicyEngine that exists only to prove
// EngineContract above actually exercises the contract, before any real
// engine (Cedar, Task 4) exists to run it against. "Compiling" a policy set
// means snapshotting it; "evaluating" means turning each StoredPolicy's
// Effect into a verdict. It ignores EvaluationInput entirely — there is no
// condition language here to evaluate it against.
type fakeEngine struct{}

func (fakeEngine) Language() string { return "fake" }

func (fakeEngine) Prepare(_ context.Context, policies []StoredPolicy) (CompiledPolicySet, error) {
	// Defensive copy: a caller that mutates the slice it passed in after
	// Prepare returns must not be able to change what a concurrently running
	// Evaluate sees.
	snapshot := make([]StoredPolicy, len(policies))
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
	policies []StoredPolicy
}

func (f fakeCompiledSet) Evaluate(_ context.Context, _ EvaluationInput) ([]authz.PolicyVerdict, error) {
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
	EngineContract(t, fakeEngine{})
}
