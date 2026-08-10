// Package policytest provides EngineContract, the reusable conformance suite
// every policy.PolicyEngine implementation must pass.
//
// It lives in its own non-test package rather than in policy's own
// engine_test.go, because Go excludes _test.go files from what other
// packages may import — a contract defined there is reachable only from
// test files inside package policy itself. Cedar (internal/policy/cedar)
// and every engine after it live in subpackages and could not call it, so
// each would end up writing its own version of these checks — precisely the
// drift a shared contract exists to prevent. httptest is the same pattern
// for the same reason: it ships as its own importable package so test code
// outside net/http can still use it.
package policytest

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
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
func EngineContract(t *testing.T, engine policy.PolicyEngine) {
	ctx := context.Background()

	t.Run("prepare with no policies evaluates to zero verdicts, not an error", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			policies []policy.StoredPolicy
		}{
			{"nil", nil},
			{"empty", []policy.StoredPolicy{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				set, err := engine.Prepare(ctx, tc.policies)
				if err != nil {
					t.Fatalf("Prepare(%s) returned an error, want success: %v", tc.name, err)
				}
				if set == nil {
					t.Fatal("Prepare returned a nil CompiledPolicySet alongside a nil error")
				}

				verdicts, err := set.Evaluate(ctx, policy.EvaluationInput{})
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
		policies := []policy.StoredPolicy{
			{ID: "p1", Name: "allow-all", Language: engine.Language(), Text: "permit(principal, action, resource);", Effect: "allow", Priority: 1, Version: 1},
			{ID: "p2", Name: "deny-all", Language: engine.Language(), Text: "forbid(principal, action, resource);", Effect: "deny", Priority: 2, Version: 1},
		}
		set, err := engine.Prepare(ctx, policies)
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}

		const goroutines = 64
		const perGoroutine = 50
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "concurrent-user"}}

		var wg sync.WaitGroup
		errs := make(chan error, goroutines)
		wg.Add(goroutines)
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				for i := 0; i < perGoroutine; i++ {
					verdicts, err := set.Evaluate(ctx, in)
					if err != nil {
						errs <- fmt.Errorf("evaluate: %w", err)
						return
					}
					if len(verdicts) != len(policies) {
						errs <- fmt.Errorf("evaluate returned %d verdicts, want %d", len(verdicts), len(policies))
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
