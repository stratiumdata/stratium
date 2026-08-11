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

// Fixtures supplies the language-specific policy text EngineContract needs.
// Every field is required; a zero value is a programming error, not a skip.
type Fixtures struct {
	// Malformed must fail Validate and Prepare.
	Malformed string
	// WellFormed must pass Validate. It is the positive control without which
	// an always-erroring Validate would satisfy Malformed too.
	WellFormed string
	// AllowAll and DenyAll must each match every input and carry their
	// respective effects. The concurrency check needs two policies that both
	// always match, so that a set of two always yields exactly two verdicts.
	AllowAll string
	DenyAll  string
}

// EngineContract is the reusable conformance suite every PolicyEngine
// implementation must pass. Cedar (internal/policy/cedar) and every engine
// after it call this same function against their own PolicyEngine and their
// own Fixtures, rather than each inventing its own version of these checks —
// spec defect D9 was this suite's fixtures being hardcoded Cedar syntax, so
// no other language could ever have passed it. A contract only one
// implementation can satisfy has never been tested as a contract.
//
// It exercises:
//
//  1. Prepare on a nil or empty policy list succeeds and evaluates to zero
//     verdicts — no policies is not an error.
//  2. Validate rejects Fixtures.Malformed and accepts Fixtures.WellFormed.
//  3. A prepared CompiledPolicySet is safe for concurrent Evaluate calls (run
//     this package under -race; that is what actually checks it).
func EngineContract(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()
	requireFixtures(t, f)

	testPrepareWithNoPolicies(t, engine)
	testValidate(t, engine, f)
	testConcurrentEvaluate(t, engine, f)
}

// requireFixtures fails fast on an incomplete Fixtures value. Every field
// backs a distinct property below; leaving one blank would silently
// exercise an engine with the empty string as policy text instead of
// failing loudly at the call site that forgot to set it — a wrong-for-the-
// wrong-reason pass (or failure) either way.
func requireFixtures(t *testing.T, f Fixtures) {
	t.Helper()
	for _, field := range []struct{ name, value string }{
		{"Malformed", f.Malformed},
		{"WellFormed", f.WellFormed},
		{"AllowAll", f.AllowAll},
		{"DenyAll", f.DenyAll},
	} {
		if field.value == "" {
			t.Fatalf("policytest.Fixtures.%s is empty — every field is required (see Fixtures' doc comment), not optional", field.name)
		}
	}
}

// testPrepareWithNoPolicies checks that a nil or empty policy list is a
// valid, zero-verdict input rather than an error — a tenant who has not
// authored any policies yet must not be indistinguishable from a broken
// engine.
func testPrepareWithNoPolicies(t *testing.T, engine policy.PolicyEngine) {
	t.Helper()
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
}

// testValidate checks Validate's two-sided contract using Fixtures.Malformed
// and Fixtures.WellFormed: reject text that cannot be prepared, accept text
// that can.
func testValidate(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()
	ctx := context.Background()

	t.Run("validate", func(t *testing.T) {
		// Validate takes only text — no StoredPolicy, no store handle — so
		// there is no way for it to persist anything by construction. Nothing
		// beyond the signature needs asserting for the "without persisting"
		// half of the contract.
		t.Run("rejects malformed text", func(t *testing.T) {
			if err := engine.Validate(ctx, f.Malformed); err == nil {
				t.Fatal("Validate accepted malformed text, want an error")
			}
		})

		t.Run("accepts well-formed text", func(t *testing.T) {
			// A positive control: without this, a Validate that always errors
			// would also pass the "rejects malformed text" case above.
			if err := engine.Validate(ctx, f.WellFormed); err != nil {
				t.Fatalf("Validate rejected well-formed text: %v", err)
			}
		})
	})
}

// testConcurrentEvaluate proves a prepared set is safe under concurrent
// Evaluate calls — the property policy.CompiledPolicySet's doc comment
// requires, because one prepared set serves every concurrent decision for a
// tenant. AllowAll and DenyAll are combined so a correct engine always
// returns exactly two verdicts per call; this property only means something
// run under -race (see the Makefile's `test` target).
func testConcurrentEvaluate(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()
	ctx := context.Background()

	t.Run("a prepared set is safe for concurrent evaluate", func(t *testing.T) {
		policies := []policy.StoredPolicy{
			{ID: "p1", Name: "allow-all", Language: engine.Language(), Text: f.AllowAll, Effect: "allow", Priority: 1, Version: 1},
			{ID: "p2", Name: "deny-all", Language: engine.Language(), Text: f.DenyAll, Effect: "deny", Priority: 2, Version: 1},
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
