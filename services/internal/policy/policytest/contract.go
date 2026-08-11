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
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
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
//  4. Fixtures.AllowAll and Fixtures.DenyAll each match every input with
//     exactly one verdict, carrying EffectAllow and EffectDeny respectively.
//  5. Every verdict's Source is the engine's own Language(), and its
//     PolicyID is the producing StoredPolicy's ID — never a hardcoded
//     string, a display Name, or a slice index.
//  6. StoredPolicy.Priority round-trips into the verdict, and changing only
//     the priorities in a policy set changes none of the verdicts it
//     produces (spec Y7: priority is provenance, never combining logic).
//  7. Prepare on a policy set containing Fixtures.Malformed fails with the
//     offending policy's ID in the error, not just "a policy" — see
//     Fixtures.Malformed's own doc comment.
func EngineContract(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()
	requireFixtures(t, f)

	testPrepareWithNoPolicies(t, engine)
	testValidate(t, engine, f)
	testConcurrentEvaluate(t, engine, f)
	testAllowDenyEffects(t, engine, f)
	testVerdictProvenance(t, engine, f)
	testPriority(t, engine, f)
	testPrepareNamesMalformedPolicy(t, engine, f)
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

// mustPrepare prepares policies and fails the test immediately on error —
// the shared setup every property below needs before it can assert anything
// about the verdicts a set produces.
func mustPrepare(t *testing.T, engine policy.PolicyEngine, policies []policy.StoredPolicy) policy.CompiledPolicySet {
	t.Helper()
	set, err := engine.Prepare(context.Background(), policies)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return set
}

// mustEvaluate evaluates in against set and fails the test immediately on
// error.
func mustEvaluate(t *testing.T, set policy.CompiledPolicySet, in policy.EvaluationInput) []authz.PolicyVerdict {
	t.Helper()
	verdicts, err := set.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return verdicts
}

// probeInput names one EvaluationInput shape used to prove a fixture matches
// more than one coincidental input.
type probeInput struct {
	name string
	in   policy.EvaluationInput
}

// tierPtr returns a pointer to t. Action.DeclaredTier is *models.ActionTier,
// and Go cannot address a composite literal field's value directly.
func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

// probeInputs is deliberately more than one shape: a zero-value input and a
// fully populated one exercising every EvaluationInput dimension an engine
// might (wrongly) condition on. AllowAll and DenyAll are documented to match
// all of them — a single hardcoded probe would not catch a fixture
// accidentally scoped to it, e.g. a stray principal condition left over from
// copy-pasting a narrower fixture.
//
// Every field is set to a non-zero value, distinct from every other field's
// value. Both halves of that matter: a field left at its zero value in both
// probes makes "conditioned on this field being absent" indistinguishable
// from "genuinely unconditional" — either reading agrees on both probes, so
// a wrongly-conditional fixture still reports exactly one verdict for each
// and the gap passes undetected (mutation testing found exactly this: Cedar
// mutated to require a non-empty Delegation.ClassificationCaps survived here
// while that field was left nil in both probes). Distinct values matter
// separately: two fields sharing a value would not catch one being read in
// place of the other, the same reasoning behind the ID/Name fix in
// fb448be. Agent.Enabled and Agent.Suspended are the one unavoidable
// exception — bool has only one non-zero value, so both are true here;
// telling them apart is what the context-mapping tests (not this probe)
// are for.
func probeInputs() []probeInput {
	return []probeInput{
		{"zero-value input", policy.EvaluationInput{}},
		{"fully populated input", policy.EvaluationInput{
			Principal: authz.Principal{Subject: "probe-subject", Attributes: map[string]string{"dept": "eng"}},
			Action: authz.Action{
				Tool:            "Bash",
				Verb:            "write",
				RawInput:        "rm -rf /tmp/x",
				NormalizedInput: "probe-normalized-input",
				DeclaredTier:    tierPtr(models.ActionTierReadOnly),
			},
			DerivedTier: models.ActionTierDestructive,
			Resource:    map[string]string{"id": "res-1", "classification": "restricted"},
			Environment: map[string]string{"region": "us-east-1"},
			Agent: authz.AgentInfo{
				// A fixed UUID, not uuid.New(): every other value in this probe is
				// a stable literal, and a fixture that differs run to run makes a
				// failure harder to reproduce than it needs to be.
				ID:           uuid.MustParse("a5f1c2d3-0000-4000-8000-000000000001"),
				TrustTier:    models.TrustTierCertified,
				Enabled:      true,
				Suspended:    true,
				AllowedTools: []string{"probe-allowed-tool-a", "probe-allowed-tool-b"},
			},
			Delegation: policy.DelegationContext{
				Depth:              2,
				MaxActionTier:      models.ActionTierExternalComms,
				ClassificationCaps: map[string]string{"probe-classification-key": "probe-classification-value"},
				Purpose:            "quarterly-close",
			},
		}},
	}
}

// testAllowDenyEffects checks the positive control several other properties
// lean on: AllowAll and DenyAll each produce exactly one verdict, with the
// documented effect, regardless of what is being asked.
func testAllowDenyEffects(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()

	t.Run("AllowAll matches every input with exactly one EffectAllow verdict", func(t *testing.T) {
		requireUniformVerdict(t, engine, f.AllowAll, "allow", authz.EffectAllow)
	})

	t.Run("DenyAll matches every input with exactly one EffectDeny verdict", func(t *testing.T) {
		requireUniformVerdict(t, engine, f.DenyAll, "deny", authz.EffectDeny)
	})
}

// requireUniformVerdict prepares a single policy from text and asserts it
// produces exactly one verdict carrying wantEffect against every probeInput.
// storedEffect populates StoredPolicy.Effect alongside text: an engine may
// derive its verdict's effect from either one (Cedar reads only the Cedar
// text; the fake test engine in package policy reads only StoredPolicy.
// Effect), so a fixture author must keep the two in agreement — which
// AllowAll and DenyAll's own doc comment already requires.
//
// The PolicyID check matters even on the deny side: authz.EffectDeny is the
// zero value (see authz.Effect's doc comment), so an Effect-only assertion
// would also pass a completely unpopulated authz.PolicyVerdict{}. This
// project has shipped exactly that gap before — see cedar's
// TestEvaluate_DerivedTierReadableFromContextDrivesForbid for the same trap
// hit during Cedar's own development. Checking PolicyID forces the verdict
// under test to be the one this policy actually produced.
func requireUniformVerdict(t *testing.T, engine policy.PolicyEngine, text, storedEffect string, wantEffect authz.Effect) {
	t.Helper()
	// ID and Name deliberately differ, the same way testVerdictProvenance's
	// do: mutation-testing this suite found that an ID/Name mix-up survives
	// here if the fixture happens to use the same string for both (Name
	// silently substituted for ID still reads as "correct" when the two are
	// equal by coincidence).
	const wantID = "uniform-check"
	set := mustPrepare(t, engine, []policy.StoredPolicy{
		{ID: wantID, Name: "uniform-check-display-name", Language: engine.Language(), Text: text, Effect: storedEffect, Priority: 1, Version: 1},
	})

	for _, probe := range probeInputs() {
		t.Run(probe.name, func(t *testing.T) {
			verdicts := mustEvaluate(t, set, probe.in)
			if len(verdicts) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
			}
			if verdicts[0].PolicyID != wantID {
				t.Fatalf("PolicyID = %q, want %q", verdicts[0].PolicyID, wantID)
			}
			if verdicts[0].Effect != wantEffect {
				t.Errorf("Effect = %v, want %v", verdicts[0].Effect, wantEffect)
			}
		})
	}
}

// testVerdictProvenance checks the field audit provenance depends on most:
// every verdict must carry the engine's own Language() as Source and the
// producing StoredPolicy's ID as PolicyID. ID and Name are deliberately
// different strings below so a bug that reports the Name, or a slice index,
// instead of the ID fails loudly here rather than coincidentally matching.
func testVerdictProvenance(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()

	t.Run("every verdict names its source engine and its StoredPolicy's ID", func(t *testing.T) {
		const wantID = "provenance-id-should-appear-verbatim"
		set := mustPrepare(t, engine, []policy.StoredPolicy{
			{ID: wantID, Name: "a-completely-different-display-name", Language: engine.Language(), Text: f.AllowAll, Effect: "allow", Priority: 1, Version: 1},
		})

		verdicts := mustEvaluate(t, set, policy.EvaluationInput{Principal: authz.Principal{Subject: "someone"}})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}

		v := verdicts[0]
		if v.Source != engine.Language() {
			t.Errorf("Source = %q, want %q (engine.Language(), not a hardcoded string)", v.Source, engine.Language())
		}
		if v.PolicyID != wantID {
			t.Errorf("PolicyID = %q, want %q (the StoredPolicy's ID — never its Name, never a positional index)", v.PolicyID, wantID)
		}
	})
}

// testPriority checks spec Y7's guard as it applies to every engine:
// Priority is recorded on the verdict for provenance only, and is never
// consulted to decide which verdicts come back.
func testPriority(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()

	t.Run("priority round-trips from StoredPolicy into the verdict", func(t *testing.T) {
		// Nonzero: Priority's own zero value is a legitimate int, so a field
		// silently left unpopulated would misreport as a pass if this used 0.
		const wantPriority = 42
		set := mustPrepare(t, engine, []policy.StoredPolicy{
			{ID: "p1", Name: "allow-all", Language: engine.Language(), Text: f.AllowAll, Effect: "allow", Priority: wantPriority, Version: 1},
		})
		verdicts := mustEvaluate(t, set, policy.EvaluationInput{})
		if len(verdicts) != 1 {
			t.Fatalf("got %d verdicts, want 1: %+v", len(verdicts), verdicts)
		}
		if verdicts[0].Priority != wantPriority {
			t.Errorf("Priority = %d, want %d (StoredPolicy.Priority must round-trip into the verdict)", verdicts[0].Priority, wantPriority)
		}
	})

	t.Run("changing only priorities does not change the verdicts", func(t *testing.T) {
		build := func(allowPriority, denyPriority int) []policy.StoredPolicy {
			return []policy.StoredPolicy{
				{ID: "allow-leg", Name: "allow-all", Language: engine.Language(), Text: f.AllowAll, Effect: "allow", Priority: allowPriority, Version: 1},
				{ID: "deny-leg", Name: "deny-all", Language: engine.Language(), Text: f.DenyAll, Effect: "deny", Priority: denyPriority, Version: 1},
			}
		}
		in := policy.EvaluationInput{Principal: authz.Principal{Subject: "priority-probe"}}

		before := mustEvaluate(t, mustPrepare(t, engine, build(1, 2)), in)
		after := mustEvaluate(t, mustPrepare(t, engine, build(100, 1)), in)
		requireSameEffectsByPolicyID(t, before, after)
	})
}

// requireSameEffectsByPolicyID asserts before and after name the same set of
// PolicyIDs with the same Effect each, regardless of the order either slice
// happened to be returned in. The comparison is order-independent by design,
// not by oversight: Cedar's own Evaluate documents that its return order
// follows Go's (randomised) map iteration, unrelated to priority, so
// asserting on raw slice order here would fail for reasons that have
// nothing to do with the property under test. Sorting both sides by
// PolicyID first is what makes "same effects, same order, same count" a
// single comparison once the order either engine happened to return is
// canonicalised away.
func requireSameEffectsByPolicyID(t *testing.T, before, after []authz.PolicyVerdict) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatalf("got %d verdicts after re-prioritising, want %d (count changed): before=%+v after=%+v", len(after), len(before), before, after)
	}

	sortByPolicyID := func(vs []authz.PolicyVerdict) []authz.PolicyVerdict {
		sorted := make([]authz.PolicyVerdict, len(vs))
		copy(sorted, vs)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].PolicyID < sorted[j].PolicyID })
		return sorted
	}
	beforeSorted, afterSorted := sortByPolicyID(before), sortByPolicyID(after)

	for i := range beforeSorted {
		if beforeSorted[i].PolicyID != afterSorted[i].PolicyID || beforeSorted[i].Effect != afterSorted[i].Effect {
			t.Errorf("verdict %d changed after re-prioritising: before={PolicyID:%q Effect:%v} after={PolicyID:%q Effect:%v} — priority is provenance only (spec Y7) and must not change which policies match or their effects",
				i, beforeSorted[i].PolicyID, beforeSorted[i].Effect, afterSorted[i].PolicyID, afterSorted[i].Effect)
		}
	}
}

// testPrepareNamesMalformedPolicy checks Prepare's own error path.
// Rejecting bad text is not enough on its own — testValidate already proves
// an engine can tell malformed text apart from well-formed — the error must
// say which policy, by ID, so an operator with forty policies knows which
// one to fix rather than being told only that "a policy" broke.
//
// Fixtures.WellFormed is prepared alongside Fixtures.Malformed in the same
// call so the test can also confirm the error does not misattribute the
// well-formed neighbor: without that half, a Prepare that dumped every
// policy's ID into every error message would pass an ID-only check by
// accident, without ever actually identifying the offender.
func testPrepareNamesMalformedPolicy(t *testing.T, engine policy.PolicyEngine, f Fixtures) {
	t.Helper()

	t.Run("prepare on malformed text fails and names the offending policy's ID", func(t *testing.T) {
		const (
			malformedID = "malformed-under-test"
			neighborID  = "well-formed-neighbor"
		)
		policies := []policy.StoredPolicy{
			{ID: neighborID, Name: "neighbor", Language: engine.Language(), Text: f.WellFormed, Effect: "allow", Priority: 1, Version: 1},
			{ID: malformedID, Name: "quarantine-me", Language: engine.Language(), Text: f.Malformed, Effect: "deny", Priority: 1, Version: 1},
		}

		_, err := engine.Prepare(context.Background(), policies)
		if err == nil {
			t.Fatal("Prepare accepted a policy set containing malformed text, want an error")
		}
		if !strings.Contains(err.Error(), malformedID) {
			t.Errorf("Prepare error does not name the offending policy's ID %q: %v", malformedID, err)
		}
		if strings.Contains(err.Error(), neighborID) {
			t.Errorf("Prepare error blames the well-formed neighbor %q instead of (or as well as) the offender: %v", neighborID, err)
		}
	})
}
