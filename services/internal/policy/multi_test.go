package policy

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"stratium/internal/authz"
)

// fakeAllSource is an AllPolicySource test double, the Multi-focused sibling
// of stubSource (configured_test.go). gotCalls counts LoadAllPolicies
// invocations so a test can pin "one load per PrepareAll call."
type fakeAllSource struct {
	policies []StoredPolicy
	err      error
	gotCalls *int
}

func (f fakeAllSource) LoadAllPolicies(context.Context) ([]StoredPolicy, error) {
	if f.gotCalls != nil {
		*f.gotCalls++
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.policies, nil
}

// verdictIDs returns the PolicyIDs of vs, in order — the compact form most
// of the assertions below compare, since exact Reason text is checked
// separately where it matters (the D10 orphan test).
func verdictIDs(vs []authz.PolicyVerdict) []string {
	ids := make([]string, len(vs))
	for i, v := range vs {
		ids[i] = v.PolicyID
	}
	return ids
}

// TestMulti_LanguageWithRegisteredEngineEvaluatesNormally defends the base
// case every other property is a variation on: a language with policies and
// a registered engine is prepared and evaluated, and its verdicts pass
// through unchanged.
func TestMulti_LanguageWithRegisteredEngineEvaluatesNormally(t *testing.T) {
	want := []authz.PolicyVerdict{{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "p1"}}
	source := fakeAllSource{policies: []StoredPolicy{{ID: "p1", Language: "cedar"}}}
	engines := Registry{"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: want}}}

	got := NewMulti(source, engines).Evaluate(context.Background(), EvaluationInput{})
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("Evaluate() = %+v, want %+v (verdicts must pass through unchanged)", got, want)
	}
}

// TestMulti_OrphanLanguageDeniesNamingLanguageAndPolicyIDs is D10 — the
// reason this task exists. A language with policies and no registered
// engine must never be silently skipped: it must produce exactly one deny
// verdict, and that verdict's Reason must name the language and every
// policy id left unevaluated, not just its Effect. An operator who authored
// a rego rule this deployment cannot run needs to learn that from the
// denial text itself.
func TestMulti_OrphanLanguageDeniesNamingLanguageAndPolicyIDs(t *testing.T) {
	source := fakeAllSource{policies: []StoredPolicy{
		{ID: "orphan-1", Language: "rego"},
		{ID: "orphan-2", Language: "rego"},
	}}
	// No "rego" entry in the registry at all — an empty Registry, not nil,
	// to prove the zero value isn't doing the work by accident.
	got := NewMulti(source, Registry{}).Evaluate(context.Background(), EvaluationInput{})

	if len(got) != 1 {
		t.Fatalf("Evaluate() = %d verdicts, want exactly 1 (never skipped, never split per policy): %+v", len(got), got)
	}
	v := got[0]
	if v.Effect != authz.EffectDeny {
		t.Fatalf("Effect = %v, want EffectDeny", v.Effect)
	}
	if v.Source != "rego" {
		t.Errorf("Source = %q, want %q", v.Source, "rego")
	}
	if !strings.Contains(v.Reason, "rego") {
		t.Errorf("Reason = %q, want it to name the orphaned language %q", v.Reason, "rego")
	}
	for _, id := range []string{"orphan-1", "orphan-2"} {
		if !strings.Contains(v.Reason, id) {
			t.Errorf("Reason = %q, want it to name unevaluated policy id %q", v.Reason, id)
		}
	}
}

// TestMulti_RegisteredEngineWithNoPoliciesContributesNothing defends the
// other half of D10's subtlety: having no opinion is different from
// denying. A registered engine for a language the tenant simply has not
// authored any policies in must not appear in the output at all — not as an
// allow, not as a deny. FoldVerdicts' own default-deny is what turns "no
// verdicts at all" into a denial downstream; this engine must not
// pre-empt that by manufacturing one of its own.
func TestMulti_RegisteredEngineWithNoPoliciesContributesNothing(t *testing.T) {
	// cedar has policies; rego is registered but the tenant authored nothing
	// in it — the case under test.
	source := fakeAllSource{policies: []StoredPolicy{{ID: "p1", Language: "cedar"}}}
	engines := Registry{
		"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "p1"},
		}}},
		"rego": stubEngine{language: "rego", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectDeny, Source: "rego", PolicyID: "should-never-appear"},
		}}},
	}

	got := NewMulti(source, engines).Evaluate(context.Background(), EvaluationInput{})
	if len(got) != 1 {
		t.Fatalf("Evaluate() = %d verdicts, want exactly 1 (only cedar's, rego contributes nothing): %+v", len(got), got)
	}
	if got[0].Source != "cedar" {
		t.Errorf("Source = %q, want %q — rego's registered-but-unused engine must not appear", got[0].Source, "cedar")
	}
}

// TestMulti_ZeroPoliciesTotalDeniesWithoutNamingALanguage keeps Configured's
// existing single deny for a tenant with no policies anywhere, but the
// message must no longer name one language's absence — it is tenant-wide
// now, not the absence of any one engine's policies.
func TestMulti_ZeroPoliciesTotalDeniesWithoutNamingALanguage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []StoredPolicy
	}{
		{"nil", nil},
		{"empty", []StoredPolicy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NewMulti(fakeAllSource{policies: tc.policies}, Registry{"cedar": stubEngine{language: "cedar"}}).
				Evaluate(context.Background(), EvaluationInput{})
			if len(got) != 1 {
				t.Fatalf("Evaluate() with no policies = %d verdicts, want exactly 1: %+v", len(got), got)
			}
			v := got[0]
			const want = "principal: no policies configured for this tenant"
			if v.Reason != want {
				t.Errorf("Reason = %q, want %q verbatim", v.Reason, want)
			}
			if v.Effect != authz.EffectDeny {
				t.Errorf("Effect = %v, want EffectDeny", v.Effect)
			}
		})
	}
}

// TestMulti_PrepareFailureDeniesNamingLanguageWithoutSuppressingOthers: one
// language's engine failing to compile must not take down the others. Cedar
// still evaluates and its allow is still visible in the returned set;
// rego's failure is reported as its own deny, naming rego.
func TestMulti_PrepareFailureDeniesNamingLanguageWithoutSuppressingOthers(t *testing.T) {
	prepareErr := errors.New("boom: malformed rego")
	source := fakeAllSource{policies: []StoredPolicy{
		{ID: "cedar-1", Language: "cedar"},
		{ID: "rego-1", Language: "rego"},
	}}
	engines := Registry{
		"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "cedar-1"},
		}}},
		"rego": stubEngine{language: "rego", prepareErr: prepareErr},
	}

	m := NewMulti(source, engines)
	set, err := m.PrepareAll(context.Background())
	if err == nil {
		t.Fatal("PrepareAll() error = nil, want a non-nil error naming the language that failed to prepare")
	}
	if !strings.Contains(err.Error(), "rego") {
		t.Errorf("PrepareAll() error = %q, want it to name %q", err.Error(), "rego")
	}
	if set == nil {
		t.Fatal("PrepareAll() set = nil, want a usable partial set even when one language failed to prepare")
	}

	verdicts, evalErr := set.Evaluate(context.Background(), EvaluationInput{})
	if evalErr != nil {
		t.Fatalf("set.Evaluate() error = %v, want nil — per-language failures are folded into verdicts, not propagated", evalErr)
	}
	if len(verdicts) != 2 {
		t.Fatalf("set.Evaluate() = %d verdicts, want 2 (cedar's real verdict + rego's prepare-failure deny): %+v", len(verdicts), verdicts)
	}

	var cedarVerdict, regoVerdict *authz.PolicyVerdict
	for i := range verdicts {
		switch verdicts[i].Source {
		case "cedar":
			cedarVerdict = &verdicts[i]
		case "rego":
			regoVerdict = &verdicts[i]
		}
	}
	if cedarVerdict == nil || cedarVerdict.Effect != authz.EffectAllow {
		t.Errorf("cedar's verdict = %+v, want a surviving EffectAllow — rego's outage must not suppress it", cedarVerdict)
	}
	if regoVerdict == nil || regoVerdict.Effect != authz.EffectDeny {
		t.Fatalf("rego's verdict = %+v, want an EffectDeny naming its prepare failure", regoVerdict)
	}
	if !strings.Contains(regoVerdict.Reason, "rego") || !strings.Contains(regoVerdict.Reason, prepareErr.Error()) {
		t.Errorf("rego verdict Reason = %q, want it to name the language and the underlying error %q", regoVerdict.Reason, prepareErr.Error())
	}

	// Evaluate (the PrincipalPolicy-facing method) must also see both: the
	// non-nil PrepareAll error must not turn into a blanket deny that drops
	// cedar's allow — see PrepareAll's own doc comment on why a non-nil set
	// is used regardless of a non-nil err.
	principalVerdicts := m.Evaluate(context.Background(), EvaluationInput{})
	if len(principalVerdicts) != 2 {
		t.Fatalf("Multi.Evaluate() = %d verdicts, want 2 (PrepareAll's error must not collapse this to a single generic deny): %+v", len(principalVerdicts), principalVerdicts)
	}
}

// TestMulti_EvaluateFailureDeniesNamingLanguageWithoutSuppressingOthers is
// the evaluate-time sibling of the prepare-time test above: cedar prepares
// and evaluates fine, rego prepares fine but its Evaluate call itself
// fails. The failure must surface as rego's own deny, and cedar's verdict
// must still be present.
func TestMulti_EvaluateFailureDeniesNamingLanguageWithoutSuppressingOthers(t *testing.T) {
	evalErr := errors.New("boom: rego evaluator unreachable")
	source := fakeAllSource{policies: []StoredPolicy{
		{ID: "cedar-1", Language: "cedar"},
		{ID: "rego-1", Language: "rego"},
	}}
	engines := Registry{
		"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "cedar-1"},
		}}},
		"rego": stubEngine{language: "rego", set: stubSet{err: evalErr}},
	}

	got := NewMulti(source, engines).Evaluate(context.Background(), EvaluationInput{})
	if len(got) != 2 {
		t.Fatalf("Evaluate() = %d verdicts, want 2 (cedar's real verdict + rego's evaluate-failure deny): %+v", len(got), got)
	}

	var cedarVerdict, regoVerdict *authz.PolicyVerdict
	for i := range got {
		switch got[i].Source {
		case "cedar":
			cedarVerdict = &got[i]
		case "rego":
			regoVerdict = &got[i]
		}
	}
	if cedarVerdict == nil || cedarVerdict.Effect != authz.EffectAllow {
		t.Errorf("cedar's verdict = %+v, want a surviving EffectAllow", cedarVerdict)
	}
	if regoVerdict == nil || regoVerdict.Effect != authz.EffectDeny {
		t.Fatalf("rego's verdict = %+v, want an EffectDeny naming its evaluate failure", regoVerdict)
	}
	if !strings.Contains(regoVerdict.Reason, "rego") || !strings.Contains(regoVerdict.Reason, evalErr.Error()) {
		t.Errorf("rego verdict Reason = %q, want it to name the language and the underlying error %q", regoVerdict.Reason, evalErr.Error())
	}
}

// TestMulti_PrepareAllTotalLoadFailureReturnsNilSetAndError is the one case
// where PrepareAll's returned set is unusable: the tenant's policies could
// not even be loaded, so nothing is known about what languages exist.
// Evaluate must fold this into a single deny rather than panicking on a nil
// set.
func TestMulti_PrepareAllTotalLoadFailureReturnsNilSetAndError(t *testing.T) {
	loadErr := errors.New("boom: connection refused")
	m := NewMulti(fakeAllSource{err: loadErr}, Registry{"cedar": stubEngine{language: "cedar"}})

	set, err := m.PrepareAll(context.Background())
	if set != nil {
		t.Errorf("PrepareAll() set = %v, want nil when loading policies fails outright", set)
	}
	if err == nil {
		t.Fatal("PrepareAll() error = nil, want a non-nil error")
	}

	got := m.Evaluate(context.Background(), EvaluationInput{})
	if len(got) != 1 {
		t.Fatalf("Evaluate() = %d verdicts, want exactly 1: %+v", len(got), got)
	}
	if got[0].Effect != authz.EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny (fail closed on a total load failure)", got[0].Effect)
	}
	if !strings.Contains(got[0].Reason, loadErr.Error()) {
		t.Errorf("Reason = %q, want it to contain the underlying error %q", got[0].Reason, loadErr.Error())
	}
}

// TestMulti_VerdictOrderIsDeterministicAcrossCalls defends the ordering
// contract directly: languages sorted, and within a language, policies
// sorted by id — regardless of what order a sub-engine's own Evaluate
// happens to return them in (Cedar's documented map-order caveat is exactly
// what this guards against). Two languages are used, each returning its
// policies in an order deliberately reversed from sorted.
//
// The 5-call loop only proves "re-sorts every call, not just once" because
// each stubEngine's stubSet hands back the exact same backing array on
// every call (stubSet.Evaluate returns s.verdicts directly, unmodified).
// That property depends on multiSet.Evaluate never mutating a sub-engine's
// own slice: before the fix that sorts a copy appended into verdicts
// instead of sorting vs in place, the first call's in-place sort left the
// stub's shared array permanently ordered, so calls 2-5 received
// already-sorted input and would have passed even if multiSet stopped
// sorting entirely after call 1 — the loop was not actually exercising
// "re-sorts every call" pre-fix, only "sorts once." Now that the sub-engine's
// own slice is never touched, every call independently receives the same
// reversed input and must independently re-sort it.
func TestMulti_VerdictOrderIsDeterministicAcrossCalls(t *testing.T) {
	source := fakeAllSource{policies: []StoredPolicy{
		{ID: "z-cedar", Language: "cedar"},
		{ID: "a-cedar", Language: "cedar"},
		{ID: "z-rego", Language: "rego"},
		{ID: "a-rego", Language: "rego"},
	}}
	// Each sub-engine hands back its own two verdicts in id-descending
	// order — the opposite of what a correct multiSet must report them in —
	// so a passing test proves multiSet re-sorts rather than merely
	// happening to preserve an already-sorted input.
	engines := Registry{
		"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "z-cedar"},
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "a-cedar"},
		}}},
		"rego": stubEngine{language: "rego", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectDeny, Source: "rego", PolicyID: "z-rego"},
			{Effect: authz.EffectDeny, Source: "rego", PolicyID: "a-rego"},
		}}},
	}
	want := []string{"a-cedar", "z-cedar", "a-rego", "z-rego"}

	m := NewMulti(source, engines)
	for i := 0; i < 5; i++ {
		got := verdictIDs(m.Evaluate(context.Background(), EvaluationInput{}))
		if !equalStrings(got, want) {
			t.Fatalf("call %d: verdict order = %v, want %v (languages sorted, ids sorted within a language)", i, got, want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestMulti_PrepareAllCalledOncePerEvaluate pins that Evaluate does not
// recompile: exactly one LoadAllPolicies call (and, by construction, one
// Prepare call per language — stubEngine.Prepare panics on no fixture to
// return here, so this only asserts the load count, which is the shared
// entry point every recompile-per-call bug would also hit) per Evaluate
// call. This is D5's rule restated for Multi: Prepare compiles once,
// Evaluate must not compile.
func TestMulti_PrepareAllCalledOncePerEvaluate(t *testing.T) {
	var loadCalls int
	source := fakeAllSource{policies: []StoredPolicy{{ID: "p1", Language: "cedar"}}, gotCalls: &loadCalls}
	m := NewMulti(source, Registry{"cedar": stubEngine{language: "cedar", set: stubSet{}}})

	m.Evaluate(context.Background(), EvaluationInput{})
	if loadCalls != 1 {
		t.Errorf("LoadAllPolicies called %d times for one Evaluate() call, want 1", loadCalls)
	}
}

// TestMulti_PreparedSetSafeForConcurrentEvaluate proves multiSet — the
// CompiledPolicySet PrepareAll returns — tolerates the concurrent Evaluate
// calls its own contract requires (one prepared set serves every concurrent
// decision for a tenant). Meaningful only under -race, per this project's
// Makefile `test` target.
//
// stubSet, deliberately, not a fresh-slice-per-call fixture: stubSet.Evaluate
// returns s.verdicts directly, so every call — across every goroutine —
// gets back the exact same backing array. That is the scenario that
// actually exercises the concurrency claim: a sub-engine that precomputes
// its verdict slice once (plausible for a cache, see Task 6) and hands the
// same array back on every call. A fixture that allocates fresh per call
// cannot distinguish "multiSet is safe" from "nothing shared ever collided
// by construction" — this one can and, before the fix that sorts a copy
// instead of the sub-engine's own slice, does: substituting this exact
// fixture in reproduced a real WARNING: DATA RACE at the in-place sort.
// Two verdicts per language, deliberately out of PolicyID order, so the
// per-language sort has actual work to do — sorting a single-element slice
// never writes, so never races.
func TestMulti_PreparedSetSafeForConcurrentEvaluate(t *testing.T) {
	source := fakeAllSource{policies: []StoredPolicy{
		{ID: "p1", Language: "cedar"}, {ID: "p2", Language: "cedar"},
		{ID: "p3", Language: "rego"}, {ID: "p4", Language: "rego"},
	}}
	engines := Registry{
		"cedar": stubEngine{language: "cedar", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "p2"},
			{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "p1"},
		}}},
		"rego": stubEngine{language: "rego", set: stubSet{verdicts: []authz.PolicyVerdict{
			{Effect: authz.EffectDeny, Source: "rego", PolicyID: "p4"},
			{Effect: authz.EffectDeny, Source: "rego", PolicyID: "p3"},
		}}},
	}

	set, err := NewMulti(source, engines).PrepareAll(context.Background())
	if err != nil {
		t.Fatalf("PrepareAll: %v", err)
	}

	const goroutines = 32
	const perGoroutine = 50
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				vs, err := set.Evaluate(context.Background(), EvaluationInput{})
				if err != nil {
					errs <- err
					return
				}
				if len(vs) != 4 {
					errs <- errors.New("wrong verdict count")
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
}

// TestNewMulti_PanicsOnRegistryKeyLanguageMismatch defends the invariant
// Registry's own doc comment claims: NewMulti, not silent routing, is what
// catches a typo'd key. Without this check, Registry{"rego": xacml.New()}
// would compile and route every "rego" policy to an XACML engine, silently
// misattributing every verdict it produces — Multi routes purely by map
// key and never itself calls Language() to cross-check (see PrepareAll), so
// nothing downstream would ever catch the mismatch.
func TestNewMulti_PanicsOnRegistryKeyLanguageMismatch(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("NewMulti did not panic on a Registry key that disagrees with its engine's Language()")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "rego") || !strings.Contains(msg, "xacml") {
			t.Errorf("panic value = %v, want it to name both the mismatched key %q and the engine's actual language %q", r, "rego", "xacml")
		}
	}()

	NewMulti(fakeAllSource{}, Registry{"rego": stubEngine{language: "xacml"}})
	t.Fatal("unreachable: NewMulti should have panicked before returning")
}

// TestMulti_ConstructorCannotAllow is the same behavioral check
// TestNoExportedConstructorAllows runs automatically (see
// engineBackedConstructors["NewMulti"] in policy_test.go), pinned here too,
// directly against NewMulti, as its own named test: a reader looking for
// "what stops Multi from allowing with no real policy data" should find it
// next to Multi's other tests, not only inside the AST-driven guard.
func TestMulti_ConstructorCannotAllow(t *testing.T) {
	got := NewMulti(fakeAllSource{}, Registry{}).Evaluate(context.Background(), EvaluationInput{})
	for _, v := range got {
		if v.Effect == authz.EffectAllow {
			t.Fatalf("NewMulti with an empty source and an empty registry produced an allow: %+v", got)
		}
	}
}
