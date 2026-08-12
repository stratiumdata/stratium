package authz

import (
	"fmt"
	"strings"
	"testing"
)

// outcome is a conformance property's disposition in this run. The zero
// value is outcomePass deliberately: a TestC* that calls neither notBuilt
// nor provenElsewhere falls through to its own real assertions, and if
// those assertions fail, go test's own exit code — required green before
// any commit here (see the Makefile) — already catches it. Nothing needs to
// mark "pass" explicitly; only the two ways of NOT passing here need to
// record which one they are.
type outcome int

const (
	outcomePass outcome = iota
	outcomeProvenElsewhere
	outcomeNotBuilt
)

func (o outcome) String() string {
	switch o {
	case outcomePass:
		return "pass"
	case outcomeProvenElsewhere:
		return "proven elsewhere"
	case outcomeNotBuilt:
		return "not built"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// conformanceOutcome parallels conformanceRan (conformance_test.go): index n
// holds property Cn's disposition. Same index convention (0 unused, 1..25),
// same reason it lives at package scope instead of inside one test —
// notBuilt and provenElsewhere are called from 25 separate TestC* functions
// across a run, and Go gives sibling top-level tests no way to share state
// except a package variable.
//
// The test that reads this and reports the tally, TestConformanceTally,
// lives at the bottom of conformance_test.go instead of in this file,
// despite conformanceOutcome being declared here: go test runs a package's
// tests in each file's declaration order, concatenated in filename order,
// and this file sorts before conformance_test.go alphabetically
// ("conformance_o..." < "conformance_t..."). A tally test declared here
// would run, and find conformanceOutcome still all-zero, before any TestC*
// had a chance to set it — confirmed the hard way, not a hypothetical.
// Declaring it after TestC1..TestC25 in the same file they run in is what
// actually guarantees the ordering; cross-file order is not something to
// build on.
var conformanceOutcome [26]outcome

// notBuilt records cNum as NOT BUILT — the subsystem the property needs
// does not exist anywhere in this tree yet — and skips the test. reason
// must name what is missing; an empty reason is rejected because "not
// built, for no stated reason" is not a claim anyone could check, which is
// the same complaint this file exists to fix about a bare t.Skip.
func notBuilt(t *testing.T, cNum int, reason string) {
	t.Helper()
	if strings.TrimSpace(reason) == "" {
		t.Fatalf("C%d: notBuilt requires a reason naming what is missing", cNum)
	}
	conformanceOutcome[cNum] = outcomeNotBuilt
	t.Skip("not built: " + reason)
}

// provenElsewhere records cNum as PROVEN ELSEWHERE — the property holds and
// is tested for real, just in a package this pure, DB-free, network-free
// suite structurally cannot reach — verifies the pointer against real
// source, and skips.
//
// Verifying before skipping is the actual reason this is a function and not
// still a bare t.Skip string: a pointer naming a renamed or deleted test
// would otherwise sit there passing (a skip always does) until a human
// happened to read it and notice. verifyPointer (conformance_pointer_test.go)
// makes a stale pointer fail the build instead — the only way a claim like
// this stays honest in a codebase that keeps changing after it was written.
func provenElsewhere(t *testing.T, cNum int, pkgPath string, testFuncs ...string) {
	t.Helper()
	if err := verifyPointer(pkgPath, testFuncs); err != nil {
		t.Fatalf("C%d: proven-elsewhere pointer is stale: %v", cNum, err)
	}
	conformanceOutcome[cNum] = outcomeProvenElsewhere
	t.Skipf("proven elsewhere: %s: %s", pkgPath, strings.Join(testFuncs, ", "))
}

// TestConformanceTally lives at the bottom of conformance_test.go, not
// here, even though conformanceOutcome is this file's variable: go test
// runs a package's tests in each file's declaration order, concatenated in
// filename order, and this file (conformance_outcome_test.go) sorts before
// conformance_test.go — a tally test here would run, and read
// conformanceOutcome as still all-zero, BEFORE any TestC* had a chance to
// set it. Declaring it after TestC1..TestC25 in the same file they run in
// is what actually guarantees the ordering; relying on cross-file order
// does not (confirmed the hard way — see that test's own doc comment).
