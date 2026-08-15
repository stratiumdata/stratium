package authz

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// verifyPointer confirms every name in testFuncs is a real, top-level Go
// test function somewhere under pkgPath (a package path relative to the
// services/ module root, e.g. "internal/pdpgrpc"), by parsing that
// package's own _test.go files with go/ast — never by importing it.
//
// Parsing instead of importing is the entire reason this function exists,
// not a style choice: internal/authz is a deliberately pure package (see
// the package doc in types.go) that may never import internal/policy,
// internal/store, internal/pdpgrpc, or any cmd/* binary — exactly the
// packages a "proven elsewhere" pointer needs to name. It is not merely a
// convention here: internal/pdpgrpc itself imports internal/authz, and this
// file compiles as part of package authz (not authz_test), so a real import
// the other way would be a genuine cycle, not just a purity violation —
// `go test` would refuse to build it. go/parser reads a file's bytes off
// disk and hands back a syntax tree; it never touches Go's build graph, so
// this function can name cmd/stratium-pep in a plain string argument
// without internal/authz ever depending on it. If a future change here
// needs an import of one of those packages to compile, that change broke
// the property this function exists to preserve — the fix is to find
// another way to ask the question, not to add the import.
//
// Existence is deliberately ALL this checks — it does not re-run testFuncs.
// Every package in this module is compiled and run by one of two standing
// gates that must be green before any commit here: go test -race ./... for
// an ordinary package, or make integration (a live Postgres, built with the
// `integration` tag) for a package that needs one — see the Makefile. A
// named function that exists, in a tree where its gate is green, already
// ran and already passed as part of that standing gate. Re-running it from
// in here would need exactly the cross-package call this package is
// forbidden from making, to re-derive a fact the green gate already
// establishes for free. If a future reader wants to add that, this
// paragraph is the reason it was deliberately left out — do it only if one
// of those gates stops running on every commit.
func verifyPointer(pkgPath string, testFuncs []string) error {
	if len(testFuncs) == 0 {
		return fmt.Errorf("no test functions named for package %q — a pointer with nothing to check is the stale claim this gate exists to catch", pkgPath)
	}

	// pkgPath is normally module-relative ("internal/pdpgrpc"), resolved
	// against servicesRoot; an absolute path is accepted as-is so this
	// function can be tested directly against a synthetic fixture
	// directory (see TestVerifyPointer_NonTestShapeNotMatched) without a
	// seam purpose-built for mocking.
	dir := pkgPath
	if !filepath.IsAbs(dir) {
		root, err := servicesRoot()
		if err != nil {
			return fmt.Errorf("locating services/ module root: %w", err)
		}
		dir = filepath.Join(root, filepath.FromSlash(pkgPath))
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("package %q (%s): %w", pkgPath, dir, err)
	}

	want := make(map[string]bool, len(testFuncs))
	for _, name := range testFuncs {
		want[name] = true
	}
	found := make(map[string]bool, len(testFuncs))

	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", filepath.Join(pkgPath, name), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !want[fn.Name.Name] || !isTestFunc(fn) {
				continue
			}
			found[fn.Name.Name] = true
		}
	}

	var missing []string
	for _, name := range testFuncs {
		if !found[name] {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("package %q (%s): test function(s) not found: %s", pkgPath, dir, strings.Join(missing, ", "))
	}
	return nil
}

// isTestFunc reports whether fn has the exact shape go test itself runs:
// no receiver, a "Test" name prefix, and a single func(*testing.T)
// parameter. Matching on name alone would also accept a same-named
// production function or a differently-shaped helper that go test would
// never actually invoke — a pointer verified against either would name
// something real that nonetheless never ran as part of the green gate
// verifyPointer's own doc comment leans on, which defeats the point.
func isTestFunc(fn *ast.FuncDecl) bool {
	if fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Test") {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "T" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing"
}

// servicesRoot returns the absolute path to the services/ module root (the
// directory holding go.mod), derived from this file's own location via
// runtime.Caller rather than os.Getwd: go test sets the working directory
// to the package under test (internal/authz), not the module root, and
// verifyPointer needs to reach sibling packages such as internal/pdpgrpc.
// This file lives two directories below services/ (internal/authz), so
// climbing two levels reaches it — if this file ever moves, that is the
// number to update.
func servicesRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("runtime.Caller could not resolve this file's own path")
	}
	return filepath.Join(filepath.Dir(file), "..", ".."), nil
}

// TestVerifyPointer_FindsRealTestFunctions is the positive case, run
// against the exact pointers conformance_test.go wires into provenElsewhere
// for C5, C16, C18, C19, C20, C21, C22, C23, and C24. If a future rename
// ever broke one of those pointers, this test — not just a full run of make
// conformance — names it directly, without needing every one of the 25
// conformance properties to execute first.
func TestVerifyPointer_FindsRealTestFunctions(t *testing.T) {
	tests := []struct {
		name      string
		pkgPath   string
		testFuncs []string
	}{
		// C5 spans three packages -- the only property here that does. Each
		// group is a separate row for the same reason the others are single
		// rows: a failure names the package whose test moved.
		{"C5/pep", "cmd/stratium-pep", []string{
			"TestRunHook_RequestCarriesRawInputAndNoDeclaredTier",
			"TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier",
			"TestCheck_NeverSendsDeclaredTier",
			"TestAuthorize_NeverSendsDeclaredTier",
		}},
		{"C5/authz", "internal/authz", []string{
			"TestDeriveTier_IgnoresDeclaredTier",
			"TestCheckDeclaredTier_UnderDeclarationDenies",
		}},
		{"C5/store", "internal/store", []string{
			"TestIntegration_PAPRole_BumpsOnGovernedTableWrites",
			"TestIntegration_StratiumApp_CanReadButCannotWriteTierOverrides",
			"TestIntegration_TierOverride_DirectlyInsertedLoweringRowIsDroppedAtReadTime",
			"TestIntegration_PAPE2E_UnverifiedTokenIsRefusedEverywhere",
		}},
		{"C16", "internal/store", []string{"TestEndToEnd"}},
		{"C18", "internal/store", []string{
			"TestIntegration_Multi_CrossTenantIsolationAcrossLanguages",
			"TestIntegration_Escalation_CrossTenantCannotReadOrApprove",
		}},
		{"C21", "internal/pdpgrpc", []string{
			"TestDecide_Escalation_CreatesApprovalWithRootPrincipalAsApprover",
			"TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate",
		}},
		{"C22", "cmd/stratium-pep", []string{
			"TestRunHook_Escalate_TimeoutStillPendingDenies",
			"TestPollApproval_ContextCancelledMidPoll_ReturnsPromptlyAndDenies",
			"TestDecideAndRelay_EscalationTimeout_Denies",
			"TestAuthorize_EscalationTimeout_Denies",
			"TestHandleStream_EscalationTimeout_DeniesWithoutForwarding",
		}},
		{"C23", "internal/store", []string{
			"TestIntegration_Envoy_EscalateDeniesWithFindablePendingApproval_ApprovedRetrySucceeds",
		}},
		{"C19", "internal/store", []string{
			"TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies",
			"TestIntegration_Cache_E2E_PastStalenessWindow_StopsServing",
		}},
		{"C20", "internal/store", []string{
			"TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry",
		}},
		{"C24", "internal/store", []string{
			"TestIntegration_Cache_E2E_ExpiredTokenDeniedDespiteValidEntry",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyPointer(tt.pkgPath, tt.testFuncs); err != nil {
				t.Fatalf("verifyPointer(%q, %v) = %v, want nil", tt.pkgPath, tt.testFuncs, err)
			}
		})
	}
}

// TestVerifyPointer_MissingFunctionFails is mutation coverage for the
// pointed-to-test-gets-renamed case: a name that does not exist in a real
// package must fail, and name the function it could not find.
func TestVerifyPointer_MissingFunctionFails(t *testing.T) {
	const madeUp = "TestThisFunctionDoesNotExist_MadeUp"
	err := verifyPointer("internal/pdpgrpc", []string{madeUp})
	if err == nil {
		t.Fatal("verifyPointer with a made-up function name = nil error, want a failure naming it")
	}
	if !strings.Contains(err.Error(), madeUp) {
		t.Fatalf("error %q does not name the missing function %q", err, madeUp)
	}
}

// TestVerifyPointer_MissingPackageFails is mutation coverage for the
// pointed-at-a-package-that-does-not-exist case.
func TestVerifyPointer_MissingPackageFails(t *testing.T) {
	const bogus = "internal/this-package-does-not-exist"
	err := verifyPointer(bogus, []string{"TestAnything"})
	if err == nil {
		t.Fatal("verifyPointer against a nonexistent package = nil error, want a failure")
	}
	if !strings.Contains(err.Error(), bogus) {
		t.Fatalf("error %q does not name the missing package %q", err, bogus)
	}
}

// TestVerifyPointer_EmptyPointerRejected is mutation coverage for the
// marked-proven-elsewhere-with-nothing-to-check case: an empty pointer list
// must fail rather than vacuously succeed.
func TestVerifyPointer_EmptyPointerRejected(t *testing.T) {
	if err := verifyPointer("internal/pdpgrpc", nil); err == nil {
		t.Fatal("verifyPointer with no test functions = nil error, want rejection — an empty pointer proves nothing")
	}
}

// TestVerifyPointer_NonTestShapeNotMatched writes a synthetic package to a
// temp directory rather than relying on some real function in this module
// happening to have the wrong shape today: a helper that takes *testing.T
// but is never prefixed "Test" is an ordinary, common pattern (fixture
// setup functions do this constantly), and isTestFunc must not treat one as
// proof a property was ever run by go test, no matter how closely its
// parameter list resembles a real test's.
func TestVerifyPointer_NonTestShapeNotMatched(t *testing.T) {
	dir := t.TempDir()
	const src = `package fixture

import "testing"

func setupHelper(t *testing.T) { t.Helper() }

func TestReal(t *testing.T) {}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture_test.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	if err := verifyPointer(dir, []string{"setupHelper"}); err == nil {
		t.Fatal("verifyPointer matched a non-Test-prefixed helper with a *testing.T parameter, want rejection")
	}
	if err := verifyPointer(dir, []string{"TestReal"}); err != nil {
		t.Fatalf("verifyPointer(%q, [TestReal]) = %v, want nil — a genuine test function in the directory", dir, err)
	}
}

// TestServicesRoot_ResolvesToTheModuleRoot guards servicesRoot's own
// "climbing two levels reaches it" assumption: if this file ever moves to a
// different depth, every provenElsewhere pointer would silently start
// resolving against the wrong directory instead of failing loudly, because
// a wrong-but-existing directory is exactly as easy to os.ReadDir as the
// right one.
func TestServicesRoot_ResolvesToTheModuleRoot(t *testing.T) {
	root, err := servicesRoot()
	if err != nil {
		t.Fatalf("servicesRoot() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("servicesRoot() = %q, does not contain go.mod: %v", root, err)
	}
}
