package rego

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"stratium/internal/policy"
	"stratium/internal/policy/policytest"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent. Malformed
// deliberately reuses the unbalanced-bracket shape cedar's fixture uses (a
// syntax error is a syntax error in any language); WellFormed, AllowAll, and
// DenyAll are otherwise unrelated policies so a mixup between them would not
// coincidentally still compile or still carry the right effect.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed: `package stratium.policy

allow if { unbalanced [[`,
		WellFormed: `package stratium.policy

allow if {
	input.principal.subject == "nobody-in-particular"
}`,
		AllowAll: `package stratium.policy

allow := true`,
		DenyAll: `package stratium.policy

deny := true`,
	})
}

// TestPrepare_RejectsWrongPackage guards the fix for a review-found Critical:
// rego.New(...).PrepareForEval accepts a module declaring any package, and
// this engine only ever queries queryPath (data.stratium.policy) — so a
// policy whose module declared, say, `package stratium.oops` used to
// compile cleanly and then never produce a verdict for any input, forever,
// with nothing at Prepare time or decision time distinguishing it from a
// rule that correctly never fires. See checkPackage's own doc comment for
// the full reasoning and why a runtime probe cannot substitute for this
// static check. Names the offending policy's ID, the same property
// policytest.EngineContract's own "malformed" case checks for other kinds
// of bad text.
func TestPrepare_RejectsWrongPackage(t *testing.T) {
	t.Run("wrong package is rejected, naming the policy ID", func(t *testing.T) {
		const wantID = "wrong-package-under-test"
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: wantID, Name: "typo'd package", Text: `package stratium.oops

allow := true`},
		})
		if err == nil {
			t.Fatal("Prepare accepted a policy declaring the wrong package, want an error")
		}
		if !strings.Contains(err.Error(), wantID) {
			t.Errorf("error does not name the offending policy's ID %q: %v", wantID, err)
		}
	})

	// Positive control: the check above must reject the wrong package
	// specifically, not policies in general — otherwise this "fix" would be
	// indistinguishable from Prepare rejecting everything.
	t.Run("correct package still prepares normally", func(t *testing.T) {
		_, err := New().Prepare(context.Background(), []policy.StoredPolicy{
			{ID: "right-package-under-test", Name: "correct", Text: `package stratium.policy

allow := true`},
		})
		if err != nil {
			t.Fatalf("Prepare rejected a correctly-packaged policy: %v", err)
		}
	})
}

// TestValidate_RejectsWrongPackage is TestPrepare_RejectsWrongPackage's
// counterpart for the PAP's authoring-time gate — deliberately a separate
// test function, not a subtest folded into the one above, because the fix
// touches Prepare and Validate independently (checkPackage is called from
// both, but each call site can regress on its own) and a single test
// covering both call sites would leave whichever one broke first still
// green.
func TestValidate_RejectsWrongPackage(t *testing.T) {
	t.Run("wrong package is rejected", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.oops

allow := true`)
		if err == nil {
			t.Fatal("Validate accepted text declaring the wrong package, want an error")
		}
	})

	t.Run("correct package still validates normally", func(t *testing.T) {
		err := New().Validate(context.Background(), `package stratium.policy

allow := true`)
		if err != nil {
			t.Fatalf("Validate rejected correctly-packaged text: %v", err)
		}
	})
}

// allowedToCompile are the only functions in this package permitted to call
// PrepareForEval: Prepare (the compile-once step) and Validate (the PAP's
// authoring-time check, which also compiles text but is never called on a
// per-decision path). See TestPrepareForEval_OnlyCalledFromPrepareOrValidate.
var allowedToCompile = map[string]bool{
	"Prepare":  true,
	"Validate": true,
}

// TestPrepareForEval_OnlyCalledFromPrepareOrValidate guards spec defect D5
// by name: the predecessor called rego.New(...).PrepareForEval inside
// Evaluate, once per policy per decision, instead of once per policy inside
// Prepare. No behavioural test can catch that regression — a version of this
// engine that recompiles on every Evaluate call produces byte-identical
// verdicts to one that reuses a prepared query, just far slower, and none of
// this package's other tests measure time (confirmed directly: the full
// mutation — moving the compile call into Evaluate and having it evaluate
// against the freshly recompiled query — was applied and every behavioural
// test in this package still passed). This is a structural check instead: it
// parses every non-test .go file in this package, walks every top-level
// function and method declaration, and fails if a call to PrepareForEval
// appears inside any function not named in allowedToCompile. "Move
// PrepareForEval into Evaluate" is exactly the source-shape change this
// catches.
func TestPrepareForEval_OnlyCalledFromPrepareOrValidate(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package source: %v", err)
	}

	fset := token.NewFileSet()
	totalCalls := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			calls := prepareForEvalCallCount(fn.Body)
			if calls == 0 {
				continue
			}
			totalCalls += calls
			if !allowedToCompile[fn.Name.Name] {
				t.Errorf("%s (in %s) calls PrepareForEval %d time(s) — only Prepare and Validate may compile; "+
					"a compile call anywhere else (Evaluate, above all) reintroduces spec defect D5, recompiling "+
					"on every decision instead of reusing what Prepare already built",
					fn.Name.Name, name, calls)
			}
		}
	}

	// Positive control: if the scan found nothing at all, the guard above
	// passes vacuously regardless of what Evaluate does — a wrong glob or a
	// renamed method (PrepareForEval itself, or Prepare/Validate) would
	// silently defeat this test rather than failing it. See
	// policy_test.go's TestNoExportedConstructorAllows for the same
	// "found no candidates" guard applied to a different structural check.
	if totalCalls == 0 {
		t.Fatal("found zero calls to PrepareForEval anywhere in this package — the guard isn't exercising anything, fix the scan")
	}
}

// prepareForEvalCallCount counts calls to a method or function named
// PrepareForEval within node, whether reached through a selector
// (x.PrepareForEval(...)) or a bare identifier (a dot-imported or
// locally-aliased call — not used anywhere in this package today, but the
// guard should not depend on that staying true).
func prepareForEvalCallCount(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel.Name == "PrepareForEval" {
				count++
			}
		case *ast.Ident:
			if fun.Name == "PrepareForEval" {
				count++
			}
		}
		return true
	})
	return count
}
