package jsonpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"stratium/internal/policy/policytest"
)

// TestEngine_Contract runs the shared conformance suite every PolicyEngine
// must pass. It does not reimplement any of these checks itself — that is
// exactly the drift policytest.EngineContract exists to prevent.
//
// AllowAll and DenyAll are the emptiest policies this schema can express: an
// empty match object, nothing else. That is deliberate, not a shortcut —
// they reference the input not at all, so there is no fixture-side
// condition that could accidentally narrow them to "matches every input
// this suite happens to send," the exact trap this task's own instructions
// name explicitly. WellFormed is a different, ordinary policy (a real
// subject constraint) so a mixup between it and AllowAll/DenyAll would not
// coincidentally still validate, or still carry the right effect. Malformed
// is plain invalid JSON syntax — a missing closing brace — the same "a
// syntax error is a syntax error in any language" fixture rego and cedar
// both use.
func TestEngine_Contract(t *testing.T) {
	policytest.EngineContract(t, New(), policytest.Fixtures{
		Malformed:  `{"effect": "allow", "match": {}`,
		WellFormed: `{"effect": "allow", "match": {"subject": {"attr": "department", "equals": "finance"}}}`,
		AllowAll:   `{"effect": "allow", "match": {}}`,
		DenyAll:    `{"effect": "deny", "match": {}}`,
	})
}

// allowedToDecode is the only functions in this package permitted to
// decode (directly or by calling parseDoc) policy JSON. See
// TestDecodeOnlyCalledFromParseDoc — parseDoc is deliberately in this set
// alongside Prepare and Validate: rego's equivalent guard only had one
// compile primitive (PrepareForEval) called directly from two functions,
// but this package routes both Prepare and Validate through a shared
// parseDoc helper (see parseDoc's own doc comment for why that sharing is
// correct), so parseDoc is itself a legitimate call site the scan must
// allow, not merely a producer of decode calls to attribute elsewhere.
var allowedToDecode = map[string]bool{
	"Prepare":  true,
	"Validate": true,
	"parseDoc": true,
}

// TestDecodeOnlyCalledFromParseDoc guards spec defect D5 by name: an engine
// that re-decodes a policy's JSON text inside Evaluate, instead of once per
// policy inside Prepare, produces byte-identical verdicts to a correct
// implementation — just far slower — and no behavioural test in this
// package measures time. This is a structural check instead, the same
// approach rego/engine_test.go's
// TestPrepareForEval_OnlyCalledFromPrepareOrValidate takes for OPA's
// PrepareForEval: it parses every non-test .go file in this package, walks
// every top-level function and method declaration, and fails if a call to
// Decode, Unmarshal, or parseDoc appears inside any function not named in
// allowedToDecode.
//
// parseDoc is scanned as its own name, not only Decode/Unmarshal, because
// of a real gap mutation testing found in an earlier version of this guard:
// a version that scanned only for literal Decode/Unmarshal calls did not
// notice Evaluate calling parseDoc(cp.text) — parseDoc's own body still
// contained real Decode calls (attributed correctly to parseDoc, which was
// allowed), so the "found zero calls" tripwire below never fired, and nothing
// else was checking who calls parseDoc itself. The scan must therefore
// recognize a call to parseDoc as decode-shaped in its own right, the same
// way a call to Decode or Unmarshal is — otherwise a chokepoint helper
// (correct, and exactly what rego's checkPackage precedent recommends) is
// itself a blind spot for a scan that only looks one level down.
func TestDecodeOnlyCalledFromParseDoc(t *testing.T) {
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
			calls := decodeCallCount(fn.Body)
			if calls == 0 {
				continue
			}
			totalCalls += calls
			if !allowedToDecode[fn.Name.Name] {
				t.Errorf("%s (in %s) calls a JSON decode function %d time(s) — only parseDoc may decode policy text; "+
					"a decode call anywhere else (Evaluate, above all) reintroduces spec defect D5, re-parsing on "+
					"every decision instead of reusing what Prepare already built",
					fn.Name.Name, name, calls)
			}
		}
	}

	// Positive control: if the scan found nothing at all, the guard above
	// passes vacuously regardless of what Evaluate does — a wrong glob or a
	// renamed function (parseDoc itself, or a rename away from Decode)
	// would silently defeat this test rather than failing it. Same
	// reasoning as rego/engine_test.go's identical tripwire.
	if totalCalls == 0 {
		t.Fatal("found zero JSON decode calls anywhere in this package — the guard isn't exercising anything, fix the scan")
	}
}

// decodeCallCount counts calls to a method or function named Decode,
// Unmarshal, or parseDoc within node, whether reached through a selector
// (dec.Decode(...), json.Unmarshal(...)) or a bare identifier
// (parseDoc(...), or a dot-imported/locally-aliased Decode/Unmarshal — the
// latter not used anywhere in this package today, but the guard should not
// depend on that staying true).
func decodeCallCount(node ast.Node) int {
	count := 0
	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fun.Sel.Name == "Decode" || fun.Sel.Name == "Unmarshal" {
				count++
			}
		case *ast.Ident:
			if fun.Name == "Decode" || fun.Name == "Unmarshal" || fun.Name == "parseDoc" {
				count++
			}
		}
		return true
	})
	return count
}
