package policy

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"stratium/internal/authz"
)

// constructors is the documented convention the guard test below enforces
// for every exported, zero-argument, top-level function in this package that
// returns PrincipalPolicy: each one must have an entry here that calls it
// with no arguments. TestNoExportedConstructorAllows cross-checks this map
// against the package's actual source, so a constructor added here without
// ever updating this map fails loudly instead of shipping unchecked.
//
// Empty now: Unconfigured, this map's last entry, was deleted in Phase 4a
// Task 4 alongside Configured (both production-dead once policy.Multi
// replaced them — see multi.go and policy.go's own package doc). The map
// stays declared rather than being deleted with its last entry: the strict,
// zero-argument path through TestNoExportedConstructorAllows below exists
// for whatever zero-argument constructor gets added next, and Task 4's own
// verification exercised it directly — a temporary AllowAll() was added,
// wired in here, confirmed to make the guard fail naming it, then removed
// (see the task report). A guard whose subjects can all be deleted out from
// under it needs proof it still fires on a fresh one, not just that it
// compiles.
var constructors = map[string]func() PrincipalPolicy{}

// engineBackedConstructors is the guard's one deliberate, narrow exemption,
// for exported constructors the AST scan finds that take a data-loading
// argument (see policySourceParamTypes): a constructor that cannot be called
// with zero arguments — Go's own type checker enforces that a source is
// supplied — cannot be a hardcoded, zero-configuration bypass the way an
// "AllowAll()" could be. That is a structural fact
// TestNoExportedConstructorAllows re-derives from the source itself
// (requiresPolicySource), not something this map is trusted to claim on its
// own: a constructor that takes arguments but none of them is a recognized
// data-loading type does NOT get exempted (see the test's default case) —
// only the specific, narrow shape "requires one of those types" does.
//
// NewMulti is the only entry: it takes an AllPolicySource, added alongside
// Multi (multi.go) — Configured used to be a second entry here, exempted the
// same way on PolicySource, until Phase 4a Task 4 deleted it (see policy.go's
// own package doc for why: it was worse than merely redundant with Multi).
//
// The entry here still gets the same behavioral check every zero-argument
// constructor gets (assertNoAllow), just built from a minimal, explicitly
// empty source rather than a genuinely zero-argument call — proving that
// even in the most permissive-looking wiring this guard can construct, the
// result still cannot allow without policies actually flowing through it.
// (What a *non-empty* source can produce is the whole point of Multi,
// exercised by multi_test.go and the Task 5 integration suite instead — this
// guard is not the place that proves an engine's real evaluation logic, only
// that nothing here can allow for free.)
var engineBackedConstructors = map[string]func() PrincipalPolicy{
	"NewMulti": func() PrincipalPolicy {
		return NewMulti(fakeAllSource{}, Registry{})
	},
}

// TestNoExportedConstructorAllows is the guard against a bypass being added
// later. It does not trust the constructors/engineBackedConstructors maps
// above as ground truth — it parses this package's own source with go/ast to
// find every exported, top-level function whose return type is one
// guardedReturnTypes recognizes (PrincipalPolicy itself, or Multi — see that
// map's own doc comment), then classifies each by its own declared
// signature:
//
//   - zero parameters: must be wired into constructors, called with no
//     arguments, and its result checked for EffectAllow. This is the strict
//     path — the shape a hardcoded bypass would use.
//   - takes a parameter whose type is in policySourceParamTypes
//     (AllPolicySource today): must be wired into engineBackedConstructors
//     instead. This is the guard's only exemption, and it is narrow by
//     construction: arity alone would let a decoy parameter ("Bypass(x int)")
//     dodge the strict path, so the exemption requires one of those specific
//     types, not merely that some argument exists.
//   - anything else (takes arguments, but none matches
//     policySourceParamTypes): fails loudly. The guard refuses to guess at a
//     new shape rather than silently passing it through.
//
// Every verdict in a checked result is inspected, not just the first, so a
// constructor that buries an allow behind a leading deny is caught too.
func TestNoExportedConstructorAllows(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package source: %v", err)
	}

	fset := token.NewFileSet()
	found := make(map[string]*ast.FuncDecl)
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
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			if returnsPrincipalPolicy(fn) {
				found[fn.Name.Name] = fn
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("found no exported PrincipalPolicy constructor in source — the guard isn't exercising anything, fix the scan")
	}

	for name, fn := range found {
		switch {
		case paramCount(fn) == 0:
			ctor, ok := constructors[name]
			if !ok {
				t.Errorf("exported constructor %s takes no arguments but is not wired into the constructors map in policy_test.go — add it so this guard actually checks it", name)
				continue
			}
			assertNoAllow(t, name, ctor().Evaluate(context.Background(), EvaluationInput{}))

		case requiresPolicySource(fn):
			build, ok := engineBackedConstructors[name]
			if !ok {
				t.Errorf("exported constructor %s takes a data-loading argument (policySourceParamTypes) but is not "+
					"acknowledged in engineBackedConstructors in policy_test.go — it is exempt from the zero-argument "+
					"check because it cannot allow without real policy data flowing through a caller-supplied source "+
					"(see engineBackedConstructors' own doc comment), but this guard must see it wired in "+
					"deliberately, not by omission", name)
				continue
			}
			assertNoAllow(t, name, build().Evaluate(context.Background(), EvaluationInput{}))

		default:
			t.Errorf("exported constructor %s returns PrincipalPolicy and takes arguments, but none of them is a "+
				"recognized data-loading type (policySourceParamTypes) — this guard does not recognize the shape and "+
				"refuses to guess: either make it zero-argument and wire it into constructors, or take a "+
				"policySourceParamTypes argument and wire it into engineBackedConstructors", name)
		}
	}
}

// assertNoAllow fails t if verdicts contains any EffectAllow, checking every
// element, not just the first, so a constructor that buries an allow behind
// a leading deny is still caught.
func assertNoAllow(t *testing.T, name string, verdicts []authz.PolicyVerdict) {
	t.Helper()
	for _, v := range verdicts {
		if v.Effect == authz.EffectAllow {
			t.Errorf("%s() must not produce a verdict slice containing EffectAllow (found one from source %q, "+
				"policy_id %q) — a zero-configuration call must never authorize anything (see package doc)",
				name, v.Source, v.PolicyID)
		}
	}
}

// guardedReturnTypes are the return types this filter recognizes as "worth
// checking for a free allow": PrincipalPolicy itself (the documented
// convention — a constructor with no reason to expose more than the
// interface returns it, never a concrete type; Unconfigured and Configured
// did this before Phase 4a Task 4 deleted both as production-dead, and a
// future simple implementation should follow the same convention), and Multi
// (NewMulti), the one deliberate exception. Multi returns its own concrete
// type instead of PrincipalPolicy specifically so pdpgrpc's NewServer can
// reach its PrepareAll method without a type assertion (see Multi's own doc
// comment in multi.go) — a caller holding a
// bare PrincipalPolicy interface value cannot call a method the interface
// doesn't declare, even when the underlying value has one. That is a real
// need, not a precedent to generalize from: this set stays a short, explicit
// list rather than "anything found in this package," so an unrelated
// exported function returning some other type cannot silently slip past a
// guard whose name promises no exported constructor allows for free. A third
// constructor needing the same treatment extends this set the same
// deliberate way.
var guardedReturnTypes = map[string]bool{
	"PrincipalPolicy": true,
	"Multi":           true,
}

// returnsPrincipalPolicy reports whether fn's declared return type is one
// guardedReturnTypes recognizes.
func returnsPrincipalPolicy(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	results := fn.Type.Results.List

	// One result, or two where the second is error. Requiring exactly one
	// result was a hole in this guard rather than a property of it: a
	// constructor declared `func NewThing(...) (PrincipalPolicy, error)` —
	// the most ordinary shape in Go for a constructor that can fail — was
	// not merely exempted, it was never examined at all. The guard's name
	// promises no exported constructor allows for free, and a bypass had
	// only to add an error return to escape it entirely. NewMulti's own doc
	// comment reasoned from the old shape, treating a single-value return as
	// something to preserve; with this fixed, that constraint is gone and a
	// future constructor may return an error without losing coverage.
	switch len(results) {
	case 1:
	case 2:
		second, ok := results[1].Type.(*ast.Ident)
		if !ok || second.Name != "error" {
			return false
		}
	default:
		return false
	}

	ident, ok := results[0].Type.(*ast.Ident)
	return ok && guardedReturnTypes[ident.Name]
}

// paramCount returns fn's declared parameter count, counting each name in a
// grouped field (e.g. "a, b int") separately and an unnamed field as one.
func paramCount(fn *ast.FuncDecl) int {
	if fn.Type.Params == nil {
		return 0
	}
	n := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			n++
			continue
		}
		n += len(field.Names)
	}
	return n
}

// policySourceParamTypes are the parameter types this guard accepts as proof
// a constructor cannot be a hardcoded, zero-configuration bypass: each is an
// interface a caller must satisfy with something that actually loads policy
// data before the constructor will even compile. AllPolicySource is Multi's
// (every language in one call) — the sole entry now that Phase 4a Task 4
// deleted Configured and, with it, PolicySource (one language at a time),
// the entry this map used to also carry. A future constructor with a new
// such interface extends this set the same deliberate way — this does not
// accept "any parameter with any interface type," which would let a decoy
// interface exempt a real bypass the same way an arity-only check would.
var policySourceParamTypes = map[string]bool{
	"AllPolicySource": true,
}

// requiresPolicySource reports whether fn declares a parameter whose type is
// in policySourceParamTypes. This is the guard's one exemption criterion
// (see engineBackedConstructors above): a constructor that cannot compile
// without a caller supplying something that loads real policy data cannot
// itself be a hardcoded bypass — Go's own type checker enforces that the
// argument is present, which this test does not need to re-verify, only
// rely on. A parameter of any other type does not count, deliberately: an
// arity-only check would let a decoy parameter exempt a real bypass.
func requiresPolicySource(fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil {
		return false
	}
	for _, field := range fn.Type.Params.List {
		if ident, ok := field.Type.(*ast.Ident); ok && policySourceParamTypes[ident.Name] {
			return true
		}
	}
	return false
}
