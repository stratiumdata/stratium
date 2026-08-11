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
	"stratium/pkg/models"
)

func TestUnconfigured_Denies(t *testing.T) {
	// A populated, allow-shaped input (trusted agent, wide-open delegation)
	// proves Unconfigured truly ignores its argument, rather than merely
	// happening to deny a zero-valued one.
	in := EvaluationInput{
		Principal: authz.Principal{Subject: "alice@example.com"},
		Agent:     authz.AgentInfo{TrustTier: models.TrustTierPlatformTrusted, Enabled: true},
		Delegation: DelegationContext{
			MaxActionTier: models.ActionTierDestructive,
		},
	}
	got := Unconfigured().Evaluate(context.Background(), in)

	if len(got) != 1 {
		t.Fatalf("Unconfigured must return exactly one verdict, got %d", len(got))
	}
	v := got[0]
	if v.Effect != authz.EffectDeny {
		t.Fatalf("Unconfigured must deny, got %v", v.Effect)
	}
	if v.Source != "none" {
		t.Errorf("Source = %q, want %q", v.Source, "none")
	}
	if v.Reason == "" {
		t.Fatal("Unconfigured must give a non-empty reason")
	}
	if !strings.Contains(v.Reason, "policy engine") {
		t.Errorf("reason must name the policy engine as the cause, got %q", v.Reason)
	}
	if !strings.Contains(v.Reason, "Phase 2") {
		t.Errorf("reason must mention Phase 2, got %q", v.Reason)
	}
}

// constructors is the documented convention the guard test below enforces
// for every exported, zero-argument, top-level function in this package that
// returns PrincipalPolicy: each one must have an entry here that calls it
// with no arguments. TestNoExportedConstructorAllows cross-checks this map
// against the package's actual source, so a constructor added here without
// ever updating this map fails loudly instead of shipping unchecked.
var constructors = map[string]func() PrincipalPolicy{
	"Unconfigured": Unconfigured,
}

// engineBackedConstructors is the guard's one deliberate, narrow exemption,
// for exported constructors the AST scan finds that take a data-loading
// argument (see policySourceParamTypes). Configured is the first: it cannot
// be called with zero arguments — Go's own type checker enforces that a
// source and an engine are supplied — so it cannot be a hardcoded,
// zero-configuration bypass the way an "AllowAll()" could be. That is a
// structural fact TestNoExportedConstructorAllows re-derives from the source
// itself (requiresPolicySource), not something this map is trusted to claim
// on its own: a constructor that takes arguments but none of them is a
// recognized data-loading type does NOT get exempted (see the test's default
// case) — only the specific, narrow shape "requires one of those types" does.
//
// NewMulti is the second entry, added alongside Multi (multi.go): it takes
// an AllPolicySource rather than a PolicySource — a different interface for
// a different need (load every language at once, not one at a time) — so
// recognizing it required widening requiresPolicySource's accepted type set,
// not just adding a map entry (see policySourceParamTypes).
//
// Each entry here still gets the same behavioral check every zero-argument
// constructor gets (assertNoAllow), just built from a minimal, explicitly
// empty source rather than a genuinely zero-argument call — proving that
// even in the most permissive-looking wiring this guard can construct, the
// result still cannot allow without policies actually flowing through it.
// (What a *non-empty* source can produce is the whole point of Configured
// and Multi, exercised by configured_test.go/multi_test.go and the Task 5
// integration suite instead — this guard is not the place that proves an
// engine's real evaluation logic, only that nothing here can allow for
// free.)
var engineBackedConstructors = map[string]func() PrincipalPolicy{
	"Configured": func() PrincipalPolicy {
		return Configured(stubSource{}, stubEngine{language: "guard-empty-policy-check"})
	},
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
//   - takes a parameter whose type is in policySourceParamTypes (PolicySource
//     or AllPolicySource): must be wired into engineBackedConstructors
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
				t.Errorf("exported constructor %s takes a PolicySource argument but is not acknowledged in "+
					"engineBackedConstructors in policy_test.go — it is exempt from the zero-argument check because "+
					"it cannot allow without real policy data flowing through a caller-supplied PolicySource (see "+
					"Configured's doc comment), but this guard must see it wired in deliberately, not by omission", name)
				continue
			}
			assertNoAllow(t, name, build().Evaluate(context.Background(), EvaluationInput{}))

		default:
			t.Errorf("exported constructor %s returns PrincipalPolicy and takes arguments, but none of them is a "+
				"PolicySource — this guard does not recognize the shape and refuses to guess: either make it "+
				"zero-argument and wire it into constructors, or take a PolicySource argument and wire it into "+
				"engineBackedConstructors", name)
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
// checking for a free allow": PrincipalPolicy itself (Configured,
// Unconfigured — the documented convention, return the interface, never a
// concrete type), and Multi (NewMulti), the one deliberate exception. Multi
// returns its own concrete type instead of PrincipalPolicy specifically so
// pdpgrpc's NewServer can reach its PrepareAll method without a type
// assertion (see Multi's own doc comment in multi.go) — a caller holding a
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
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
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
// data before the constructor will even compile. PolicySource is
// Configured's (one language at a time); AllPolicySource is Multi's (every
// language in one call) — a different, narrower interface because Multi's
// need is different from Configured's, not because this exemption's own
// logic changed. A third constructor with a third such interface extends
// this set the same deliberate way — this does not accept "any parameter
// with any interface type," which would let a decoy interface exempt a real
// bypass the same way an arity-only check would.
var policySourceParamTypes = map[string]bool{
	"PolicySource":    true,
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
