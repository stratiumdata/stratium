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

// constructors is the documented convention the guard test below enforces:
// every exported, top-level function in this package that returns
// PrincipalPolicy must have an entry here that calls it with zero-value
// arguments. TestNoExportedConstructorAllows cross-checks this map against
// the package's actual source, so a constructor added here without ever
// updating this map fails loudly instead of shipping unchecked.
var constructors = map[string]func() PrincipalPolicy{
	"Unconfigured": Unconfigured,
}

// TestNoExportedConstructorAllows is the guard against a bypass being added
// later. It does not trust the constructors map above as ground truth — it
// parses this package's own source with go/ast to find every exported,
// top-level function that returns PrincipalPolicy, then requires each one to
// be wired into the map and to never produce a verdict slice containing
// EffectAllow. A new constructor (an "AllowAll", say) that isn't wired into
// the map fails the test by name rather than passing silently — and every
// verdict in the slice is checked, not just the first, so a constructor that
// buries an allow behind a leading deny is caught too.
func TestNoExportedConstructorAllows(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("listing package source: %v", err)
	}

	fset := token.NewFileSet()
	var found []string
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
				found = append(found, fn.Name.Name)
			}
		}
	}

	if len(found) == 0 {
		t.Fatal("found no exported PrincipalPolicy constructor in source — the guard isn't exercising anything, fix the scan")
	}

	for _, name := range found {
		ctor, ok := constructors[name]
		if !ok {
			t.Errorf("exported constructor %s returns PrincipalPolicy but is not wired into the constructors map in policy_test.go — add it so this guard actually checks it", name)
			continue
		}
		verdicts := ctor().Evaluate(context.Background(), EvaluationInput{})
		for _, v := range verdicts {
			if v.Effect == authz.EffectAllow {
				t.Errorf("%s() must not produce a verdict slice containing EffectAllow (found one from source %q, policy_id %q) — Phase 1c has no policy engine to authorize this (see package doc)", name, v.Source, v.PolicyID)
			}
		}
	}
}

// returnsPrincipalPolicy reports whether fn's declared return type is
// exactly PrincipalPolicy. This is the documented convention: constructors
// in this package are written to return the interface, never a concrete
// type, so the guard above can find them by source inspection alone.
func returnsPrincipalPolicy(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	ident, ok := fn.Type.Results.List[0].Type.(*ast.Ident)
	return ok && ident.Name == "PrincipalPolicy"
}
