package authz

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultTrustTableIsTheOnlyConstructionSite guards the gap this package's
// own doc comment records: TrustTable is per-tenant data with no raise-only
// validation, so "nothing today stops a tenant-supplied table from requiring
// LESS trust than DefaultTrustTable" (agent.go). Only DefaultTrustTable() is
// wired, which is the only reason that gap is latent rather than live.
//
// WHEN THIS FAILS: you are building a TrustTable somewhere new -- most likely
// a tenant-configurable load path. Read agent.go's TrustTable doc comment
// first. A load path needs write-time raise-only validation analogous to
// ValidateOverride BEFORE it lands, or it silently makes a security floor
// lowerable by the tenant it constrains.
func TestDefaultTrustTableIsTheOnlyConstructionSite(t *testing.T) {
	// Path SUFFIX, not basename: pkg/models/agent.go also basenames to
	// "agent.go", and matching on the basename would silently permit a second
	// construction site there.
	const allowedPath = "internal/authz/agent.go"

	root := "../.."
	fset := token.NewFileSet()
	var offenders []string

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// An unparsed file is an unchecked file: a construction site in it
			// would pass this guard silently.
			return fmt.Errorf("parse %s: %w", path, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var name string
			switch t := lit.Type.(type) {
			case *ast.Ident:
				name = t.Name
			case *ast.SelectorExpr:
				name = t.Sel.Name
			}
			if name == "TrustTable" && !strings.HasSuffix(filepath.ToSlash(path), allowedPath) {
				offenders = append(offenders, fset.Position(lit.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("TrustTable is constructed outside %s at:\n  %s\n\n"+
			"Read this test's doc comment before adding an exception.",
			allowedPath, strings.Join(offenders, "\n  "))
	}
}
