package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file makes "no Go query filters by tenant_id" structural instead of
// remembered.
//
// Before it, the constraint was six hand-written, opt-in, per-query text
// assertions (approval_test.go, delegation_test.go, resource_label_test.go,
// tenant_epoch_test.go, ...). A query added without one of those was not
// covered, and nothing failed to say so. Those assertions stay — several of
// them pin more than tenancy (no WHERE clause at all, no prefix matching in
// SQL) — but they are no longer the only thing standing between a new query
// and a second, divergent tenant boundary.
//
// A behavioural test structurally cannot cover this, and
// pap_task6_list_integration_test.go already wrote down why: a redundant
// WHERE tenant_id "changes no observable behaviour — it only moves the
// apparent source of the guarantee somewhere it is not." sqlmock replays
// whatever rows a test hands it; against real Postgres the predicate is
// simply redundant with the RLS policy that already applies. The query text
// is the only place the mistake is visible, so the check has to read the
// query text — automatically, for every query, without an author opting in.
//
// The structural-scan shape follows the house precedent:
// internal/policy/policy_test.go's TestNoExportedConstructorAllows (parse
// the package's own non-test .go files with go/ast; fail loudly if the scan
// finds nothing to look at) and migrations/migrations_test.go's
// TestEveryTableHasTenantID (a guard plus fixtures proving the guard still
// fires).
//
// There is deliberately NO allowlist. Every one of this package's queries
// passes today with zero exceptions, and an exception list that is easy to
// append to is exactly how this constraint decays back into "remembered".
// If a genuine exception ever appears, that is a conversation, not a skip.

// tenantPredicate matches a tenant_id token used as a FILTER: the name
// immediately followed by a comparison. That single shape is what separates
// the violation from the two legitimate uses, without needing to know which
// clause it sits in:
//
//   - `WHERE tenant_id = $1`, `AND tenant_id=$2`, `ON a.tenant_id = b.tenant_id`,
//     `WHERE tenant_id IN ($1,$2)` -> caught.
//   - `INSERT INTO agents (tenant_id, name, ...)` -> a column list; tenant_id
//     is followed by a comma. That is how a row acquires its tenant and RLS's
//     WITH CHECK validates it, so it must pass.
//   - `SELECT id, tenant_id, name ...` and `RETURNING id, tenant_id, ...` ->
//     also column lists, also followed by a comma. tenant_id is a selected
//     column in most of this package's queries (models.Approval.TenantID and
//     friends are populated from it), which is precisely why a plain
//     "contains tenant_id" substring check is not usable here — see
//     approval_test.go's TestStore_ListApprovals_QueryHasNoTenantPredicate,
//     which had to fall back to "no WHERE clause at all" for that reason.
//   - `SELECT set_config('app.tenant_id', $1, true)` -> followed by a quote.
//     Setting the RLS session variable is the mechanism this guard protects,
//     not a violation of it.
//
// The leading [^a-z0-9_] keeps the match on the whole token, so a column or
// constraint named agents_tenant_id_name_key is not mistaken for it. IN
// requires its opening paren so an English sentence ("tenant_id in the
// request") in some future error string cannot trip the guard.
//
// ponytail: text matching, so `WHERE tenant_id::text = $1` — a cast between
// the name and the operator — slips through. That is an evasion, not a
// slip; this guard exists to catch the predicate someone adds without
// thinking, and everything in that class puts the operator next to the
// name. If a cast ever shows up legitimately, add a second pattern for
// "tenant_id preceded by WHERE/AND/OR/ON" rather than widening this one —
// that form cannot be used on its own because RETURNING clauses follow
// WHERE and legitimately name tenant_id (see revokeDelegationQuery).
//
// ponytail: `JOIN … USING (tenant_id)` is also missed, and unlike the cast it
// is a forgetting-class miss — a genuine redundant join predicate someone
// could write without meaning anything by it. Adding `)` to the operator
// class is NOT the fix: `USING (tenant_id)` and `ON CONFLICT (tenant_id)` are
// textually identical at that point, and the second is correct. It needs a
// keyword anchor on USING itself. No JOIN and no ON CONFLICT exists in this
// package today, so this is a named limit rather than a pattern.
var tenantPredicate = regexp.MustCompile(`(?i)(^|[^a-z0-9_])tenant_id\s*(=|<>|!=|<|>|\bIN\s*\()`)

// sqlStatement recognises a string that carries a SQL statement, which is
// what scanForTenantPredicates counts so its caller can tell "found no
// violations" apart from "looked at nothing". It is only ever used for that
// count — a finding is reported from any string, statement-shaped or not, so
// that a query composed as `loadApprovalQuery + " WHERE tenant_id = $1"` is
// still caught by the fragment even though the fragment names no verb.
//
// UPDATE requires an identifier after it so the ` FOR UPDATE` fragment
// appended to loadApprovalForUpdateQuery is not counted as a statement of
// its own.
//
// ponytail: case-sensitive, unlike tenantPredicate above. Every SQL keyword
// in this package is written uppercase, and matching case-insensitively
// counted four ordinary error strings ("store: update agent %s: %w") as
// statements — inflating the very number that is supposed to say how much
// real SQL the walk found. A lowercase query would go uncounted but is
// still checked: the finding rule runs on every string regardless.
var sqlStatement = regexp.MustCompile(`\b(SELECT\s|INSERT\s+INTO\s|UPDATE\s+[a-z_]|DELETE\s+FROM\s)`)

// queryFloor is a LOWER bound on the number of SQL statements the scan must
// find in this package, not an exact count: this is the "a scan that finds
// nothing because it looked at nothing passes silently" guard, and that
// failure mode is a collapse toward zero, not a drift of one or two.
//
// There is deliberately no upper bound. A ceiling would have to be edited
// every time a query is added — the opt-in problem this whole file exists to
// remove, reintroduced in one constant.
//
// The scan finds 40 today: 39 of this package's 40 production query
// constants (loadApprovalForUpdateQuery is loadApprovalQuery plus a
// ` FOR UPDATE` fragment, so it is counted once, at its base), plus audit.go's
// inline pg_advisory_xact_lock call. The floor leaves ten queries of room
// below that, which no plausible walk-stopped-matching bug lands in: the
// largest single production file here contributes six.
const queryFloor = 30

// tenantFilterFinding is one query that filters by tenant_id, with the
// position it was found at. A failure that names nothing is a failure an
// author cannot act on, so both fields are always reported.
type tenantFilterFinding struct {
	Pos   string // file:line:col, relative to the scanned directory
	Query string
}

func (f tenantFilterFinding) String() string {
	return fmt.Sprintf("%s: %s", f.Pos, f.Query)
}

// scanForTenantPredicates parses every non-test .go file in dir and returns
// each string expression that filters by tenant_id, along with the number of
// SQL statements it examined.
//
// It identifies a query as "a string expression": a string literal, or any
// chain of them joined by +, which is the form every query in this package
// takes. Concatenation is folded BEFORE matching, and that is load-bearing
// rather than tidiness. Most queries here are written across several backtick
// literals, and a split that falls between the column name and its operator
// — `... WHERE tenant_id` + ` = $1` — leaves neither fragment matching on its
// own. (A split before the name, `... WHERE ` + `tenant_id = $1`, would still
// be caught fragment-by-fragment; folding is what covers the other one. Both
// are pinned by TestTenantPredicateScan_CatchesAFilteringQuery.)
//
// It walks every string expression rather than only const and var
// declarations. That costs nothing extra (ast.Inspect already visits them)
// and covers inline query strings passed straight to ExecContext, of which
// this package already has one — audit.go's pg_advisory_xact_lock call.
// Restricting the walk to declarations would leave that shape as an
// unguarded way to reach the database.
func scanForTenantPredicates(dir string) ([]tenantFilterFinding, int, error) {
	fset, files, err := parseProductionFiles(dir)
	if err != nil {
		return nil, 0, err
	}

	var findings []tenantFilterFinding
	examined := 0
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := stringExprValue(expr)
			if !ok {
				// A chain with a non-literal operand never folds, and this
				// package writes that shape (loadApprovalForUpdateQuery is
				// loadApprovalQuery + ` FOR UPDATE`). Its literal parts are
				// still one contiguous fragment as far as a predicate is
				// concerned, so a split that lands inside the predicate —
				// base + ` WHERE tenant_id` + ` = $1` — is caught here and
				// nowhere else: the full fold cannot see it and neither
				// literal matches alone.
				if parts, isChain := literalParts(expr); isChain && tenantPredicate.MatchString(parts) {
					findings = append(findings, tenantFilterFinding{
						Pos:   fset.Position(expr.Pos()).String(),
						Query: parts,
					})
					return false
				}
				return true
			}
			if sqlStatement.MatchString(text) {
				examined++
			}
			if tenantPredicate.MatchString(text) {
				findings = append(findings, tenantFilterFinding{
					Pos:   fset.Position(expr.Pos()).String(),
					Query: text,
				})
			}
			// The whole concatenation is one query; descending would
			// re-count its own literals as separate statements.
			return false
		})
	}
	return findings, examined, nil
}

// parseProductionFiles parses every non-test .go file in dir and hands back
// the file set and syntax trees. Both scans in this file share it.
//
// _test.go is excluded the same way internal/policy's constructor scan
// excludes it: a test may legitimately use WHERE tenant_id to set up or
// assert against another tenant's rows — catalog_integration_test.go and
// pap_role_integration_test.go both do, and both are proving RLS works
// rather than relying on it.
//
// A file that will not parse is an error, never a skip. A scan that quietly
// ignores what it cannot read is the same defect one level up: it would
// report a clean tree because it never looked. Both invariants inherit that
// refusal from here, so one test
// (TestTenantPredicateScan_RefusesToSkipAnUnparseableFile) pins it for both.
func parseProductionFiles(dir string) (*token.FileSet, []*ast.File, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		// Object resolution is deliberately ON (no SkipObjectResolution).
		// staticSQLArg needs it to tell a genuine const from a local
		// variable that shadows a const's name — see its own comment.
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		files = append(files, file)
	}
	return fset, files, nil
}

// stringExprValue folds expr into its string value when expr is a string
// literal or a + chain of them, reporting false for anything else (an
// identifier, a function call, a runtime-built string). A chain with a
// non-literal operand is not folded, so ast.Inspect descends and evaluates
// its literal parts individually — which is what catches a filtering
// fragment appended to a named query constant.
func stringExprValue(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, ok := stringExprValue(e.X)
		if !ok {
			return "", false
		}
		right, ok := stringExprValue(e.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	default:
		return "", false
	}
}

// TestNoProductionQueryFiltersByTenantID is the guard itself: no query in
// this package's production files may filter by tenant_id, because RLS is
// the only tenant boundary and a second, divergent one is worse than none
// (see this package's own doc comment in store.go). A query added in a new
// file is covered by this the moment it is written — nobody has to remember
// to assert anything.
func TestNoProductionQueryFiltersByTenantID(t *testing.T) {
	findings, examined, err := scanForTenantPredicates(".")
	if err != nil {
		t.Fatalf("scanning internal/store: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s\n\tthis query filters by tenant_id; RLS via beginTenantTx is the only tenant boundary "+
			"in this codebase, and a redundant predicate makes it look like the Go code is protecting you "+
			"when it is not (see store.go's package doc)", f)
	}
	if examined < queryFloor {
		t.Fatalf("the scan examined %d SQL statements, want at least %d — a scan that finds no violations "+
			"because it looked at nothing is the very defect this guard exists to prevent, one level up",
			examined, queryFloor)
	}
}

// fixturePackage writes files into a fresh temp directory and returns it, so
// the tests below exercise the scan against source they control rather than
// against whatever this package happens to contain today.
func fixturePackage(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatalf("writing fixture %s: %v", name, err)
		}
	}
	return dir
}

// TestTenantPredicateScan_CatchesAFilteringQuery is the claim this whole
// file rests on, checked rather than reasoned to: the scan must actually
// catch a violation, not merely pass on a tree that has none. The finding
// must name the file and the query, since a failure naming neither leaves an
// author with nothing to act on.
// The second case is the one that pins the concatenation fold: the split
// falls between tenant_id and its operator, so neither literal matches on
// its own and only the folded string does.
func TestTenantPredicateScan_CatchesAFilteringQuery(t *testing.T) {
	tick := "`"
	tests := map[string]string{
		"predicate inside one literal": `package fixture

const listThingsQuery = ` + tick + `SELECT id, tenant_id, name ` + tick + ` +
	` + tick + `FROM things WHERE tenant_id = $1 ORDER BY name` + tick + `
`,
		"operator split across the concatenation": `package fixture

const listThingsQuery = ` + tick + `SELECT id, tenant_id, name FROM things WHERE tenant_id` + tick + ` +
	` + tick + ` = $1 ORDER BY name` + tick + `
`,
		"predicate split across a const-append chain": `package fixture

const baseThingsQuery = ` + tick + `SELECT id, tenant_id, name FROM things` + tick + `

const listThingsQuery = baseThingsQuery + ` + tick + ` WHERE tenant_id` + tick + ` + ` + tick + ` = $1` + tick + `
`,
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			dir := fixturePackage(t, map[string]string{"things.go": src})

			findings, examined, err := scanForTenantPredicates(dir)
			if err != nil {
				t.Fatalf("scanForTenantPredicates() error = %v", err)
			}
			if len(findings) != 1 {
				t.Fatalf("scan found %d findings, want exactly 1: a WHERE tenant_id predicate must be caught, got %v",
					len(findings), findings)
			}
			if examined == 0 {
				t.Error("scan examined 0 SQL statements while reporting a finding — the count is not tracking the walk")
			}
			if !strings.Contains(findings[0].Pos, "things.go") {
				t.Errorf("finding position = %q, want it to name things.go", findings[0].Pos)
			}
			if !strings.Contains(findings[0].Query, "WHERE tenant_id = $1") {
				t.Errorf("finding query = %q, want the whole folded query, including the predicate", findings[0].Query)
			}
		})
	}
}

// TestTenantPredicateScan_AllowsTenantIDAsAnInsertColumn is the carve-out
// that keeps the guard usable: an INSERT naming tenant_id as a column is how
// a row acquires its tenant, and RLS's WITH CHECK validates it. Nine of this
// package's queries have that shape, so a guard that flagged them would be
// deleted within the week.
//
// The examined-count assertion is not decoration here. "Nothing was caught"
// is exactly what a scan that examined nothing also reports, so without it
// this test would pass just as happily against a walk that had stopped
// finding queries altogether — which would make it evidence of nothing.
func TestTenantPredicateScan_AllowsTenantIDAsAnInsertColumn(t *testing.T) {
	const src = `package fixture

const insertThingQuery = ` + "`" + `INSERT INTO things (tenant_id, name, kind) ` + "`" + ` +
	` + "`" + `VALUES ($1,$2,$3) RETURNING id, tenant_id, created_at` + "`" + `

const selectThingQuery = ` + "`" + `SELECT id, tenant_id, name FROM things WHERE id = $1` + "`" + `

const setTenantFixtureQuery = ` + "`" + `SELECT set_config('app.tenant_id', $1, true)` + "`" + `
`
	dir := fixturePackage(t, map[string]string{"things.go": src})

	findings, examined, err := scanForTenantPredicates(dir)
	if err != nil {
		t.Fatalf("scanForTenantPredicates() error = %v", err)
	}
	if examined != 3 {
		t.Fatalf("scan examined %d SQL statements, want 3 — this test's whole claim is that these three "+
			"were looked at and cleared, which is indistinguishable from never looking if the count is wrong",
			examined)
	}
	if len(findings) != 0 {
		t.Errorf("scan flagged %v; tenant_id as an INSERT column, a selected column, a RETURNING column, "+
			"and the app.tenant_id session setting are all correct and must pass", findings)
	}
}

// TestTenantPredicateScan_IgnoresTestFiles pins the second carve-out: a test
// file may use WHERE tenant_id to seed or assert against another tenant's
// rows, which is how this package proves RLS works rather than a way of
// relying on it. catalog_integration_test.go and pap_role_integration_test.go
// both do exactly this today, so a scan that read _test.go files would fail
// on the tree as it stands.
func TestTenantPredicateScan_IgnoresTestFiles(t *testing.T) {
	const src = `package fixture

const probeQuery = ` + "`" + `DELETE FROM things WHERE tenant_id = $1` + "`" + `
`
	dir := fixturePackage(t, map[string]string{"things_test.go": src})

	findings, _, err := scanForTenantPredicates(dir)
	if err != nil {
		t.Fatalf("scanForTenantPredicates() error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("scan flagged %v in a _test.go file; test setup and cross-tenant assertions legitimately "+
			"use WHERE tenant_id", findings)
	}
}

// TestTenantPredicateScan_RefusesToSkipAnUnparseableFile pins that a file
// the scan cannot read is an error, not a skip. A skip would let a syntax
// error — or, worse, a future Go version this parser does not understand —
// silently remove a file from coverage while the guard still reported a
// clean tree. The unparseable file here also contains a violation, so a
// skipping scan would be reporting "clean" about a file that is not.
func TestTenantPredicateScan_RefusesToSkipAnUnparseableFile(t *testing.T) {
	const broken = `package fixture

const q = ` + "`" + `SELECT id FROM things WHERE tenant_id = $1` + "`" + `

func Oops( {
`
	dir := fixturePackage(t, map[string]string{"broken.go": broken})

	_, _, err := scanForTenantPredicates(dir)
	if err == nil {
		t.Fatal("scanForTenantPredicates() on an unparseable file = nil error, want a failure: skipping a " +
			"file it cannot read would let the guard report a clean tree it never looked at")
	}
	if !strings.Contains(err.Error(), "broken.go") {
		t.Errorf("error %q does not name the file it could not parse", err)
	}
}

// --- Second invariant: no SQL in this package is assembled at runtime -----
//
// This is what makes the scan above mean anything, and it is worth having on
// its own terms.
//
// The tenant scan reads string literals. A query assembled at runtime —
// fmt.Sprintf("... WHERE tenant_id = %s", tenant), a strings.Builder, a
// predicate appended behind an if — is not a literal, so the tenant scan
// cannot see it and reports zero findings anyway. That clean result is what
// the next author will trust, and it would be a clean result about a package
// the scan could not fully read: "no violations" and "violations I cannot
// see" would be indistinguishable. That is precisely the defect the tenant
// scan exists to remove, one level up — it looked, at the wrong thing, and
// reported clean.
//
// Every other gap in the tenant scan's coverage is visible from outside it: a
// query in cmd/*, SQL in a migration, a _test.go file. This one is not. It
// sits inside the scanned package, in scanned files, and produces a green
// run.
//
// So: no SQL here is built at runtime. That also happens to be the property
// that makes SQL injection structurally impossible in this package — every
// statement is fixed text with bound parameters — which is why it is stated
// as its own rule rather than as a footnote to the tenant scan. If you came
// here wanting to build a query dynamically, this paragraph is the argument
// to answer, not a mysterious failing test: adding one silently voids
// TestNoProductionQueryFiltersByTenantID's guarantee for your query.

// dbQueryMethods are the database/sql methods that take a SQL string, mapped
// to that string's index in the argument list — 1 for the Context variants,
// which take ctx first.
//
// ponytail: matched on method name alone, so an unrelated type with a Query
// method would be checked too. That is a false positive which fails loudly
// and is cheap to fix; the alternative is running go/types over the package
// to resolve receivers, which is a lot of machinery for a guard that needs
// none of it today.
var dbQueryMethods = map[string]int{
	"Exec": 0, "ExecContext": 1,
	"Query": 0, "QueryContext": 1,
	"QueryRow": 0, "QueryRowContext": 1,
	"Prepare": 0, "PrepareContext": 1,
}

// dbCallFloor is a floor on the number of database calls the scan must find,
// for the same reason queryFloor exists and under the same floor-never-a-
// ceiling rule. There are 43 today.
const dbCallFloor = 30

// runtimeSQLFinding is one database call whose SQL is not fixed at compile
// time, and the call site that has to change.
type runtimeSQLFinding struct {
	Pos    string
	Method string
	Arg    string // the offending argument, printed back as Go source
}

func (f runtimeSQLFinding) String() string {
	return fmt.Sprintf("%s: %s(..., %s, ...)", f.Pos, f.Method, f.Arg)
}

// scanForRuntimeSQL returns every database call in dir's production files
// whose SQL argument is not fixed at compile time, plus the number of
// database calls it examined.
//
// Fixed at compile time means a string literal, a + chain of them, or an
// identifier naming a Go const. The const case is not a hole: Go's spec
// requires a const's value to be a constant expression, so a const can never
// hold a Sprintf result. That is also what keeps this cheap — the check needs
// no type information, only the set of names declared const in the package.
//
// A local variable is deliberately NOT accepted. `q := fmt.Sprintf(...)` two
// lines above the call is the realistic shape of runtime-assembled SQL, and
// accepting any identifier would wave exactly that through while looking
// thorough.
func scanForRuntimeSQL(dir string) ([]runtimeSQLFinding, int, error) {
	fset, files, err := parseProductionFiles(dir)
	if err != nil {
		return nil, 0, err
	}

	consts := collectConsts(files)

	var findings []runtimeSQLFinding
	examined := 0
	forEachDBCall(files, func(method string, arg ast.Expr) {
		examined++
		if !staticSQLArg(arg, consts) {
			findings = append(findings, runtimeSQLFinding{
				Pos:    fset.Position(arg.Pos()).String(),
				Method: method,
				Arg:    exprSource(fset, arg),
			})
		}
	})
	return findings, examined, nil
}

// collectConsts maps every const name declared in files to its folded string
// value, or "" when the value is not a foldable string literal chain. Names
// are collected across every file before any call site is checked: a call in
// agent.go names a const declared in store.go, and go/parser's own
// resolution does not cross files.
func collectConsts(files []*ast.File) map[string]bool {
	consts := map[string]bool{}
	for name := range constValues(files) {
		consts[name] = true
	}
	return consts
}

// constValues is collectConsts' underlying map, kept separate because the
// reconciliation below needs the values and staticSQLArg needs only the
// names.
func constValues(files []*ast.File) map[string]string {
	values := map[string]string{}
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			decl, ok := n.(*ast.GenDecl)
			if !ok || decl.Tok != token.CONST {
				return true
			}
			for _, spec := range decl.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					value := ""
					if i < len(vs.Values) {
						value, _ = stringExprValue(vs.Values[i])
					}
					values[name.Name] = value
				}
			}
			return true
		})
	}
	return values
}

// forEachDBCall calls fn for every database call in files, with the method
// name and the expression in its SQL-argument position. Shared by the
// runtime scan and the reconciliation so both agree, by construction, on
// what "a call this scan examined" means.
func forEachDBCall(files []*ast.File, fn func(method string, arg ast.Expr)) {
	for _, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			idx, ok := dbQueryMethods[sel.Sel.Name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			fn(sel.Sel.Name, call.Args[idx])
			return true
		})
	}
}

// unreachedQueryConsts returns every const in dir holding a SQL statement
// that no database call the scan examined ever names, plus the number of
// query constants it reconciled.
//
// This is what stops dbQueryMethods from being a remembered list. The map is
// hand-maintained, and a call whose method name is not in it is not examined
// and does not exist as far as either scan is concerned — adopting sqlx or
// pgx incrementally is an ordinary refactor, not an evasion, and it would
// quietly take call sites out of coverage while both tests stayed green. The
// floor cannot see that: dropping 12 of 43 calls still clears 30.
//
// The cross-check is independent because it is derived from a different part
// of the syntax tree. The query constants come from string-literal
// declarations; the reference set comes from call expressions. Renaming a
// call leaves its query constant exactly where it was, so the constant goes
// unreferenced and is named here. Both would have to fail in the same
// direction, at once, to stay silent together.
//
// This is the every-run form of the reconciliation migrations_test.go's
// reconcileTableCount performs, and which the first version of this file did
// only by hand, once, in a report.
//
// ponytail: the alternative considered was asserting that no production file
// imports a SQL library other than database/sql and lib/pq (today's only
// non-stdlib imports here are lib/pq and google/uuid). That is fewer lines
// but strictly weaker: it catches a new dependency, not a hand-rolled
// wrapper type in this package with a Fetch method. Reconciliation catches
// both, because it asks where the queries went rather than what was
// imported.
func unreachedQueryConsts(dir string) ([]string, int, error) {
	_, files, err := parseProductionFiles(dir)
	if err != nil {
		return nil, 0, err
	}

	referenced := map[string]bool{}
	forEachDBCall(files, func(_ string, arg ast.Expr) {
		// Every identifier in the argument counts, so a const appended to
		// (loadApprovalQuery + ` FOR UPDATE`) still marks its base used.
		ast.Inspect(arg, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				referenced[id.Name] = true
			}
			return true
		})
	})

	var unreached []string
	queries := 0
	for name, value := range constValues(files) {
		if !sqlStatement.MatchString(value) {
			continue
		}
		queries++
		if !referenced[name] {
			unreached = append(unreached, name)
		}
	}
	sort.Strings(unreached)
	return unreached, queries, nil
}

// staticSQLArg reports whether expr is SQL fixed at compile time: a string
// literal, an identifier that IS a const, or a + chain of those.
//
// "Is a const" is asked of the identifier, not of its spelling. Checking the
// name against the package's const set alone accepts a local variable that
// shadows the constant it is derived from —
//
//	const listQuery = `SELECT id, name FROM things`
//	listQuery := fmt.Sprintf(`DELETE FROM things WHERE %s = $1`, "tenant_id")
//	tx.ExecContext(ctx, listQuery, tenant)
//
// — which compiles, vets clean, and is what a developer actually types when
// modifying the query they are looking at. Nothing adversarial about it.
//
// go/parser resolves identifiers within a file, so any local declaration —
// which is always in the same file as its use — comes back with a non-nil
// Obj naming what it really is. A nil Obj means the identifier is not
// declared in this file, so it is a package-level name from a sibling file,
// and only then does the cross-file const set get consulted. That set is
// still needed: resolution does not cross files.
//
// A package-level var holding SQL resolves to ast.Var and is rejected, which
// is correct rather than incidental — //go:embed writes SQL into a var, and
// SQL that arrives from outside the scanned source is exactly what neither
// scan can read.
func staticSQLArg(expr ast.Expr, consts map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return e.Kind == token.STRING
	case *ast.Ident:
		if e.Obj != nil {
			return e.Obj.Kind == ast.Con
		}
		return consts[e.Name]
	case *ast.BinaryExpr:
		return e.Op == token.ADD && staticSQLArg(e.X, consts) && staticSQLArg(e.Y, consts)
	default:
		return false
	}
}

// literalParts concatenates every string literal in a + chain in source
// order, skipping the operands that are not literals, and reports whether
// expr was a + chain at all. It is the fallback for what stringExprValue
// refuses to fold; a chain of one literal is not a chain, so an ordinary
// string is left to the main path.
func literalParts(expr ast.Expr) (string, bool) {
	bin, ok := expr.(*ast.BinaryExpr)
	if !ok || bin.Op != token.ADD {
		return "", false
	}
	var out strings.Builder
	ast.Inspect(expr, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				out.WriteString(s)
			}
		}
		return true
	})
	return out.String(), true
}

// exprSource prints expr back as Go source, so a failure shows the argument
// the author actually wrote instead of an AST node type.
func exprSource(fset *token.FileSet, expr ast.Expr) string {
	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return fmt.Sprintf("<unprintable %T>", expr)
	}
	return buf.String()
}

// TestNoRuntimeAssembledSQL is the second invariant's guard: every database
// call in this package's production files passes SQL that is fixed at compile
// time.
func TestNoRuntimeAssembledSQL(t *testing.T) {
	findings, examined, err := scanForRuntimeSQL(".")
	if err != nil {
		t.Fatalf("scanning internal/store: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s\n\tthis call's SQL is not fixed at compile time; every query in this package must be "+
			"fixed text with bound parameters. It is also unreadable to "+
			"TestNoProductionQueryFiltersByTenantID, which scans string literals — so a tenant predicate "+
			"reaching the database this way would make that guard report a clean tree it could not "+
			"actually see.\n\tIf the argument is a function parameter, this is a shared query helper rather "+
			"than assembled SQL: the SQL is still fixed, but it is fixed at the helper's call sites, which "+
			"this scan does not follow. Inline the helper, or teach the scan to resolve it — do not "+
			"weaken staticSQLArg to accept parameters, which would accept genuine runtime assembly too", f)
	}
	if examined < dbCallFloor {
		t.Fatalf("the scan examined %d database calls, want at least %d — a scan that finds no violations "+
			"because it looked at nothing is the very defect this guard exists to prevent, one level up",
			examined, dbCallFloor)
	}
}

// TestRuntimeSQLScan_CatchesAssembledSQL checks the claim rather than
// reasoning to it. Both realistic shapes are covered: the Sprintf inline at
// the call site, and — the one an "argument contains no call expression"
// check would miss — the Sprintf assigned to a local variable two lines
// above it.
func TestRuntimeSQLScan_CatchesAssembledSQL(t *testing.T) {
	tick := "`"
	src := `package fixture

import (
	"context"
	"database/sql"
	"fmt"
)

func inlineSprintf(ctx context.Context, tx *sql.Tx, tenant string) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf(` + tick + `DELETE FROM things WHERE tenant_id = %q` + tick + `, tenant))
	return err
}

func viaLocalVariable(ctx context.Context, tx *sql.Tx, tenant string) error {
	q := fmt.Sprintf(` + tick + `DELETE FROM things WHERE tenant_id = %q` + tick + `, tenant)
	_, err := tx.ExecContext(ctx, q)
	return err
}

const listQuery = ` + tick + `SELECT id, name FROM things` + tick + `

func viaLocalShadowingTheConst(ctx context.Context, tx *sql.Tx, tenant string) error {
	listQuery := fmt.Sprintf(` + tick + `DELETE FROM things WHERE %s = $1` + tick + `, "tenant_id")
	_, err := tx.ExecContext(ctx, listQuery, tenant)
	return err
}
`
	dir := fixturePackage(t, map[string]string{"things.go": src})

	findings, examined, err := scanForRuntimeSQL(dir)
	if err != nil {
		t.Fatalf("scanForRuntimeSQL() error = %v", err)
	}
	if examined != 3 {
		t.Fatalf("scan examined %d database calls, want 3", examined)
	}

	// Asserted per shape, not by count. A count check would let a mutation
	// that blinds the scan to one shape while it still catches another die on
	// "wrong number", which is not evidence that the shape in question is
	// covered — the shape has to be named.
	seen := map[string]bool{}
	for _, f := range findings {
		if !strings.Contains(f.Pos, "things.go") {
			t.Errorf("finding position = %q, want it to name things.go", f.Pos)
		}
		if f.Method != "ExecContext" {
			t.Errorf("finding method = %q, want ExecContext", f.Method)
		}
		switch {
		case strings.HasPrefix(f.Arg, "fmt.Sprintf("):
			seen["inline Sprintf"] = true
		case f.Arg == "q":
			seen["local variable"] = true
		case f.Arg == "listQuery":
			seen["local shadowing a const's name"] = true
		default:
			t.Errorf("unexpected finding argument %q", f.Arg)
		}
	}
	for _, shape := range []string{"inline Sprintf", "local variable", "local shadowing a const's name"} {
		if !seen[shape] {
			t.Errorf("the %s shape was not caught; findings were %v", shape, findings)
		}
	}
}

// TestRuntimeSQLScan_AllowsConstantsAndLiterals is the carve-out: the three
// shapes this package actually uses must pass. The examined-count assertion
// is load-bearing for the same reason it is in the tenant scan's carve-out
// test — "nothing was caught" is also what a scan that examined nothing
// reports.
func TestRuntimeSQLScan_AllowsConstantsAndLiterals(t *testing.T) {
	tick := "`"
	src := `package fixture

import (
	"context"
	"database/sql"
)

const deleteThingQuery = ` + tick + `DELETE FROM things WHERE id = $1` + tick + `

func viaConst(ctx context.Context, tx *sql.Tx, id string) error {
	_, err := tx.ExecContext(ctx, deleteThingQuery, id)
	return err
}

func viaLiteral(ctx context.Context, tx *sql.Tx, tenant string) error {
	_, err := tx.ExecContext(ctx, ` + tick + `SELECT pg_advisory_xact_lock(hashtext($1))` + tick + `, tenant)
	return err
}

func viaConstPlusLiteral(ctx context.Context, tx *sql.Tx, id string) error {
	return tx.QueryRowContext(ctx, deleteThingQuery+` + tick + ` RETURNING name` + tick + `, id).Err()
}
`
	dir := fixturePackage(t, map[string]string{"things.go": src})

	findings, examined, err := scanForRuntimeSQL(dir)
	if err != nil {
		t.Fatalf("scanForRuntimeSQL() error = %v", err)
	}
	if examined != 3 {
		t.Fatalf("scan examined %d database calls, want 3 — this test's claim is that these three were "+
			"looked at and cleared, which is indistinguishable from never looking if the count is wrong",
			examined)
	}
	if len(findings) != 0 {
		t.Errorf("scan flagged %v; a named const, a string literal, and a const + literal chain are all "+
			"fixed at compile time and must pass", findings)
	}
}

// TestEveryQueryConstIsReachedByAScannedCall is what stops dbQueryMethods
// from being the remembered list the rest of this file exists to delete.
//
// A database call whose method name is not in that map is not examined, and
// does not exist as far as either scan is concerned. Renaming this package's
// calls to sqlx-style names — an ordinary incremental refactor, not an
// evasion — took 12 of 43 call sites out of coverage in review with both
// scans still green, because a floor detects collapse and not erosion: 31
// still clears 30.
//
// Reconciling the query constants against the calls that reference them
// catches exactly that, every run, with no constant to maintain. A renamed
// call leaves its query constant untouched and unreferenced, so the constant
// is named here.
func TestEveryQueryConstIsReachedByAScannedCall(t *testing.T) {
	unreached, queries, err := unreachedQueryConsts(".")
	if err != nil {
		t.Fatalf("reconciling internal/store: %v", err)
	}
	for _, name := range unreached {
		t.Errorf("query constant %s is never named by a database call this scan examined.\n"+
			"\tEither it is dead and should be deleted, or it reaches the database through a method "+
			"dbQueryMethods does not know — in which case TestNoRuntimeAssembledSQL silently stopped "+
			"covering that call, and the map is what needs updating", name)
	}
	// Reconciling nothing against nothing passes; the same trap, one level
	// down. Shares queryFloor because it counts the same thing from the other
	// direction — named query constants rather than SQL statements.
	if queries < queryFloor {
		t.Fatalf("reconciled %d query constants, want at least %d — a reconciliation with nothing on "+
			"either side is vacuous", queries, queryFloor)
	}
}

// TestQueryConstReconciliation_CatchesAnUnscannedCall checks that claim
// instead of reasoning to it, using the exact scenario from review: a call
// renamed to something dbQueryMethods does not know. The scanned query must
// stay silent, so the fixture proves the reconciliation discriminates rather
// than simply reporting everything.
func TestQueryConstReconciliation_CatchesAnUnscannedCall(t *testing.T) {
	tick := "`"
	src := `package fixture

import (
	"context"
	"database/sql"
)

const scannedQuery = ` + tick + `SELECT id FROM things WHERE id = $1` + tick + `

const unscannedQuery = ` + tick + `SELECT id, tenant_id FROM things` + tick + `

func scanned(ctx context.Context, tx *sql.Tx, id string) error {
	return tx.QueryRowContext(ctx, scannedQuery, id).Err()
}

func unscanned(ctx context.Context, db *sqlxDB, out *[]string) error {
	return db.SelectContext(ctx, out, unscannedQuery)
}
`
	dir := fixturePackage(t, map[string]string{"things.go": src})

	unreached, queries, err := unreachedQueryConsts(dir)
	if err != nil {
		t.Fatalf("unreachedQueryConsts() error = %v", err)
	}
	if queries != 2 {
		t.Fatalf("reconciled %d query constants, want 2 — the fixture declares two, and a reconciliation "+
			"that saw neither would report nothing unreached for the wrong reason", queries)
	}
	if len(unreached) != 1 || unreached[0] != "unscannedQuery" {
		t.Fatalf("unreached = %v, want exactly [unscannedQuery]: the SelectContext call is invisible to "+
			"dbQueryMethods, and scannedQuery must not be reported since QueryRowContext is scanned",
			unreached)
	}
}
