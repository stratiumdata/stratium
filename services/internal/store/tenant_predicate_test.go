package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
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
// rather than tidiness — most queries here are written across several
// backtick literals, so a predicate split as `... WHERE ` + `tenant_id = $1`
// would be invisible to a per-literal check.
//
// It walks every string expression rather than only const and var
// declarations. That costs nothing extra (ast.Inspect already visits them)
// and covers inline query strings passed straight to ExecContext, of which
// this package already has one — audit.go's pg_advisory_xact_lock call.
// Restricting the walk to declarations would leave that shape as an
// unguarded way to reach the database.
//
// A file that will not parse is an error, never a skip. A scan that quietly
// ignores what it cannot read is the same defect one level up: it would
// report a clean tree because it never looked.
func scanForTenantPredicates(dir string) ([]tenantFilterFinding, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("reading %s: %w", dir, err)
	}

	var findings []tenantFilterFinding
	examined := 0
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		// _test.go is excluded the same way internal/policy's constructor
		// scan excludes it: a test may legitimately use WHERE tenant_id to
		// set up or assert against another tenant's rows — catalog_
		// integration_test.go and pap_role_integration_test.go both do,
		// and both are proving RLS works rather than relying on it.
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, 0, fmt.Errorf("parsing %s: %w", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := stringExprValue(expr)
			if !ok {
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
func TestTenantPredicateScan_CatchesAFilteringQuery(t *testing.T) {
	const src = `package fixture

const listThingsQuery = ` + "`" + `SELECT id, tenant_id, name ` + "`" + ` +
	` + "`" + `FROM things WHERE tenant_id = $1 ORDER BY name` + "`" + `
`
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
		t.Errorf("finding query = %q, want the offending query text", findings[0].Query)
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
