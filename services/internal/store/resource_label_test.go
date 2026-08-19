package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"go/ast"
	"go/token"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// resourceLabelRuleColumns is loadResourceLabelRulesQuery's own column order,
// factored out since every LoadResourceLabelRules test below builds rows
// against it.
func resourceLabelRuleColumns() []string { return []string{"prefix", "hierarchy", "level"} }

// loadResourceLabelRulesQuery's text is asserted directly, the same reason
// TestLoadTenantEpochQuery_HasNoTenantIDClause and
// TestLoadAllPoliciesQuery_FiltersEnabledOrdersByIDAndIgnoresLanguage inspect
// their own queries' text: sqlmock never runs real SQL, so this is the only
// way a unit test pins "no WHERE tenant_id" and "no prefix matching in SQL" as
// properties of the query ITSELF rather than of whatever text the mock was
// told to expect.
//
// The three absence checks are not decoration. LIKE/~~ and a prefix predicate
// would each be a second implementation of R5/R6's matching rules living in
// SQL beside pkg/classification.Resolve's tested one — the specific mistake
// this task was told not to make — and the two are free to disagree about
// case-sensitivity, ties, and the empty-prefix catch-all.
func TestLoadResourceLabelRulesQuery_HasNoTenantIDClauseAndNoMatchingInSQL(t *testing.T) {
	if strings.Contains(loadResourceLabelRulesQuery, "tenant_id") {
		t.Errorf("loadResourceLabelRulesQuery = %q, must not reference tenant_id — RLS is the only tenant boundary",
			loadResourceLabelRulesQuery)
	}
	if strings.Contains(loadResourceLabelRulesQuery, "WHERE") {
		t.Errorf("loadResourceLabelRulesQuery = %q, want no WHERE clause at all: the whole rule set is loaded and "+
			"matched in pkg/classification.Resolve", loadResourceLabelRulesQuery)
	}
	for _, matcher := range []string{"LIKE", "~~", "^@", "position(", "starts_with"} {
		if strings.Contains(loadResourceLabelRulesQuery, matcher) {
			t.Errorf("loadResourceLabelRulesQuery = %q, must not contain %q — prefix matching belongs to "+
				"pkg/classification.Resolve, and a second matcher in SQL would be free to disagree with it",
				loadResourceLabelRulesQuery, matcher)
		}
	}
	if !strings.Contains(loadResourceLabelRulesQuery, "ORDER BY prefix, hierarchy, level") {
		t.Errorf("loadResourceLabelRulesQuery = %q, want ORDER BY on all three selected columns: ordering on "+
			"prefix alone would be total only if prefix were unique, which is a schema constraint and "+
			"therefore not a runtime one — the exact distinction validateResourceLabelRule's own doc comment "+
			"insists on", loadResourceLabelRulesQuery)
	}
}

// A full rule set loads intact, in the exact order this package requires —
// begin, THEN set the tenant, THEN the data query, THEN commit (sqlmock
// matches expectations in order; newMockStore's own doc comment).
//
// Three rows, three scanned fields each, and no value repeated anywhere across
// the nine: a transposition in the Scan call — prefix/hierarchy swapped,
// hierarchy/level swapped — shows up as a wrong assertion on a named field and
// can never pass by coincidence. The fixture deliberately mixes hierarchies
// and includes the empty-prefix catch-all, so "the loader drops the catch-all"
// is a distinguishable failure too.
func TestStore_LoadResourceLabelRules_RoundTripsFieldForField(t *testing.T) {
	s, mock := newMockStore(t)

	want := []classification.Rule{
		{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/reports/q3", Hierarchy: "NATO", Level: "restricted"},
	}

	rows := sqlmock.NewRows(resourceLabelRuleColumns())
	for _, r := range want {
		rows.AddRow(r.Prefix, r.Hierarchy, r.Level)
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).WillReturnRows(rows)
	mock.ExpectCommit()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err != nil {
		t.Fatalf("LoadResourceLabelRules() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("LoadResourceLabelRules() returned %d rules, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no rules is an ordinary, empty result — never an error, and
// never a nil slice a caller might have to nil-check before ranging. This is
// the state every tenant is in until an operator registers a rule, and R2/R7
// make it deny at CheckCap rather than default to a level; nothing here
// substitutes one.
func TestStore_LoadResourceLabelRules_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
		WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()))
	mock.ExpectCommit()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err != nil {
		t.Fatalf("LoadResourceLabelRules() error = %v, want nil — no rules is an ordinary state, not a failure", err)
	}
	if got == nil {
		t.Error("LoadResourceLabelRules() = nil, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("LoadResourceLabelRules() = %v, want empty", got)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadResourceLabelRules_QueryErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err == nil {
		t.Fatal("LoadResourceLabelRules() error = nil, want error")
	}
	if got != nil {
		t.Errorf("LoadResourceLabelRules() = %v, want nil alongside a non-nil error", got)
	}

	assertExpectationsMet(t, mock)
}

// A row that fails mid-iteration must abort the whole load rather than return
// the rules read so far. A partial rule set is not a smaller rule set: dropping
// the longest-prefix carve-out silently promotes a shorter, higher rule to the
// winner, which is a classification change nothing would report.
func TestStore_LoadResourceLabelRules_RowErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	rows := sqlmock.NewRows(resourceLabelRuleColumns()).
		AddRow("/data/", "nato", "SECRET").
		RowError(0, errors.New("read error mid-iteration"))

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err == nil {
		t.Fatal("LoadResourceLabelRules() error = nil, want the row error to propagate")
	}
	if got != nil {
		t.Errorf("LoadResourceLabelRules() = %v, want nil — never a partial rule set", got)
	}

	assertExpectationsMet(t, mock)
}

// A column that will not scan into its Go field must abort the load, not
// contribute a zero-valued rule. A Rule with an empty Prefix is R7's
// catch-all — it matches EVERYTHING — so a scan failure quietly yielding one
// would turn a corrupt row into a tenant-wide label.
func TestStore_LoadResourceLabelRules_ScanErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
		WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()).AddRow(nil, "nato", "SECRET"))
	mock.ExpectRollback()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err == nil {
		t.Fatal("LoadResourceLabelRules() error = nil, want a scan error")
	}
	if got != nil {
		t.Errorf("LoadResourceLabelRules() = %v, want nil on a scan failure", got)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadResourceLabelRules_SetTenantFailsRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(setTenantQuery)).
		WithArgs(testTenant).
		WillReturnError(errors.New("invalid_parameter_value"))
	mock.ExpectRollback()

	if _, err := s.LoadResourceLabelRules(context.Background()); err == nil {
		t.Fatal("LoadResourceLabelRules() error = nil, want error when the tenant-set statement fails")
	}

	assertExpectationsMet(t, mock)
}

// expectResourceLabelRuleWrite registers the full successful write: the INSERT
// with its exact arguments, then the audit append's three statements (N4, in
// the same transaction), then the commit. id is what the schema's own
// uuid_generate_v4() DEFAULT would have generated, handed back through the
// INSERT's RETURNING clause.
func expectResourceLabelRuleWrite(mock sqlmock.Sqlmock, rule models.ResourceLabelRule, id uuid.UUID) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WithArgs(testTenant, rule.Prefix, rule.Hierarchy, rule.Level).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// TestStore_CreateResourceLabelRule_ValidRowsPersist covers every shape a
// legal rule takes, each with a CONSUMED write expectation rather than merely
// err == nil: the ordinary case, the empty-prefix catch-all R7 depends on, and
// a hierarchy and level whose casing differs from Levels' own — accepted
// because Index folds when it compares, and stored VERBATIM (the WithArgs
// assertion is what pins that nothing normalises on the way in).
func TestStore_CreateResourceLabelRule_ValidRowsPersist(t *testing.T) {
	tests := []struct {
		name string
		rule models.ResourceLabelRule
	}{
		{"ordinary rule", models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}},
		{"R7's empty-prefix catch-all", models.ResourceLabelRule{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"}},
		{"casing an operator typed, stored verbatim", models.ResourceLabelRule{Prefix: "/x", Hierarchy: "NATO", Level: "secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			id := uuid.New()
			expectResourceLabelRuleWrite(mock, tt.rule, id)

			created, err := s.CreateResourceLabelRule(context.Background(), tt.rule, "operator-1", time.Now())
			if err != nil {
				t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want nil", tt.rule, err)
			}
			// The returned id is the handle the PAP's update-by-id and
			// delete-by-id routes name, and the only place an operator gets it
			// without a second round trip. A create that returned the zero
			// UUID would look successful and leave the rule unaddressable.
			if created.ID != id {
				t.Errorf("CreateResourceLabelRule().ID = %s, want %s (read back from the INSERT's RETURNING)",
					created.ID, id)
			}
			if created.TenantID != testTenant {
				t.Errorf("CreateResourceLabelRule().TenantID = %q, want %q (set authoritatively by the store, "+
					"never from the request)", created.TenantID, testTenant)
			}
			if created.Rule() != tt.rule.Rule() {
				t.Errorf("CreateResourceLabelRule() = %+v, want the three operator-owned fields returned "+
					"verbatim from %+v", created, tt.rule)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_ResourceLabelRuleWrites_InvalidLabelRefusedBeforePersisting is the
// write-time validation the brief requires, at the Go-side layer that holds it
// (there is no CHECK constraint for this — see the migration's own comment).
// The zero-expectation mock is the proof it happens BEFORE the database is
// touched: a mutant that deleted the check would reach the empty mock and fail
// with sqlmock's own "was not expected" error rather than this errors.Is
// assertion.
//
// EVERY WRITE PATH, not just create. The fixtures below run against
// CreateResourceLabelRule AND UpdateResourceLabelRule, from one table, because
// the property at stake is not "create validates" but "there is one validator
// and both callers reach it." Task 2's own report flagged this as the ranked
// risk of adding an update: a second copy of the rule, reached only by the
// update path, is exactly the drift a schema CHECK enumerating the ten
// (hierarchy, level) pairs was rejected for (migrations/000019), and it would
// be worse for sharing a name with the original. Two mutants make the
// difference visible: deleting the check from either method leaves the other's
// subtests green, and only this table's other half fails.
//
// The fixtures are chosen so that a WEAKER check cannot pass them:
//
//   - "PUBLIC" under "nato" is a REAL level of a REAL hierarchy, just not that
//     one. A check that only asked "is this string a level somewhere?" accepts
//     it; only one that ranks the level WITHIN its hierarchy refuses it. A
//     fixture using a nonsense level could not tell the two apart, which is
//     exactly the class of fixture this project keeps finding.
//   - "natoo" is R9's own one-typed-character example, verbatim.
//   - the two empty cases pin that "" is not silently treated as a wildcard on
//     the fields where it would mean nothing — deliberately unlike prefix,
//     whose own empty case is a legal catch-all proven to persist above.
//
// Each case also asserts WHICH of the two checks fired, by its message. The
// two overlap on the verdict — Index returns -1 for an unknown hierarchy just
// as it does for an unknown level — so a mutant that removed the
// unknown-hierarchy branch would still refuse every fixture here and would
// survive a test that only asserted ErrInvalidRequest. What it would destroy
// is the message: an unknown hierarchy would be reported as "level
// UNCLASSIFIED is not a level of hierarchy natoo (known: )", listing an empty
// set of levels, which is not the error an operator can act on. Since a better
// error is the entire value this check delivers (R9: not the enforcement), the
// message is the property worth pinning.
func TestStore_ResourceLabelRuleWrites_InvalidLabelRefusedBeforePersisting(t *testing.T) {
	// The two messages validateResourceLabelRule can produce, named once so
	// each case below says which of the two checks it expects to have fired.
	const (
		unknownHierarchyMsg = "unknown classification hierarchy"
		unknownLevelMsg     = "is not a level of hierarchy"
	)
	// The write paths under test, named by the method an operator's request
	// reaches. Adding a third write to this table without adding it here is
	// meant to look like an omission.
	writes := map[string]func(*Store, models.ResourceLabelRule) error{
		"CreateResourceLabelRule": func(s *Store, rule models.ResourceLabelRule) error {
			_, err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now())
			return err
		},
		"UpdateResourceLabelRule": func(s *Store, rule models.ResourceLabelRule) error {
			_, err := s.UpdateResourceLabelRule(context.Background(), uuid.New(), rule, "operator-1", time.Now())
			return err
		},
	}
	tests := []struct {
		name     string
		rule     models.ResourceLabelRule
		wantMsgs []string
	}{
		{
			"a real level, but of the other hierarchy",
			models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "PUBLIC"},
			// The known-levels list must be nato's, not commercial's: an
			// operator told "PUBLIC is not a level of nato" needs to be shown
			// what nato's levels ARE, and TOP-SECRET appears in no other
			// hierarchy.
			[]string{unknownLevelMsg, `"PUBLIC"`, `"nato"`, "TOP-SECRET"},
		},
		{
			"R9's typo: natoo for nato",
			models.ResourceLabelRule{Prefix: "/data/x/", Hierarchy: "natoo", Level: "UNCLASSIFIED"},
			// The hierarchy branch, not the level branch: both refuse, but only
			// this one can list the hierarchies that do exist. The level branch
			// would report "(known: )" — an empty set — because natoo has no
			// levels to list.
			[]string{unknownHierarchyMsg, `"natoo"`, "nato", "commercial"},
		},
		{
			"a level that exists nowhere",
			models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "commercial", Level: "MOSTLY-SECRET"},
			[]string{unknownLevelMsg, `"MOSTLY-SECRET"`, `"commercial"`, "HIGHLY-CONFIDENTIAL"},
		},
		{
			"empty hierarchy",
			models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "", Level: "SECRET"},
			[]string{unknownHierarchyMsg},
		},
		{
			"empty level",
			models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: ""},
			[]string{unknownLevelMsg},
		},
	}
	for method, write := range writes {
		for _, tt := range tests {
			t.Run(method+"/"+tt.name, func(t *testing.T) {
				s, mock := newMockStore(t)

				err := write(s, tt.rule)
				if !errors.Is(err, ErrInvalidRequest) {
					t.Fatalf("%s(%+v) error = %v, want ErrInvalidRequest", method, tt.rule, err)
				}
				// The message must name the value the operator got wrong: this
				// check exists to be a good error at the point of the typo, and
				// an error that said only "invalid rule" would not be one.
				for _, want := range tt.wantMsgs {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error = %q, want it to name %s", err, want)
					}
				}

				assertExpectationsMet(t, mock) // zero expectations: nothing reached the database
			})
		}
	}
}

// TestResourceLabelRuleWrites_ShareOneValidator states, structurally, what the
// table above proves behaviourally: every write path in resource_label.go that
// can put a rule INTO this table calls the SAME validateResourceLabelRule, and
// none carries a private copy of the rule.
//
// A behavioural test alone cannot say this. Two identical, independently
// written validators pass every fixture above on the day they are written and
// drift apart on the day one of them is corrected — which is the entire
// argument migrations/000019 makes against a CHECK constraint enumerating the
// ten (hierarchy, level) pairs, transposed one layer up into Go. The only place
// a second copy is visible is the source, so this reads the source, the same
// shape TestNoProductionQueryFiltersByTenantID (tenant_predicate_test.go) uses
// for the tenancy constraint.
//
// It DISCOVERS the write paths rather than naming them, which is the property
// that guard has and an earlier version of this one did not. That version
// checked a hardcoded pair of method names, so an UpsertResourceLabelRule added
// tomorrow with no validation at all would have left it green — a guard that
// only covers what its author remembered is the thing this project keeps
// replacing. The walk is two steps:
//
//  1. Find every query constant in the file whose SQL writes a rule into the
//     table (INSERT INTO / UPDATE resource_label_rules). A future write path
//     needs a query, and its query has to say one of those two things.
//  2. Require exactly one validator call from every function that mentions one
//     of those constants.
//
// DELETE is deliberately not among them: a delete supplies no rule, so there is
// nothing for the validator to have an opinion about. That is why step 1 keys
// on the two writing verbs rather than on "any query naming this table."
//
// Scoped to the PACKAGE, not to one file. It read resource_label.go by name
// until the Task 6 review pointed out the hole that leaves: a future
// UpsertResourceLabelRule in a new internal/store/*.go, with its own INSERT and
// no validator call, was invisible to a scan bounded by a filename — and the
// filename bound bought nothing, because parseProductionFiles (tenant_predicate
// _test.go) already walks the whole package for exactly this kind of scan.
//
// Still deliberately narrow in one respect: it proves no SECOND copy is reached
// by a write path. It does not attempt to prove no validation logic exists
// anywhere in the package by any other name — a negative claim about a whole
// package that a source scan cannot honestly make.
func TestResourceLabelRuleWrites_ShareOneValidator(t *testing.T) {
	_, files, err := parseProductionFiles(".")
	if err != nil {
		t.Fatalf("parsing internal/store: %v", err)
	}
	// A floor on the scan's own input, ahead of the two below: a package walk
	// that returned nothing would satisfy every later assertion by finding no
	// writers to object to.
	if len(files) < 2 {
		t.Fatalf("parsed %d production files in internal/store, want at least 2 — the scan cannot have "+
			"looked at the package it is meant to check", len(files))
	}

	// Step 1: the query constants that write a rule into the table.
	writeQueries := map[string]bool{}
	for _, decl := range allDecls(files) {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			sql := strings.ToUpper(constText(vs))
			if strings.Contains(sql, "INSERT INTO RESOURCE_LABEL_RULES") ||
				strings.Contains(sql, "UPDATE RESOURCE_LABEL_RULES") {
				for _, name := range vs.Names {
					writeQueries[name.Name] = true
				}
			}
		}
	}
	// A floor, for the reason tenant_predicate_test.go's own queryFloor exists:
	// a scan that passed because it found nothing to look at is the defect this
	// guard is supposed to prevent, one level up. Two today (insert, update).
	if len(writeQueries) < 2 {
		t.Fatalf("found %d rule-writing query constants in internal/store (%v), want at least 2 — the scan "+
			"cannot have looked at the write paths it is meant to check", len(writeQueries), writeQueries)
	}

	// Step 2: every function mentioning one must call the validator exactly once.
	checked := 0
	for _, decl := range allDecls(files) {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		writes, validates := false, 0
		ast.Inspect(fn, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.Ident:
				if writeQueries[node.Name] {
					writes = true
				}
			case *ast.CallExpr:
				if ident, ok := node.Fun.(*ast.Ident); ok && ident.Name == "validateResourceLabelRule" {
					validates++
				}
			}
			return true
		})
		if !writes {
			continue
		}
		checked++
		if validates != 1 {
			t.Errorf("%s writes a rule (it names %v) but calls validateResourceLabelRule %d times, want exactly 1 "+
				"— every write path must reach the one validator, and a path that validates twice, or not at "+
				"all, or through a copy of its own, is the drift migrations/000019 rejected a duplicate CHECK "+
				"constraint to avoid", fn.Name.Name, writeQueryNames(writeQueries), validates)
		}
	}
	if checked < 2 {
		t.Fatalf("the scan checked %d write paths, want at least 2 (create and update) — a guard that found no "+
			"violations because it found no write paths is worse than none", checked)
	}
}

// constText concatenates the string literals a const spec is built from, so a
// query assembled by `+`-appending several backtick literals (this package's
// house style, so the source stays inside its line limit) is matched on the
// whole SQL rather than on whichever fragment happens to carry the verb.
func constText(vs *ast.ValueSpec) string {
	var b strings.Builder
	for _, value := range vs.Values {
		ast.Inspect(value, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if unquoted, err := strconv.Unquote(lit.Value); err == nil {
					b.WriteString(unquoted)
				}
			}
			return true
		})
	}
	return b.String()
}

// writeQueryNames sorts the discovered constant names so a failure names the
// same set every time rather than in Go's randomised map order — the same
// reason knownHierarchies (resource_label.go) exists.
func writeQueryNames(set map[string]bool) []string {
	return slices.Sorted(maps.Keys(set))
}

// The refusal above must not be read as a downstream guarantee. This pins the
// narrower claim the code actually makes: LoadResourceLabelRules returns
// whatever rows the table holds, including a rule naming a hierarchy no
// validation would have accepted, because a stale read, an in-flight
// migration, or a store bug can each produce one. R9 is explicit that
// write-time validation is a better error message, not the enforcement — and
// the enforcement (an unrankable label never reaching a permissive branch) is
// Task 3's, in CheckCap, not this package's.
func TestStore_LoadResourceLabelRules_ReturnsRowsValidationWouldHaveRefused(t *testing.T) {
	s, mock := newMockStore(t)

	unrankable := classification.Rule{Prefix: "/data/x/", Hierarchy: "natoo", Level: "UNCLASSIFIED"}
	if err := validateResourceLabelRule(unrankable); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("fixture is not actually a refusable rule: validate returned %v", err)
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
		WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()).
			AddRow(unrankable.Prefix, unrankable.Hierarchy, unrankable.Level))
	mock.ExpectCommit()

	got, err := s.LoadResourceLabelRules(context.Background())
	if err != nil {
		t.Fatalf("LoadResourceLabelRules() error = %v, want nil: the read path filters nothing", err)
	}
	if len(got) != 1 || got[0] != unrankable {
		t.Fatalf("LoadResourceLabelRules() = %+v, want the unrankable row returned unchanged — the read path "+
			"must not silently drop rows, which would hide the defect rather than surface it", got)
	}

	assertExpectationsMet(t, mock)
}

// A duplicate prefix within one tenant is ErrAlreadyExists (409), not a
// generic failure (500). Nothing here inspects the hierarchy: the corrected
// UNIQUE (tenant_id, prefix) key collides on the prefix alone, so a second
// rule naming a DIFFERENT hierarchy produces exactly this error too — which is
// the whole reason the key was narrowed from the triple.
func TestStore_CreateResourceLabelRule_DuplicatePrefixIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnError(&pq.Error{
			Code:    sqlStateUniqueViolation,
			Message: `duplicate key value violates unique constraint "resource_label_rules_tenant_id_prefix_key"`,
		})
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"}
	_, err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now())
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("CreateResourceLabelRule() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// A failure that is NOT a constraint violation must stay a plain error: a
// connection reset is not "this rule already exists," and mapping it to
// ErrAlreadyExists would answer 409 to an operator whose write never reached
// the table at all.
func TestStore_CreateResourceLabelRule_GenericInsertErrorIsNotAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	_, err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now())
	if err == nil {
		t.Fatal("CreateResourceLabelRule() error = nil, want error")
	}
	if errors.Is(err, ErrAlreadyExists) || errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreateResourceLabelRule() error = %v, must not be classified as a client-side conflict "+
			"or a bad request", err)
	}

	assertExpectationsMet(t, mock)
}

// N4's own proof for this table: the INSERT succeeds, the audit append's first
// statement fails, and because both share one transaction the only remaining
// registered expectation is ExpectRollback — never ExpectCommit. A rule that
// persisted without its audit row would be exactly the mutation Task 4 is told
// to hunt, one task early.
func TestStore_CreateResourceLabelRule_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New().String()))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnError(errors.New("connection reset mid-audit"))
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if _, err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now()); err == nil {
		t.Fatal("CreateResourceLabelRule() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// --- PAP CRUD (Task 5) ---
//
// None of the tests below re-asserts "no WHERE tenant_id" for the four new
// queries. TestNoProductionQueryFiltersByTenantID (tenant_predicate_test.go)
// scans every query in this package's production files automatically, so a
// hand-written per-query assertion here would be a second, opt-in copy of a
// guarantee that is already structural — which is the very shape that guard
// was written to replace.

// resourceLabelRuleCRUDColumns is the column order the PAP-facing SELECTs use
// — id and tenant_id ahead of the three loadResourceLabelRulesQuery selects.
func resourceLabelRuleCRUDColumns() []string {
	return []string{"id", "tenant_id", "prefix", "hierarchy", "level"}
}

// auditReasonArgIndex is insertAuditQuery's own zero-based position for
// `reason` ($18 of 22 — see that query's column list in audit.go). Named
// rather than inlined so the two tests that pin an audit reason below say what
// they are pinning.
const auditReasonArgIndex = 17

// containsArg matches a string query argument containing every one of want. It
// exists so a test can pin the SUBSTANCE of an audit reason (which prefix, and
// what happened to it) without pinning its exact prose, which would make every
// wording change a test failure and teach the next author to update the
// assertion rather than read it.
type containsArg struct{ want []string }

func (c containsArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	for _, w := range c.want {
		if !strings.Contains(s, w) {
			return false
		}
	}
	return true
}

// auditArgsWithReason builds insertAuditQuery's 22 arguments, all unconstrained
// except reason, which must contain every string in want.
func auditArgsWithReason(want ...string) []driver.Value {
	args := make([]driver.Value, 22)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[auditReasonArgIndex] = containsArg{want: want}
	return args
}

// The PAP's own read path returns the id and tenant_id the decision path's
// loader deliberately does not select — the handle an update-by-id or
// delete-by-id route names (migrations/000019's own reason for this table
// carrying a surrogate key at all). Five distinct values, so a transposed Scan
// shows up as a named-field mismatch rather than passing by coincidence.
func TestStore_GetResourceLabelRule_RoundTripsFieldForField(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getResourceLabelRuleQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(resourceLabelRuleCRUDColumns()).
			AddRow(id.String(), testTenant, "/data/", "nato", "SECRET"))
	mock.ExpectCommit()

	got, err := s.GetResourceLabelRule(context.Background(), id)
	if err != nil {
		t.Fatalf("GetResourceLabelRule() error = %v", err)
	}
	want := models.ResourceLabelRule{ID: id, TenantID: testTenant, Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if got != want {
		t.Errorf("GetResourceLabelRule() = %+v, want %+v", got, want)
	}

	assertExpectationsMet(t, mock)
}

// "No such row" and "another tenant's row" are indistinguishable here by
// design — RLS scopes the SELECT, so a row belonging to someone else simply is
// not there, and both arrive as sql.ErrNoRows. ErrNotFound is what an HTTP
// caller turns into 404 rather than 500.
func TestStore_GetResourceLabelRule_NotFound(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getResourceLabelRuleQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.GetResourceLabelRule(context.Background(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetResourceLabelRule() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// The operator's own list, ids included. The empty case is asserted in the same
// test because it is the state every tenant is in until an operator writes a
// rule, and it must be an ordinary empty slice — never nil, never an error.
func TestStore_ListResourceLabelRules_RoundTripsAndEmptyIsNotAnError(t *testing.T) {
	t.Run("a full set", func(t *testing.T) {
		s, mock := newMockStore(t)
		catchAll, data := uuid.New(), uuid.New()

		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery(regexp.QuoteMeta(listResourceLabelRulesQuery)).
			WillReturnRows(sqlmock.NewRows(resourceLabelRuleCRUDColumns()).
				AddRow(catchAll.String(), testTenant, "", "commercial", "PUBLIC").
				AddRow(data.String(), testTenant, "/data/", "nato", "SECRET"))
		mock.ExpectCommit()

		got, err := s.ListResourceLabelRules(context.Background())
		if err != nil {
			t.Fatalf("ListResourceLabelRules() error = %v", err)
		}
		want := []models.ResourceLabelRule{
			{ID: catchAll, TenantID: testTenant, Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"},
			{ID: data, TenantID: testTenant, Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		}
		if len(got) != len(want) {
			t.Fatalf("ListResourceLabelRules() returned %d rules, want %d: %+v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("rule[%d] = %+v, want %+v", i, got[i], want[i])
			}
		}
		// The catch-all specifically: an empty prefix is a legal, meaningful
		// row, and a list that dropped it would hide the one rule that matches
		// everything.
		if got[0].Prefix != "" {
			t.Errorf("rule[0].Prefix = %q, want the empty-prefix catch-all listed like any other rule", got[0].Prefix)
		}

		assertExpectationsMet(t, mock)
	})

	t.Run("no rules at all", func(t *testing.T) {
		s, mock := newMockStore(t)

		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery(regexp.QuoteMeta(listResourceLabelRulesQuery)).
			WillReturnRows(sqlmock.NewRows(resourceLabelRuleCRUDColumns()))
		mock.ExpectCommit()

		got, err := s.ListResourceLabelRules(context.Background())
		if err != nil {
			t.Fatalf("ListResourceLabelRules() error = %v, want nil — no rules is an ordinary state", err)
		}
		if got == nil || len(got) != 0 {
			t.Errorf("ListResourceLabelRules() = %v, want a non-nil empty slice", got)
		}

		assertExpectationsMet(t, mock)
	})
}

// A PUT-shaped full replace: all three operator-owned columns move together,
// prefix included. WithArgs is what pins BOTH the argument order (a
// hierarchy/level transposition would store "SECRET" as the hierarchy) and the
// verbatim storage — the casing an operator typed is what lands, since Index
// folds when it compares and normalising here would write back a level nobody
// wrote.
func TestStore_UpdateResourceLabelRule_ReplacesAllThreeColumnsAndAudits(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	rule := models.ResourceLabelRule{Prefix: "/data/reports/", Hierarchy: "NATO", Level: "top-secret"}

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateResourceLabelRuleQuery)).
		WithArgs(rule.Prefix, rule.Hierarchy, rule.Level, id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithReason(`"/data/reports/"`, "NATO", "top-secret", id.String())...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	updated, err := s.UpdateResourceLabelRule(context.Background(), id, rule, "operator-1", time.Now())
	if err != nil {
		t.Fatalf("UpdateResourceLabelRule() error = %v", err)
	}
	if updated.ID != id {
		t.Errorf("UpdateResourceLabelRule().ID = %s, want %s", updated.ID, id)
	}
	if updated.TenantID != testTenant {
		t.Errorf("UpdateResourceLabelRule().TenantID = %q, want %q", updated.TenantID, testTenant)
	}
	if updated.Rule() != rule.Rule() {
		t.Errorf("UpdateResourceLabelRule() = %+v, want the three fields returned verbatim from %+v", updated, rule)
	}

	assertExpectationsMet(t, mock)
}

// Updating a row that is not this tenant's (or does not exist) is ErrNotFound,
// not a silent no-op. RETURNING id is what makes the two distinguishable
// without a separate rows-affected check.
func TestStore_UpdateResourceLabelRule_NotFound(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateResourceLabelRuleQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if _, err := s.UpdateResourceLabelRule(context.Background(), uuid.New(), rule, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateResourceLabelRule() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// Editing a rule's prefix onto another rule's prefix collides on UNIQUE
// (tenant_id, prefix) exactly as a duplicate create does, and must reach an
// HTTP caller as 409 rather than 500. This is not a corner case: prefix is the
// field an operator corrects, so the collision is reachable by the ordinary
// edit, not only by a create.
func TestStore_UpdateResourceLabelRule_DuplicatePrefixIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateResourceLabelRuleQuery)).
		WillReturnError(&pq.Error{
			Code:    sqlStateUniqueViolation,
			Message: `duplicate key value violates unique constraint "resource_label_rules_tenant_id_prefix_key"`,
		})
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if _, err := s.UpdateResourceLabelRule(context.Background(), uuid.New(), rule, "operator-1", time.Now()); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("UpdateResourceLabelRule() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// N4 for the update path: the UPDATE succeeds, the audit append's first
// statement fails, and because both share one transaction the only remaining
// expectation is ExpectRollback — never ExpectCommit. This is the
// "persist without auditing" mutation's designated catcher for update, the
// counterpart of the create test above.
func TestStore_UpdateResourceLabelRule_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateResourceLabelRuleQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnError(errors.New("connection reset mid-audit"))
	mock.ExpectRollback()

	rule := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if _, err := s.UpdateResourceLabelRule(context.Background(), id, rule, "operator-1", time.Now()); err == nil {
		t.Fatal("UpdateResourceLabelRule() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// The delete's own audit entry must carry the BLAST RADIUS, computed from the
// rules that survive the delete inside the same transaction — the thing that
// stands in for a confirmation gate (DeleteResourceLabelRule's own doc
// comment). Both branches, because the two say opposite things and a report
// that always said one of them would be worse than none.
//
// The surviving-rules SELECT is queued AFTER the DELETE deliberately: read
// before it, the deleted row would still be in the result and every delete
// would report itself as still covered.
func TestStore_DeleteResourceLabelRule_AuditsWhatTheDeleteDidToThePrefix(t *testing.T) {
	t.Run("a shorter rule still covers the prefix", func(t *testing.T) {
		s, mock := newMockStore(t)
		id := uuid.New()

		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery(regexp.QuoteMeta(deleteResourceLabelRuleQuery)).
			WithArgs(id.String()).
			WillReturnRows(sqlmock.NewRows([]string{"prefix", "hierarchy", "level"}).
				AddRow("/data/reports/", "nato", "TOP-SECRET"))
		mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
			WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()).
				AddRow("/data/", "nato", "CONFIDENTIAL"))
		expectAdvisoryLock(mock)
		mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
		mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
			WithArgs(auditArgsWithReason(`"/data/reports/"`, "TOP-SECRET", "now resolves to", "CONFIDENTIAL", `"/data/"`,
				// The id the caller named. deleteResourceLabelRuleQuery returns
				// only the three operator-owned columns, so a reason carrying
				// the zero UUID here would mean the id was never filled in --
				// and "what happened to THIS rule" is exactly what a prefix
				// edit makes unanswerable without it.
				id.String())...).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		if err := s.DeleteResourceLabelRule(context.Background(), id, "operator-1", time.Now()); err != nil {
			t.Fatalf("DeleteResourceLabelRule() error = %v", err)
		}

		assertExpectationsMet(t, mock)
	})

	t.Run("nothing covers the prefix any more", func(t *testing.T) {
		s, mock := newMockStore(t)
		id := uuid.New()

		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery(regexp.QuoteMeta(deleteResourceLabelRuleQuery)).
			WithArgs(id.String()).
			WillReturnRows(sqlmock.NewRows([]string{"prefix", "hierarchy", "level"}).
				AddRow("", "commercial", "PUBLIC"))
		mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
			WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()))
		expectAdvisoryLock(mock)
		mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
		// `""` specifically: this is the catch-all, and an audit line that
		// could not name the one rule matching everything would be the one
		// line an operator most needs.
		mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
			WithArgs(auditArgsWithReason(`""`, "commercial/PUBLIC", "no remaining rule labels",
				"deny under any configured cap", id.String())...).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()

		if err := s.DeleteResourceLabelRule(context.Background(), id, "operator-1", time.Now()); err != nil {
			t.Fatalf("DeleteResourceLabelRule() error = %v", err)
		}

		assertExpectationsMet(t, mock)
	})
}

func TestStore_DeleteResourceLabelRule_NotFound(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteResourceLabelRuleQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if err := s.DeleteResourceLabelRule(context.Background(), uuid.New(), "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteResourceLabelRule() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// N4 for the delete path. A rule that vanished without its audit row is the
// worst of the three: the row is gone, so nothing is left to reconstruct what
// was removed, and under R2/R7 its absence changes decisions.
func TestStore_DeleteResourceLabelRule_AuditFailureRollsBackDelete(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteResourceLabelRuleQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"prefix", "hierarchy", "level"}).
			AddRow("/data/", "nato", "SECRET"))
	mock.ExpectQuery(regexp.QuoteMeta(loadResourceLabelRulesQuery)).
		WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnError(errors.New("connection reset mid-audit"))
	mock.ExpectRollback()

	if err := s.DeleteResourceLabelRule(context.Background(), uuid.New(), "operator-1", time.Now()); err == nil {
		t.Fatal("DeleteResourceLabelRule() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// prefixAftermath is what the delete's audit reason is made of, tested on its
// own because the interesting cases are about the RULE SET, not about SQL.
//
// The fourth case is the one that keeps the wording honest: a rule at a LONGER
// prefix still covers its own subtree, so a delete that leaves the prefix
// itself unlabelled has NOT necessarily darkened everything beneath it. The
// report says "no remaining rule labels <prefix>" and stops there; a claim
// about the whole subtree would be false exactly here.
//
// deletedHierarchy varies per case because the last two cases are about it: a
// survivor in another hierarchy is a different event from a relabelling within
// one, and saying so is the only thing that distinguishes them in the record.
func TestPrefixAftermath(t *testing.T) {
	tests := []struct {
		name      string
		remaining []classification.Rule
		prefix    string
		hierarchy string // the DELETED rule's
		want      []string
		notWant   []string
	}{
		{
			name:      "a shorter rule takes over",
			remaining: []classification.Rule{{Prefix: "/data/", Hierarchy: "nato", Level: "CONFIDENTIAL"}},
			prefix:    "/data/reports/",
			hierarchy: "nato",
			want:      []string{`"/data/reports/"`, "now resolves to", "nato/CONFIDENTIAL", `"/data/"`},
			// Same hierarchy: an ordinary relabelling, and the switch clause
			// must stay silent or it would fire on every delete.
			notWant: []string{"different hierarchy"},
		},
		{
			name:      "nothing is left",
			remaining: []classification.Rule{},
			prefix:    "/data/",
			hierarchy: "nato",
			want:      []string{"no remaining rule labels", `"/data/"`, "deny under any configured cap"},
			notWant:   []string{"now resolves to"},
		},
		{
			name:      "the catch-all takes over, in the SAME hierarchy",
			remaining: []classification.Rule{{Prefix: "", Hierarchy: "COMMERCIAL", Level: "PUBLIC"}},
			prefix:    "/data/",
			hierarchy: "commercial",
			want:      []string{"now resolves to", "COMMERCIAL/PUBLIC"},
			// Case folded, the same fold Index applies: an operator who typed
			// one casing on the survivor and another on the deleted rule has
			// not switched hierarchy, and reporting that they had would be a
			// false claim in the only record they get.
			notWant: []string{"different hierarchy"},
		},
		{
			name:      "only a LONGER rule survives -- the prefix itself is unlabelled",
			remaining: []classification.Rule{{Prefix: "/data/public/", Hierarchy: "commercial", Level: "PUBLIC"}},
			prefix:    "/data/",
			hierarchy: "commercial",
			want:      []string{"no remaining rule labels", `"/data/"`},
			// The narrow claim, stated as an absence: the report must not say
			// the subtree went dark, because /data/public/ is still labelled.
			// "now resolves to" is the string a strings.HasPrefix-based matcher
			// would produce here, so this element kills a real mutant.
			notWant: []string{"now resolves to"},
		},
		{
			// The hazard classification.Match.SwitchedHierarchyFrom exists to
			// surface, reached here by a delete instead of by a carve-out: ids
			// under /data/ were nato TOP-SECRET and are now commercial PUBLIC,
			// so a nato cap does not constrain them at all -- they did not drop
			// within an ordering, they left it. Both hierarchies appear in the
			// base string either way; what this pins is that the CONSEQUENCE is
			// spelled out rather than left for the reader to notice.
			name:      "the survivor is in a different hierarchy -- the cap is escaped, not lowered",
			remaining: []classification.Rule{{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"}},
			prefix:    "/data/",
			hierarchy: "nato",
			want:      []string{"now resolves to", "commercial/PUBLIC", "different hierarchy", "nato"},
			// Not a lowering: no ordering ranks a commercial level against a
			// nato one, and saying "lower" would assert one that does not exist.
			notWant: []string{"lower"},
		},
		{
			name: "a prefix carrying two answers resolves to none -- ambiguity is not a label",
			remaining: []classification.Rule{
				{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
				{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"},
			},
			prefix:    "/data/x/",
			hierarchy: "nato",
			want:      []string{"no remaining rule labels"},
			notWant:   []string{"now resolves to"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := prefixAftermath(tt.remaining, tt.prefix, tt.hierarchy)
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("prefixAftermath(%+v, %q) = %q, want it to name %q", tt.remaining, tt.prefix, got, w)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("prefixAftermath(%+v, %q) = %q, must not claim %q", tt.remaining, tt.prefix, got, w)
				}
			}
		})
	}
}

// allDecls flattens the package's files into one declaration stream, so the
// scan above reads "every writer in internal/store" rather than "every writer
// in the file someone remembered to name".
func allDecls(files []*ast.File) []ast.Decl {
	var decls []ast.Decl
	for _, f := range files {
		decls = append(decls, f.Decls...)
	}
	return decls
}
