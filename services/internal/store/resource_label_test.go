package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"

	"stratium/pkg/classification"
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
	if !strings.Contains(loadResourceLabelRulesQuery, "ORDER BY prefix") {
		t.Errorf("loadResourceLabelRulesQuery = %q, want ORDER BY prefix: a complete, tie-free order (prefix is "+
			"unique per tenant), so the level Resolve reports is stable across runs", loadResourceLabelRulesQuery)
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
// the same transaction), then the commit.
func expectResourceLabelRuleWrite(mock sqlmock.Sqlmock, rule classification.Rule) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WithArgs(testTenant, rule.Prefix, rule.Hierarchy, rule.Level).
		WillReturnResult(sqlmock.NewResult(0, 1))
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
		rule classification.Rule
	}{
		{"ordinary rule", classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}},
		{"R7's empty-prefix catch-all", classification.Rule{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"}},
		{"casing an operator typed, stored verbatim", classification.Rule{Prefix: "/x", Hierarchy: "NATO", Level: "secret"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			expectResourceLabelRuleWrite(mock, tt.rule)

			if err := s.CreateResourceLabelRule(context.Background(), tt.rule, "operator-1", time.Now()); err != nil {
				t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want nil", tt.rule, err)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_CreateResourceLabelRule_InvalidLabelRefusedBeforePersisting is the
// write-time validation the brief requires, at the Go-side layer that holds it
// (there is no CHECK constraint for this — see the migration's own comment).
// The zero-expectation mock is the proof it happens BEFORE the database is
// touched: a mutant that deleted the check would reach the empty mock and fail
// with sqlmock's own "was not expected" error rather than this errors.Is
// assertion.
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
func TestStore_CreateResourceLabelRule_InvalidLabelRefusedBeforePersisting(t *testing.T) {
	// The two messages validateResourceLabelRule can produce, named once so
	// each case below says which of the two checks it expects to have fired.
	const (
		unknownHierarchyMsg = "unknown classification hierarchy"
		unknownLevelMsg     = "is not a level of hierarchy"
	)
	tests := []struct {
		name     string
		rule     classification.Rule
		wantMsgs []string
	}{
		{
			"a real level, but of the other hierarchy",
			classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "PUBLIC"},
			// The known-levels list must be nato's, not commercial's: an
			// operator told "PUBLIC is not a level of nato" needs to be shown
			// what nato's levels ARE, and TOP-SECRET appears in no other
			// hierarchy.
			[]string{unknownLevelMsg, `"PUBLIC"`, `"nato"`, "TOP-SECRET"},
		},
		{
			"R9's typo: natoo for nato",
			classification.Rule{Prefix: "/data/x/", Hierarchy: "natoo", Level: "UNCLASSIFIED"},
			// The hierarchy branch, not the level branch: both refuse, but only
			// this one can list the hierarchies that do exist. The level branch
			// would report "(known: )" — an empty set — because natoo has no
			// levels to list.
			[]string{unknownHierarchyMsg, `"natoo"`, "nato", "commercial"},
		},
		{
			"a level that exists nowhere",
			classification.Rule{Prefix: "/data/", Hierarchy: "commercial", Level: "MOSTLY-SECRET"},
			[]string{unknownLevelMsg, `"MOSTLY-SECRET"`, `"commercial"`, "HIGHLY-CONFIDENTIAL"},
		},
		{
			"empty hierarchy",
			classification.Rule{Prefix: "/data/", Hierarchy: "", Level: "SECRET"},
			[]string{unknownHierarchyMsg},
		},
		{
			"empty level",
			classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: ""},
			[]string{unknownLevelMsg},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)

			err := s.CreateResourceLabelRule(context.Background(), tt.rule, "operator-1", time.Now())
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want ErrInvalidRequest", tt.rule, err)
			}
			// The message must name the value the operator got wrong: this
			// check exists to be a good error at the point of the typo, and an
			// error that said only "invalid rule" would not be one.
			for _, want := range tt.wantMsgs {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error = %q, want it to name %s", err, want)
				}
			}

			assertExpectationsMet(t, mock) // zero expectations: nothing reached the database
		})
	}
}

// The refusal above must not be read as a downstream guarantee. This pins the
// narrower claim the code actually makes: LoadResourceLabelRules returns
// whatever rows the table holds, including a rule naming a hierarchy no
// validation would have accepted, because a stale read, an in-flight
// migration, or a store bug can each produce one. R9 is explicit that
// write-time validation is a better error message, not the enforcement — and
// the enforcement (an unreadable label never reaching a permissive branch) is
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
	mock.ExpectExec(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnError(&pq.Error{
			Code:    sqlStateUniqueViolation,
			Message: `duplicate key value violates unique constraint "resource_label_rules_tenant_id_prefix_key"`,
		})
	mock.ExpectRollback()

	rule := classification.Rule{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"}
	err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now())
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
	mock.ExpectExec(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	rule := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now())
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
	mock.ExpectExec(regexp.QuoteMeta(insertResourceLabelRuleQuery)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnError(errors.New("connection reset mid-audit"))
	mock.ExpectRollback()

	rule := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	if err := s.CreateResourceLabelRule(context.Background(), rule, "operator-1", time.Now()); err == nil {
		t.Fatal("CreateResourceLabelRule() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}
