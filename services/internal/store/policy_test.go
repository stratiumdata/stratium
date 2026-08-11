package store

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"stratium/internal/policy"
)

func policyColumns() []string {
	return []string{"id", "name", "language", "policy_content", "priority", "version"}
}

// addPolicyRow appends p as one loadAllPoliciesQuery result row, in that
// query's column order.
func addPolicyRow(rows *sqlmock.Rows, p policy.StoredPolicy) *sqlmock.Rows {
	return rows.AddRow(p.ID, p.Name, p.Language, p.Text, p.Priority, p.Version)
}

// testPolicy returns a StoredPolicy with every queried field set to a
// distinguishable value. Priority is non-zero on purpose: it is the field
// 000009_policy_priority added a column for, and a zero here would let a
// dropped scan target pass every round-trip assertion below, which is exactly
// how the value went unnoticed as structurally-always-zero for two phases.
// Version differs from Priority so transposing the two adjacent scan targets
// fails rather than silently swapping equal numbers — the two are directly
// adjacent in loadAllPoliciesQuery's column order since Phase 4a Task 4
// dropped the effect column that used to sit between them.
func testPolicy(id, name string) policy.StoredPolicy {
	return policy.StoredPolicy{
		ID:       id,
		Name:     name,
		Language: "cedar",
		Text:     "permit(principal, action, resource);",
		Priority: 7,
		Version:  1,
	}
}

// --- LoadAllPolicies ---

// loadAllPoliciesQuery's own text is asserted directly, independent of the
// mock-plumbing tests below: sqlmock never executes real SQL, so the only
// way a unit test can pin "disabled rows are excluded," "ordered by id," and
// "regardless of language" as properties of the query itself — rather than
// merely "whatever text the mock was told to expect" — is to inspect that
// text. Also pins the same no-WHERE-tenant_id discipline the package doc
// requires of every query. The "regardless of language" property is
// asserted here as the query having no language predicate at all, and
// separately, below, as a behavioral test that rows from several different
// languages all come back in one call.
func TestLoadAllPoliciesQuery_FiltersEnabledOrdersByIDAndIgnoresLanguage(t *testing.T) {
	if !strings.Contains(loadAllPoliciesQuery, "enabled = true") {
		t.Errorf("loadAllPoliciesQuery = %q, want it to filter on enabled = true", loadAllPoliciesQuery)
	}
	if !strings.Contains(loadAllPoliciesQuery, "ORDER BY id") {
		t.Errorf("loadAllPoliciesQuery = %q, want ORDER BY id", loadAllPoliciesQuery)
	}
	if strings.Contains(loadAllPoliciesQuery, "tenant_id") {
		t.Errorf("loadAllPoliciesQuery = %q, must not reference tenant_id — RLS is the only tenant boundary", loadAllPoliciesQuery)
	}
	// "language" alone would also match the selected column name, so the
	// filter form itself is what's checked for absence.
	if strings.Contains(loadAllPoliciesQuery, "language =") {
		t.Errorf("loadAllPoliciesQuery = %q, must not filter on language — it loads every language a tenant has authored in one call", loadAllPoliciesQuery)
	}
}

// Rows spanning three different languages all come back in one call — the
// behavioral proof that this is a single query with no language filter at
// all, not one call repeated per language.
func TestStore_LoadAllPolicies_ReturnsEveryLanguage(t *testing.T) {
	s, mock := newMockStore(t)
	cedarPolicy := testPolicy("11111111-1111-1111-1111-111111111111", "cedar-one")
	regoPolicy := testPolicy("22222222-2222-2222-2222-222222222222", "rego-one")
	regoPolicy.Language = "rego"
	jsonPolicy := testPolicy("33333333-3333-3333-3333-333333333333", "json-one")
	jsonPolicy.Language = "json"
	want := []policy.StoredPolicy{cedarPolicy, regoPolicy, jsonPolicy}

	mock.ExpectBegin()
	expectSetTenant(mock)
	rows := sqlmock.NewRows(policyColumns())
	for _, p := range want {
		addPolicyRow(rows, p)
	}
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectCommit()

	got, err := s.LoadAllPolicies(context.Background())
	if err != nil {
		t.Fatalf("LoadAllPolicies() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("LoadAllPolicies() returned %d policies, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy[%d] = %+v, want %+v", i, got[i], want[i])
		}
		// Redundant with the struct comparison above, and kept deliberately:
		// it fails loudly if testPolicy's Priority is ever reset to zero,
		// which would make the comparison above pass while proving nothing
		// about the column 000009 added. Priority spent two phases
		// structurally-always-zero specifically because no test caught a
		// fixture regression shaped exactly like that.
		if got[i].Priority == 0 {
			t.Errorf("policy[%d].Priority = 0, want the stored value round-tripped", i)
		}
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no policies in any language is an ordinary, empty result,
// not an error: the caller gets a non-nil, zero-length slice so it can
// prepare an empty policy set without a nil check, and a nil error so
// nothing downstream mistakes "no policies" for "something broke."
func TestStore_LoadAllPolicies_EmptyResultReturnsEmptyNonNilSlice(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(sqlmock.NewRows(policyColumns()))
	mock.ExpectCommit()

	got, err := s.LoadAllPolicies(context.Background())
	if err != nil {
		t.Fatalf("LoadAllPolicies() error = %v, want nil — no policies is not an error", err)
	}
	if got == nil {
		t.Fatal("LoadAllPolicies() returned a nil slice, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("LoadAllPolicies() returned %d policies, want 0", len(got))
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadAllPolicies_QueryErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnError(dbErr)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if err == nil {
		t.Fatal("LoadAllPolicies() error = nil, want error")
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil on query failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A row that cannot scan into StoredPolicy's types — here, a version column
// that isn't a valid int64 — must fail loudly and roll back, not silently
// truncate or zero the field.
func TestStore_LoadAllPolicies_RowScanErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)

	rows := sqlmock.NewRows(policyColumns()).
		AddRow("id-1", "bad-version", "cedar", "permit(principal, action, resource);", 7, "not-a-version")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if err == nil {
		t.Fatal("LoadAllPolicies() error = nil, want scan error")
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil on scan failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A failure partway through iteration (connection dropped after some rows
// already arrived) must discard whatever was collected so far and return an
// error, never a silently truncated policy set — half a tenant's policies
// enforced as if it were the whole set is worse than an outright failure.
func TestStore_LoadAllPolicies_RowsIterationErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	iterErr := errors.New("connection dropped mid-stream")

	rows := sqlmock.NewRows(policyColumns())
	addPolicyRow(rows, testPolicy("id-1", "first"))
	addPolicyRow(rows, testPolicy("id-2", "second"))
	addPolicyRow(rows, testPolicy("id-3", "third")).RowError(2, iterErr)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if !errors.Is(err, iterErr) {
		t.Fatalf("LoadAllPolicies() error = %v, want it to wrap %v", err, iterErr)
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil when row iteration fails partway through", got)
	}

	assertExpectationsMet(t, mock)
}
