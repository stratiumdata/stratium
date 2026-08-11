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
	return []string{"id", "name", "language", "policy_content", "effect", "priority", "version"}
}

// addPolicyRow appends p as one loadPoliciesQuery result row, in that
// query's column order.
func addPolicyRow(rows *sqlmock.Rows, p policy.StoredPolicy) *sqlmock.Rows {
	return rows.AddRow(p.ID, p.Name, p.Language, p.Text, p.Effect, p.Priority, p.Version)
}

// testPolicy returns a StoredPolicy with every queried field set to a
// distinguishable value. Priority is non-zero on purpose: it is the field
// 000009_policy_priority added a column for, and a zero here would let a
// dropped scan target pass every round-trip assertion below, which is exactly
// how the value went unnoticed as structurally-always-zero for two phases.
// Version differs from Priority so transposing the two adjacent scan targets
// fails rather than silently swapping equal numbers.
func testPolicy(id, name string) policy.StoredPolicy {
	return policy.StoredPolicy{
		ID:       id,
		Name:     name,
		Language: "cedar",
		Text:     "permit(principal, action, resource);",
		Effect:   "allow",
		Priority: 7,
		Version:  1,
	}
}

// --- LoadPolicies ---

// loadPoliciesQuery's own text is asserted directly, independent of the
// mock-plumbing tests below: sqlmock never executes real SQL, so the only
// way a unit test can pin "disabled rows are excluded" and "ordered by id"
// as properties of the query itself — rather than merely "whatever text the
// mock was told to expect" — is to inspect that text. Also pins the same
// no-WHERE-tenant_id discipline the package doc requires of every query.
func TestLoadPoliciesQuery_FiltersEnabledAndOrdersByID(t *testing.T) {
	if !strings.Contains(loadPoliciesQuery, "enabled = true") {
		t.Errorf("loadPoliciesQuery = %q, want it to filter on enabled = true", loadPoliciesQuery)
	}
	if !strings.Contains(loadPoliciesQuery, "ORDER BY id") {
		t.Errorf("loadPoliciesQuery = %q, want ORDER BY id", loadPoliciesQuery)
	}
	if strings.Contains(loadPoliciesQuery, "tenant_id") {
		t.Errorf("loadPoliciesQuery = %q, must not reference tenant_id — RLS is the only tenant boundary", loadPoliciesQuery)
	}
}

// The three rows are supplied already in id order, as a real ORDER BY id
// would hand them back, and the assertion checks LoadPolicies preserves
// that positional order rather than re-sorting or shuffling it — the
// query's ORDER BY is the only thing establishing order here (see the test
// above), so this test is really checking Go adds no reordering of its own.
func TestStore_LoadPolicies_Success(t *testing.T) {
	s, mock := newMockStore(t)
	want := []policy.StoredPolicy{
		testPolicy("11111111-1111-1111-1111-111111111111", "first"),
		testPolicy("22222222-2222-2222-2222-222222222222", "second"),
		testPolicy("33333333-3333-3333-3333-333333333333", "third"),
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	rows := sqlmock.NewRows(policyColumns())
	for _, p := range want {
		addPolicyRow(rows, p)
	}
	mock.ExpectQuery(regexp.QuoteMeta(loadPoliciesQuery)).
		WithArgs("cedar").
		WillReturnRows(rows)
	mock.ExpectCommit()

	got, err := s.LoadPolicies(context.Background(), "cedar")
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("LoadPolicies() returned %d policies, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy[%d] = %+v, want %+v", i, got[i], want[i])
		}
		// Redundant with the struct comparison above, and kept deliberately:
		// it fails loudly if testPolicy's Priority is ever reset to zero,
		// which would make the comparison above pass while proving nothing
		// about the column 000009 added.
		if got[i].Priority == 0 {
			t.Errorf("policy[%d].Priority = 0, want the stored value round-tripped", i)
		}
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no policies for a language is an ordinary, empty result,
// not an error — the caller gets a non-nil, zero-length slice so it can
// prepare an empty policy set without a nil check, and a nil error so
// nothing downstream mistakes "no policies" for "something broke."
func TestStore_LoadPolicies_EmptyResultReturnsEmptyNonNilSlice(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadPoliciesQuery)).
		WithArgs("cedar").
		WillReturnRows(sqlmock.NewRows(policyColumns()))
	mock.ExpectCommit()

	got, err := s.LoadPolicies(context.Background(), "cedar")
	if err != nil {
		t.Fatalf("LoadPolicies() error = %v, want nil — no policies is not an error", err)
	}
	if got == nil {
		t.Fatal("LoadPolicies() returned a nil slice, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("LoadPolicies() returned %d policies, want 0", len(got))
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadPolicies_QueryErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadPoliciesQuery)).
		WithArgs("cedar").
		WillReturnError(dbErr)
	mock.ExpectRollback()

	got, err := s.LoadPolicies(context.Background(), "cedar")
	if err == nil {
		t.Fatal("LoadPolicies() error = nil, want error")
	}
	if got != nil {
		t.Errorf("LoadPolicies() = %v, want nil on query failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A row that cannot scan into StoredPolicy's types — here, a version column
// that isn't a valid int64 — must fail loudly and roll back, not silently
// truncate or zero the field.
func TestStore_LoadPolicies_RowScanErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)

	rows := sqlmock.NewRows(policyColumns()).
		AddRow("id-1", "bad-version", "cedar", "permit(principal, action, resource);", "allow", 7, "not-a-version")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadPoliciesQuery)).
		WithArgs("cedar").
		WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadPolicies(context.Background(), "cedar")
	if err == nil {
		t.Fatal("LoadPolicies() error = nil, want scan error")
	}
	if got != nil {
		t.Errorf("LoadPolicies() = %v, want nil on scan failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A failure partway through iteration (connection dropped after some rows
// already arrived) must discard whatever was collected so far and return an
// error, never a silently truncated policy set — half a tenant's policies
// enforced as if it were the whole set is worse than an outright failure.
func TestStore_LoadPolicies_RowsIterationErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	iterErr := errors.New("connection dropped mid-stream")

	rows := sqlmock.NewRows(policyColumns())
	addPolicyRow(rows, testPolicy("id-1", "first"))
	addPolicyRow(rows, testPolicy("id-2", "second"))
	// A third row that is never actually scanned: RowError on index 2 makes
	// the driver's third Next() call fail instead of cleanly reporting
	// end-of-rows, after two rows have already come back successfully.
	addPolicyRow(rows, testPolicy("id-3", "third")).RowError(2, iterErr)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadPoliciesQuery)).
		WithArgs("cedar").
		WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadPolicies(context.Background(), "cedar")
	if !errors.Is(err, iterErr) {
		t.Fatalf("LoadPolicies() error = %v, want it to wrap %v", err, iterErr)
	}
	if got != nil {
		t.Errorf("LoadPolicies() = %v, want nil when row iteration fails partway through", got)
	}

	assertExpectationsMet(t, mock)
}

// --- LoadAllPolicies ---

// loadAllPoliciesQuery's own text is asserted directly, the same reasoning
// as TestLoadPoliciesQuery_FiltersEnabledAndOrdersByID: enabled = true,
// ORDER BY id, and no WHERE tenant_id are all pinned as properties of the
// query text itself. The one property specific to this sibling query is
// "regardless of language" — asserted here as the query having no language
// predicate at all, and separately, below, as a behavioral test that rows
// from several different languages all come back in one call.
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
		t.Errorf("loadAllPoliciesQuery = %q, must not filter on language — it is LoadPolicies' regardless-of-language sibling", loadAllPoliciesQuery)
	}
}

// Rows spanning three different languages all come back in one call — the
// behavioral proof that LoadAllPolicies is not LoadPolicies called once per
// language, but a single query with no language filter at all.
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
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no policies in any language is an ordinary, empty result,
// not an error — LoadPolicies' own contract, pinned separately here because
// LoadAllPolicies has its own query and its own not-nil-slice guarantee to
// keep.
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

// A row that cannot scan into StoredPolicy's types must fail loudly and roll
// back, not silently truncate or zero the field — same discipline as
// LoadPolicies' own scan-error test, pinned separately because the two
// methods must share scanPolicyRows without one silently diverging from the
// other's error behavior.
func TestStore_LoadAllPolicies_RowScanErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)

	rows := sqlmock.NewRows(policyColumns()).
		AddRow("id-1", "bad-version", "cedar", "permit(principal, action, resource);", "allow", 7, "not-a-version")

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

// A failure partway through iteration must discard whatever was collected so
// far, never a silently truncated policy set — LoadPolicies' own iteration
// test, repeated here for the shared scanPolicyRows helper's other caller.
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
