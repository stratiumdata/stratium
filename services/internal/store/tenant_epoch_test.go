package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func epochColumns() []string { return []string{"epoch"} }

// loadTenantEpochQuery's own text is asserted directly, the same reason
// TestLoadAllPoliciesQuery_FiltersEnabledOrdersByIDAndIgnoresLanguage
// (policy_test.go) inspects loadAllPoliciesQuery's text rather than trusting
// only the mock-plumbing tests below: sqlmock never runs real SQL, so this
// is the only way a unit test pins "no WHERE tenant_id" as a property of the
// query itself.
func TestLoadTenantEpochQuery_HasNoTenantIDClause(t *testing.T) {
	if strings.Contains(loadTenantEpochQuery, "tenant_id") {
		t.Errorf("loadTenantEpochQuery = %q, must not reference tenant_id — RLS is the only tenant boundary", loadTenantEpochQuery)
	}
}

// TestStore_LoadTenantEpoch_Success round-trips a value chosen to be
// nothing else this file or tenant_epoch_integration_test.go ever asserts
// (not 1, LoadTenantEpoch's own no-row default; not 2, the trigger's own
// first-bump value) — a fixture close to either could pass a mixed-up
// implementation by coincidence.
//
// It also pins the ordering the brief requires explicitly: expectations are
// registered begin, THEN set the tenant, THEN the epoch query, THEN commit,
// and sqlmock matches them in that exact order by default (newMockStore's
// own doc comment) — an implementation that queried before scoping the
// transaction to the tenant would ask sqlmock for a call it has not yet
// been told to expect, and this test would fail on the unexpected call, not
// merely on a wrong answer.
func TestStore_LoadTenantEpoch_Success(t *testing.T) {
	s, mock := newMockStore(t)
	const want int64 = 47

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTenantEpochQuery)).
		WillReturnRows(sqlmock.NewRows(epochColumns()).AddRow(want))
	mock.ExpectCommit()

	got, err := s.LoadTenantEpoch(context.Background())
	if err != nil {
		t.Fatalf("LoadTenantEpoch() error = %v", err)
	}
	if got != want {
		t.Errorf("LoadTenantEpoch() = %d, want %d", got, want)
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no tenant_epoch row is not an error: it reports
// defaultTenantEpoch (1), the schema's own DEFAULT and the value Task 1's
// migration documents every reader must already treat an absent row as.
//
// Asserted against BOTH the named constant and the literal 1, deliberately:
// a comparison against defaultTenantEpoch alone is blind to defaultTenantEpoch
// itself being wrong (mutation-tested — changing its declaration to 2, the
// trigger's own first-bump value, left this assertion passing, tautologically,
// against the very constant that had just been mutated). The literal is what
// actually pins the value migrations/000015_tenant_epoch_trigger's own
// comment depends on staying distinguishable from a fresh row's initial
// bump — TestIntegration_TenantEpoch_LoadForUnseenTenantReturnsSchemaDefault
// (tenant_epoch_integration_test.go) already asserts the same literal against
// a real database, but a unit test should not depend on an integration test
// to catch a defect this cheap to pin here too.
func TestStore_LoadTenantEpoch_NoRowReturnsDefault(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTenantEpochQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectCommit()

	got, err := s.LoadTenantEpoch(context.Background())
	if err != nil {
		t.Fatalf("LoadTenantEpoch() error = %v, want nil — no row is an ordinary result, not a failure", err)
	}
	if got != defaultTenantEpoch {
		t.Errorf("LoadTenantEpoch() = %d, want %d (defaultTenantEpoch)", got, defaultTenantEpoch)
	}
	if got != 1 {
		t.Errorf("LoadTenantEpoch() = %d, want 1: the schema's own DEFAULT (migrations/000001_baseline), "+
			"and one less than the trigger's own first-bump value (migrations/000015_tenant_epoch_trigger) — "+
			"the two must never collide, or a freshly-bumped tenant would be indistinguishable from one never "+
			"written at all", got)
	}

	assertExpectationsMet(t, mock)
}

// A real query failure — as opposed to the no-rows case above — must
// propagate as an error, and the accompanying value must not be mistaken
// for a real epoch: this is the store-layer half of "a read failure denies
// rather than reporting a default" (the pdpgrpc half,
// TestDecide_EpochReadFailure_DeniesNotADefault, proves the caller actually
// treats this error as fail-closed rather than substituting a value of its
// own). Returning 0 here is not "the fallback" — it is simply what
// accompanies a Go error nobody is supposed to read; the discipline that
// makes 0 harmless is the caller's job, checking err first, every time.
func TestStore_LoadTenantEpoch_QueryErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTenantEpochQuery)).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	got, err := s.LoadTenantEpoch(context.Background())
	if err == nil {
		t.Fatal("LoadTenantEpoch() error = nil, want error")
	}
	if got != 0 {
		t.Errorf("LoadTenantEpoch() = %d, want 0 alongside a non-nil error", got)
	}

	assertExpectationsMet(t, mock)
}
