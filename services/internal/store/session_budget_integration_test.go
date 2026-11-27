//go:build integration

package store_test

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/store"
)

// Every PDP for a tenant draws on one budget for each session. Against real
// Postgres, as the serving role: the bucket is one SQL statement.
func TestIntegration_SessionBudget_IsSharedAcrossStoresOfOneTenant(t *testing.T) {
	const tenant = "tenant-session-budget-integration"
	session := uuid.New()
	// Two stores on the serving connection stand in for two PDPs.
	a, b := store.New(servingDB, tenant), store.New(servingDB, tenant)

	// A burst of 5 at a rate too slow to refill during the test.
	var got []int
	for _, pdp := range []*store.Store{a, b, a, b} {
		n, err := pdp.LeaseSessionTokens(t.Context(), session, 5, 0.001, 2)
		if err != nil {
			t.Fatalf("LeaseSessionTokens() error = %v", err)
		}
		got = append(got, n)
	}
	if want := []int{2, 2, 1, 0}; !slices.Equal(got, want) {
		t.Fatalf("tokens leased by two PDPs in turn = %v, want %v: one budget of 5 between them", got, want)
	}

	// Another session has its own.
	if n, err := a.LeaseSessionTokens(t.Context(), uuid.New(), 5, 0.001, 2); err != nil || n != 2 {
		t.Errorf("another session's first lease = %d, %v; want 2, nil", n, err)
	}

	// Another tenant sees none of these rows.
	var visible int
	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant+"-other"); err != nil {
		t.Fatalf("set tenant: %v", err)
	}
	if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM session_budgets`).Scan(&visible); err != nil && err != sql.ErrNoRows {
		t.Fatalf("count: %v", err)
	}
	if visible != 0 {
		t.Errorf("another tenant sees %d budget rows, want 0", visible)
	}

	// The sweep deletes what has been idle since a time in the future, which
	// is everything this tenant has: the two sessions above.
	reaped, err := a.ReapSessionBudgets(t.Context(), time.Now().Add(time.Hour))
	if err != nil || reaped != 2 {
		t.Errorf("ReapSessionBudgets() = %d, %v; want 2, nil", reaped, err)
	}
}
