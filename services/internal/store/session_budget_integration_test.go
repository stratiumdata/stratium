//go:build integration

package store_test

import (
	"database/sql"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
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

// The running PDP keeps its sessions' budgets in the shared table. Worth its
// own proof because a PDP that cannot use the table does not fail: it counts
// alone, and every other test would pass just the same.
func TestIntegration_SessionBudget_TheRunningPDPDrawsOnTheSharedTable(t *testing.T) {
	agentID := uuid.New()
	seedAgent(t, configuredTenant, agentID, "session-budget-agent", models.TrustTierPlatformTrusted)
	delegation := singleHopDelegation(t, configuredTenant, agentID, models.ActionTierInternalModify, "shared budget proof")

	if _, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token:   mintToken(t, pdpClient, delegation.ID),
		AgentId: agentID.String(),
		Subject: "alice@example.com",
		Tool:    "Read",
	}); err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}

	// The first call of a session takes a block from a full budget, so the
	// row exists and holds less than it started with.
	var rows int
	var tokens sql.NullFloat64
	withTenantTx(t, configuredTenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT count(*), min(tokens) FROM session_budgets WHERE session_id = $1`,
			delegation.RootDelegationID.String()).Scan(&rows, &tokens); err != nil {
			t.Fatalf("read session_budgets: %v", err)
		}
	})
	if rows != 1 {
		t.Fatalf("session_budgets rows for the session = %d, want 1: the PDP did not record the call in the shared table", rows)
	}
	t.Logf("shared budget after one call: %.0f tokens left", tokens.Float64)
}
