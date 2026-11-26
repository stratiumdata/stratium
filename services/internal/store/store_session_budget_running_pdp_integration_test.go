//go:build integration

package store_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
)

// This file's name sorts after store_integration_test.go, and has to: the
// test below sends a Decide through the stack's PDP, which writes an audit
// entry for the stack's own tenant, and TestEndToEnd counts that tenant's
// entries exactly.

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
