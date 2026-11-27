//go:build integration

package store_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// A session that has made a temporary table called tenant_epoch still bumps
// the tenant's real epoch when it writes. A temporary table is found before a
// permanent one of the same name unless the trigger function pins where it
// looks (migrations/000030_pin_epoch_trigger_search_path); without that, the
// bump went to the temporary table and the PEPs' caches were told nothing.
func TestIntegration_TenantEpoch_ATemporaryTableCannotDivertTheBump(t *testing.T) {
	const tenant = "tenant-epoch-shadow-integration"
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "epoch-shadow-agent", models.TrustTierPlatformTrusted)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierReadOnly, "epoch shadow proof")
	before, _ := readTenantEpoch(t, tenant)

	// As the admin plane's role, whose revocations are what the epoch exists
	// to announce.
	tx := beginPAPTenantTx(t, tenant)
	defer func() { _ = tx.Rollback() }()
	for _, stmt := range []string{
		`CREATE TEMP TABLE tenant_epoch (tenant_id text PRIMARY KEY, epoch bigint, updated_at timestamptz) ON COMMIT DROP`,
		`UPDATE delegations SET revoked = true, revoked_at = now() WHERE id = '` + delegation.ID.String() + `'`,
	} {
		if _, err := tx.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	assertEpochBumped(t, tenant, before)
}
