//go:build integration

package store_test

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
)

// retentionDelegation seeds one delegation that expires at expiresAt. parent
// is nil for a root.
func retentionDelegation(t *testing.T, tenant string, agentID uuid.UUID, parent *models.Delegation, expiresAt time.Time) *models.Delegation {
	t.Helper()
	id := uuid.New()
	d := &models.Delegation{
		ID: id, TenantID: tenant, UserID: "retention@example.com", AgentID: agentID,
		ApprovedTools: []string{"Bash"}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "retention proof", ExpiresAt: expiresAt,
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	}
	if parent != nil {
		d.ParentDelegationID = &parent.ID
		d.RootDelegationID = parent.RootDelegationID
		d.Depth = parent.Depth + 1
		d.ChainAgentIDs = []uuid.UUID{agentID, agentID}
	}
	return seedDelegation(t, d)
}

// This file's name sorts before store_integration_test.go, and has to: the
// sweep writes an audit entry as the serving role, and that file's proof 6
// revokes INSERT on audit_chain for the rest of the run.

// The sweep deletes a session only when every part of it expired before the
// cutoff, as the PDP's own database role, and the database refuses that role
// anything that has not expired. Against real Postgres: the rules are SQL,
// foreign keys, a trigger and a row-security policy.
func TestIntegration_SessionRetention_ReapsOnlyWhollyExpiredSessions(t *testing.T) {
	const tenant = "tenant-session-retention-integration"
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "retention-agent", models.TrustTierPlatformTrusted)

	day := 24 * time.Hour
	now := time.Now()
	cutoff := now.Add(-90 * day)

	// Long dead in every part, with an approval: the one session to go.
	deadRoot := retentionDelegation(t, tenant, agentID, nil, now.Add(-100*day))
	deadChild := retentionDelegation(t, tenant, agentID, deadRoot, now.Add(-95*day))
	deadApproval := &models.Approval{
		ID: uuid.New(), AgentID: agentID, DelegationID: deadChild.ID, RootDelegationID: deadRoot.ID,
		Subject: "retention@example.com", RootPrincipal: "retention@example.com",
		ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierDestructive,
		InputDigest: sha256.Sum256([]byte("retention")), ExpiresAt: now.Add(-99 * day),
	}
	if err := store.New(testDB, tenant).CreateApproval(t.Context(), deadApproval); err != nil {
		t.Fatalf("CreateApproval() error = %v", err)
	}
	// A root as old, whose child is still live: a child may outlive its parent.
	oldRoot := retentionDelegation(t, tenant, agentID, nil, now.Add(-100*day))
	liveChild := retentionDelegation(t, tenant, agentID, oldRoot, now.Add(time.Hour))
	// Expired, but inside the retention period.
	recent := retentionDelegation(t, tenant, agentID, nil, now.Add(-10*day))
	// Live.
	live := retentionDelegation(t, tenant, agentID, nil, now.Add(time.Hour))

	serving := store.New(servingDB, tenant)
	reaped, err := serving.ReapExpiredSessions(t.Context(), cutoff, 200)
	if err != nil || reaped != 1 {
		t.Fatalf("ReapExpiredSessions() = %d, %v; want 1 session, nil", reaped, err)
	}

	for name, id := range map[string]uuid.UUID{"the dead root": deadRoot.ID, "the dead child": deadChild.ID} {
		if _, err := serving.LoadDelegation(t.Context(), id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s is still there (err = %v), want it deleted", name, err)
		}
	}
	if _, err := serving.LoadApproval(t.Context(), deadApproval.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("the dead session's approval is still there (err = %v), want it deleted", err)
	}
	for name, id := range map[string]uuid.UUID{
		"the old root with a live child": oldRoot.ID, "its live child": liveChild.ID,
		"the recently expired root": recent.ID, "the live root": live.ID,
	} {
		if _, err := serving.LoadDelegation(t.Context(), id); err != nil {
			t.Errorf("%s was deleted or cannot be read: %v", name, err)
		}
	}
	if again, err := serving.ReapExpiredSessions(t.Context(), cutoff, 200); err != nil || again != 0 {
		t.Errorf("a second sweep = %d, %v; want 0, nil", again, err)
	}

	// What the database itself refuses the serving role, whatever SQL it sends.
	servingDelete := func(stmt string, id uuid.UUID) (int64, error) {
		t.Helper()
		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set tenant: %v", err)
		}
		var res sql.Result
		if res, err = tx.ExecContext(t.Context(), stmt, id.String()); err != nil {
			return 0, err
		}
		return res.RowsAffected()
	}
	if _, err := servingDelete(`DELETE FROM delegations WHERE id = $1`, live.ID); err == nil {
		t.Error("the serving role deleted a live delegation, want the database to refuse")
	}
	// The guard asks the catalog whether the login is a superuser. A temporary
	// table named like that catalog view is found first unless the guard pins
	// where it looks; the serving role making one must change nothing.
	shadowed := func() error {
		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		for _, stmt := range []string{
			`SELECT set_config('app.tenant_id', '` + tenant + `', true)`,
			`CREATE TEMP TABLE pg_roles ON COMMIT DROP AS SELECT session_user::name AS rolname, true AS rolsuper`,
		} {
			if _, err := tx.ExecContext(t.Context(), stmt); err != nil {
				t.Fatalf("%s: %v", stmt, err)
			}
		}
		_, err = tx.ExecContext(t.Context(), `DELETE FROM delegations WHERE id = $1`, live.ID.String())
		return err
	}
	if err := shadowed(); err == nil {
		t.Error("the serving role deleted a live delegation after shadowing pg_roles with a temporary table")
	}
	// By cascade: the root has expired, the child it would take with it has not.
	if _, err := servingDelete(`DELETE FROM delegations WHERE id = $1`, oldRoot.ID); err == nil {
		t.Error("the serving role deleted an expired root whose child is live, want the database to refuse")
	}
	pending := &models.Approval{
		ID: uuid.New(), AgentID: agentID, DelegationID: live.ID, RootDelegationID: live.ID,
		Subject: "retention@example.com", RootPrincipal: "retention@example.com",
		ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierDestructive,
		InputDigest: sha256.Sum256([]byte("pending")), ExpiresAt: now.Add(time.Hour),
	}
	if err := store.New(testDB, tenant).CreateApproval(t.Context(), pending); err != nil {
		t.Fatalf("CreateApproval() error = %v", err)
	}
	if n, err := servingDelete(`DELETE FROM approvals WHERE id = $1`, pending.ID); err != nil || n != 0 {
		t.Errorf("the serving role's delete of an unexpired approval = %d rows, %v; want 0 rows", n, err)
	}
}
