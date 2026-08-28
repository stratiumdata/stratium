//go:build integration

// Task 2's real-Postgres proof for stratium_pap
// (migrations/000016_stratium_pap_role,
// .superpowers/sdd/2026-08-14-phase-14-pap/task-2-brief.md). A GRANT and a
// rule cannot be tested with sqlmock, which has neither — every property
// here needs a real Postgres, connected as the real role each proof is
// about, the same reason catalog_integration_test.go, escalation_
// integration_test.go, and tenant_epoch_integration_test.go are each their
// own file rather than additions to store_integration_test.go. Every
// package-level var and helper this file uses (testDB, servingDB, papDB,
// withTenantTx, seedAgent, seedToolCatalogEntry, tierPtr, singleHopDelegation,
// readTenantEpoch, assertEpochBumped, fetchAuditChain,
// sqlStatePermissionDenied, ...) is already shared across every
// *_integration_test.go file in this one package without an import.
//
// Three findings worth stating up front, because each one changes what a
// correct test here has to assert rather than what the phase brief's own
// summary language would suggest:
//
//  1. SELECT is required alongside INSERT/UPDATE/DELETE on every one of the
//     six governed tables below, though the brief's own text names only
//     INSERT/UPDATE. Confirmed live, in a throwaway sandbox database, before
//     migrations/000016_stratium_pap_role was finalized: `UPDATE policies
//     SET ... WHERE id = $1` fails with SQLSTATE 42501 under UPDATE-only
//     privileges, because the WHERE clause reads the id column being
//     compared — the identical rule migrations/000015_tenant_epoch_trigger's
//     own comment already documents for tenant_epoch's `SET epoch = epoch +
//     1`. See that migration's own comment for the full account.
//  2. approvals has no tenant_epoch trigger at all — migrations/000015's own
//     DO block names policies, agents, tool_catalog, and tier_overrides
//     (every op) plus delegations (UPDATE/DELETE only); approvals is absent
//     from both that list and store.go's own package doc. TestIntegration_
//     PAPRole_ApprovalsWritableButDoesNotBumpEpoch (below) asserts the epoch
//     stays put, not that it bumps — asserting a bump would have been wrong,
//     and would have made this suite claim a property this system does not
//     have.
//  3. audit_chain's UPDATE/DELETE rules (000003_audit_chain.up.sql) make
//     both a silent no-op — no error, zero rows affected — for EVERY role,
//     granted or not; this is a materially different outcome from a
//     permission-denied error, confirmed live by temporarily granting
//     stratium_app UPDATE/DELETE on audit_chain in that same sandbox and
//     observing the identical zero-rows-affected result. TestIntegration_
//     AuditChain_PAPRoleAppendOnly (below) asserts that shape specifically,
//     not a SQLSTATE.
package store_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/internal/store"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// withPAPTenantTx runs fn inside a transaction on papDB (the real
// stratium_pap_login serving connection — store_integration_test.go's own
// package var doc comment) with app.tenant_id set for that transaction
// only, then commits. withTenantTx's own exact shape
// (store_integration_test.go), reproduced against a different connection —
// not generalized into that existing helper, because every one of its
// dozens of existing call sites across this package asserts unconditional
// success (t.Fatalf on any error, including the write itself), which is
// wrong for a probe whose whole point is a write that may legitimately fail
// (beginPAPTenantTx, below, is for those).
func withPAPTenantTx(t *testing.T, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := papDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on pap-role connection: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on pap-role connection: %v", err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// beginPAPTenantTx begins a transaction on papDB with app.tenant_id set and
// returns it uncommitted, for a caller that expects its own write to FAIL
// (a withheld DELETE, an RLS-mismatched INSERT) and needs to inspect the
// error before rolling back — the same manual begin-then-rollback shape
// TestIntegration_ToolCatalog_ServingRoleCannotWrite and TestIntegration_
// Approvals_ServingRoleCannotUpdate already use inline against servingDB,
// factored out here once rather than copied a further half-dozen times in
// this file alone.
func beginPAPTenantTx(t *testing.T, tenant string) *sql.Tx {
	t.Helper()
	tx, err := papDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on pap-role connection: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on pap-role connection: %v", err)
	}
	return tx
}

// assertWriteDenied fails t unless err is a Postgres insufficient_privilege
// or row-level-security error — both SQLSTATE 42501 (confirmed live: "new
// row violates row-level security policy" and "permission denied for table
// ..." are the same SQLSTATE with different messages, so this checks the
// code, never the text). This file's own generic form of catalog_
// integration_test.go's assertPermissionDenied, which is hardcoded to
// tool_catalog and "the serving role" and does not fit stratium_pap's own
// tables and reasons.
func assertWriteDenied(t *testing.T, op, reason string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s succeeded, want a permission error — %s", op, reason)
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
		t.Fatalf("%s error = %v, want SQLSTATE %s (insufficient_privilege) — %s", op, err, sqlStatePermissionDenied, reason)
	}
	t.Logf("%s correctly denied: %v", op, err)
}

// insertTierOverrideQuery mirrors tenant_epoch_integration_test.go's own
// seedTierOverride inline query — no shared top-level const exists for it
// there (unlike insertAgentQuery/insertPolicyQuery/insertToolCatalogQuery),
// so this file defines its own rather than reaching into another file's
// unexported function for one line of SQL.
const insertTierOverrideQuery = `INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) ` +
	`VALUES ($1,$2,$3,$4,$5)`

// TestIntegration_PAPRole_BumpsOnGovernedTableWrites is Task 2's core
// writability proof, one subtest per table migrations/000016_stratium_pap_
// role grants: a write through papDB (the real stratium_pap_login
// connection) succeeds, and — for the five tables migrations/000015_tenant_
// epoch_trigger actually attaches its trigger to — bumps tenant_epoch,
// mirroring TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites's own
// shape but as a THIRD role: every prior proof of "this trigger fires"
// bumped as testDB (the migration owner) or servingDB (stratium_app,
// stratium_epoch_trigger's own subject). Nothing before this file ever
// bumped as a role holding real, permanent write grants on the governed
// tables themselves, rather than a test-scoped temporary one.
//
// Each subtest also exercises this migration's own DELETE decision for that
// table — see migrations/000016_stratium_pap_role's own leading comment for
// the full per-table reasoning; this is that reasoning's regression guard.
// approvals is deliberately absent from this test: see TestIntegration_
// PAPRole_ApprovalsWritableButDoesNotBumpEpoch's own doc comment for why its
// epoch behavior needs a dedicated, differently-shaped proof rather than a
// sixth subtest asserting the same bump the other five do.
func TestIntegration_PAPRole_BumpsOnGovernedTableWrites(t *testing.T) {
	t.Run("policies", func(t *testing.T) {
		const tenant = "tenant-pap-role-policies-integration"
		before, _ := readTenantEpoch(t, tenant)

		policyID := uuid.New().String()
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), insertPolicyQuery,
				policyID, tenant, "pap-role-policy", "cedar", "permit(principal, action, resource);", "allow", true, 0,
			); err != nil {
				t.Fatalf("INSERT policies as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
				"updated-by-pap", policyID); err != nil {
				t.Fatalf("UPDATE policies as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		// DELETE: granted. Task 3's own brief is explicit — "Create, read,
		// update, delete for the three tables A5 names first" — and a
		// policy is config, not a decision record; nothing else in this
		// schema references one by FK.
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(), `DELETE FROM policies WHERE id = $1`, policyID)
			if err != nil {
				t.Fatalf("DELETE policies as stratium_pap: %v", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				t.Fatalf("DELETE policies affected %d rows (err=%v), want 1", n, err)
			}
		})
		assertEpochBumped(t, tenant, before)

		got, err := store.New(testDB, tenant).LoadAllPolicies(t.Context())
		if err != nil {
			t.Fatalf("LoadAllPolicies() after DELETE error = %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("LoadAllPolicies() returned %d policies after DELETE, want 0", len(got))
		}
	})

	t.Run("agents", func(t *testing.T) {
		const tenant = "tenant-pap-role-agents-integration"
		before, _ := readTenantEpoch(t, tenant)

		agentID := uuid.New()
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), insertAgentQuery,
				agentID.String(), tenant, "pap-role-agent", "anthropic", "claude",
				int64(models.TrustTierUnverified), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`),
			); err != nil {
				t.Fatalf("INSERT agents as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE agents SET suspended = true WHERE id = $1`,
				agentID.String()); err != nil {
				t.Fatalf("UPDATE agents as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		// DELETE: granted. Task 3's own CRUD brief names it, and
		// delegations.agent_id / approvals.agent_id are both ON DELETE
		// RESTRICT (migrations/000001_baseline, 000012_approvals) — the
		// database itself refuses to let an agent with any history be
		// deleted out from under it. This agent has no delegation or
		// approval referencing it (a fresh tenant, this subtest's only
		// agent), so RESTRICT does not block this DELETE.
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(), `DELETE FROM agents WHERE id = $1`, agentID.String())
			if err != nil {
				t.Fatalf("DELETE agents as stratium_pap: %v", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				t.Fatalf("DELETE agents affected %d rows (err=%v), want 1", n, err)
			}
		})
		assertEpochBumped(t, tenant, before)

		if _, err := store.New(testDB, tenant).LoadAgent(t.Context(), agentID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("LoadAgent() after DELETE error = %v, want %v", err, store.ErrNotFound)
		}
	})

	t.Run("tier_overrides", func(t *testing.T) {
		const tenant = "tenant-pap-role-tier-overrides-integration"
		before, _ := readTenantEpoch(t, tenant)

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), insertTierOverrideQuery,
				tenant, "Bash", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), "pap-role-test",
			); err != nil {
				t.Fatalf("INSERT tier_overrides as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(),
				`UPDATE tier_overrides SET action_tier = $1 WHERE tenant_id = $2 AND tool_or_verb = $3`,
				int64(models.ActionTierDestructive), tenant, "Bash"); err != nil {
				t.Fatalf("UPDATE tier_overrides as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		// DELETE: granted. Task 3's own brief names it; pure config with no
		// downstream FK — removing an override reverts a tool to its
		// built-in tier, an ordinary, safe operation.
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(), `DELETE FROM tier_overrides WHERE tenant_id = $1 AND tool_or_verb = $2`,
				tenant, "Bash")
			if err != nil {
				t.Fatalf("DELETE tier_overrides as stratium_pap: %v", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				t.Fatalf("DELETE tier_overrides affected %d rows (err=%v), want 1", n, err)
			}
		})
		assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			var count int
			if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM tier_overrides WHERE tenant_id = $1`, tenant).
				Scan(&count); err != nil {
				t.Fatalf("count tier_overrides: %v", err)
			}
			if count != 0 {
				t.Fatalf("tier_overrides has %d row(s) after DELETE, want 0", count)
			}
		})
	})

	t.Run("tool_catalog", func(t *testing.T) {
		const tenant = "tenant-pap-role-tool-catalog-integration"
		before, _ := readTenantEpoch(t, tenant)
		resourceField := "file_path"

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), insertToolCatalogQuery,
				tenant, "Read", int64(models.ActionTierReadOnly), "read", &resourceField, nil,
			); err != nil {
				t.Fatalf("INSERT tool_catalog as stratium_pap: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(),
				`UPDATE tool_catalog SET verb = $1 WHERE tenant_id = $2 AND tool_name = $3`,
				"read-updated", tenant, "Read"); err != nil {
				t.Fatalf("UPDATE tool_catalog as stratium_pap: %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)

		// DELETE: withheld. No task in this phase names a tool_catalog
		// delete endpoint (Task 4 only creates or corrects a row), and this
		// codebase's own precedent (000005_serving_app_grants.up.sql:
		// "Grant what is used, not what might be") argues against a
		// privilege with no caller. See migrations/000016_stratium_pap_role's
		// own comment for the full reasoning.
		tx := beginPAPTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		_, delErr := tx.ExecContext(t.Context(), `DELETE FROM tool_catalog WHERE tenant_id = $1 AND tool_name = $2`, tenant, "Read")
		assertWriteDenied(t, "DELETE tool_catalog",
			"migrations/000016_stratium_pap_role deliberately withholds DELETE on tool_catalog", delErr)

		got, err := store.New(testDB, tenant).LoadToolCatalog(t.Context())
		if err != nil {
			t.Fatalf("LoadToolCatalog() after the denied DELETE error = %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("LoadToolCatalog() returned %d entries after the denied DELETE, want 1 (row must survive)", len(got))
		}
	})

	t.Run("delegations", func(t *testing.T) {
		const tenant = "tenant-pap-role-delegations-integration"

		agentID := uuid.New()
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), insertAgentQuery,
				agentID.String(), tenant, "pap-role-delegations-agent", "anthropic", "claude",
				int64(models.TrustTierUnverified), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`),
			); err != nil {
				t.Fatalf("INSERT agents (prerequisite) as stratium_pap: %v", err)
			}
		})
		// Baseline captured AFTER seeding the agent (which itself bumps —
		// agents is one of the four unconditional tables), matching
		// TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites's own
		// "delegations_update_and_delete" subtest and TestIntegration_
		// TenantEpoch_DelegationInsertDoesNotBump's identical precedent.
		before, exists := readTenantEpoch(t, tenant)
		if !exists {
			t.Fatalf("tenant_epoch row for %s does not exist after seeding the agent", tenant)
		}

		delegationID := uuid.New()
		d := &models.Delegation{
			ID: delegationID, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose: "pap role delegations proof", ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: delegationID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		}
		// The real production write path (internal/store.CreateDelegation),
		// exercised through papDB rather than testDB or servingDB — the one
		// subtest in this file that proves stratium_pap's grant through
		// actual application code rather than raw SQL, since a real writer
		// for this table already exists (unlike policies/agents/tier_
		// overrides/tool_catalog, which Task 3/4 have not built yet).
		if err := store.New(papDB, tenant).CreateDelegation(t.Context(), d); err != nil {
			t.Fatalf("CreateDelegation() via stratium_pap error = %v, want nil", err)
		}
		// INSERT on delegations deliberately does not bump
		// (migrations/000015's own leading comment; TestIntegration_
		// TenantEpoch_DelegationInsertDoesNotBump proves it for testDB) — a
		// brand new delegation invalidates no existing decision. Re-proven
		// here for a role that actually holds a permanent INSERT grant on
		// this table, unlike every prior proof of this property.
		afterInsert, existsAfterInsert := readTenantEpoch(t, tenant)
		if !existsAfterInsert || afterInsert != before {
			t.Fatalf("epoch = %v (exists=%v) after CreateDelegation via stratium_pap, want unchanged at %d — "+
				"delegations INSERT must not bump", afterInsert, existsAfterInsert, before)
		}

		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(),
				`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, delegationID.String())
			if err != nil {
				t.Fatalf("UPDATE delegations (revoke) as stratium_pap: %v", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				t.Fatalf("UPDATE delegations affected %d rows (err=%v), want 1", n, err)
			}
		})
		assertEpochBumped(t, tenant, afterInsert)

		got, err := store.New(testDB, tenant).LoadDelegation(t.Context(), delegationID)
		if err != nil {
			t.Fatalf("LoadDelegation() after revoke error = %v", err)
		}
		if !got.Revoked || got.RevokedAt == nil {
			t.Fatalf("delegation after UPDATE = %+v, want revoked=true with revoked_at set", got)
		}

		// DELETE: withheld. The schema's own sanctioned "delete" for this
		// table is revoked/revoked_at (just exercised above), and
		// 000012_approvals.up.sql's own comment notes delegation_id/root_
		// delegation_id deliberately carry no ON DELETE clause specifically
		// so a delegation any pending or historical approval still names
		// cannot be deleted out from under it — granting DELETE here would
		// hand this role a write the schema's own foreign keys expect never
		// to happen. See migrations/000016_stratium_pap_role's own comment.
		tx := beginPAPTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		_, delErr := tx.ExecContext(t.Context(), `DELETE FROM delegations WHERE id = $1`, delegationID.String())
		assertWriteDenied(t, "DELETE delegations",
			"migrations/000016_stratium_pap_role deliberately withholds DELETE on delegations", delErr)
	})
}

// TestIntegration_PAPRole_ApprovalsWritableButDoesNotBumpEpoch is approvals'
// own writability proof, deliberately separate from TestIntegration_
// PAPRole_BumpsOnGovernedTableWrites (above) rather than a sixth subtest
// there: every one of that test's five subtests asserts the epoch INCREASES
// after each write; this table's correct assertion is the opposite — the
// epoch must stay exactly where it was. migrations/000015_tenant_epoch_
// trigger's own DO block names policies, agents, tool_catalog, and tier_
// overrides (every op) plus delegations (UPDATE/DELETE); approvals appears
// in neither that list nor store.go's own package doc. Folding this into
// the shared subtest loop above — where "before" and "after" always differ
// by construction — would risk the exact "test that cannot fail" defect
// this project's house style calls out: a copy-pasted assertEpochBumped
// call here would either be silently wrong (asserting a property this
// system does not have) or would have forced the property "found," not
// "assumed," which is what this comment records happened.
//
// Semantically this omission is not an oversight: nothing caches "this
// action is still pending approval" anywhere in this system (E7 — a retry
// after escalation calls LoadApproval fresh every time), so nothing needs
// invalidating when an approval resolves.
func TestIntegration_PAPRole_ApprovalsWritableButDoesNotBumpEpoch(t *testing.T) {
	const tenant = "tenant-pap-role-approvals-integration"

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "pap-role-approvals-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "pap role approvals proof")

	// Captured after seeding: seedAgent's own INSERT bumps (agents is a
	// governed table); this test is only about approvals' own effect, or
	// lack of one.
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding the agent", tenant)
	}

	approval := &models.Approval{
		ID: uuid.New(), AgentID: agentID, DelegationID: delegation.ID, RootDelegationID: delegation.ID,
		Subject: "integration-test-subject", RootPrincipal: "integration-test-root-principal",
		ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierExternalComms,
		InputDigest: sha256.Sum256([]byte("pap role approvals proof")),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	// The real production write (internal/store.CreateApproval), through
	// papDB — the one role in this system besides stratium_app that can now
	// legitimately perform it.
	if err := store.New(papDB, tenant).CreateApproval(t.Context(), approval); err != nil {
		t.Fatalf("CreateApproval() via stratium_pap error = %v, want nil", err)
	}
	if got, exists := readTenantEpoch(t, tenant); !exists || got != before {
		t.Fatalf("epoch = %v (exists=%v) after CreateApproval via stratium_pap, want unchanged at %d — "+
			"approvals has no tenant_epoch trigger (migrations/000015 does not name it)", got, exists, before)
	}

	// The approve action itself: raw SQL, not a Go wrapper — E7 says none
	// should ever exist (TestIntegration_Approvals_ServingRoleCannotUpdate's
	// own doc comment). stratium_pap is the one role in this system for
	// which this UPDATE must actually succeed.
	withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(),
			`UPDATE approvals SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE id = $2`,
			"integration-test-approver", approval.ID.String())
		if err != nil {
			t.Fatalf("UPDATE approvals (approve) as stratium_pap: %v", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("UPDATE approvals affected %d rows (err=%v), want 1", n, err)
		}
	})
	if got, exists := readTenantEpoch(t, tenant); !exists || got != before {
		t.Fatalf("epoch = %v (exists=%v) after approving via stratium_pap, want unchanged at %d", got, exists, before)
	}

	got, err := store.New(testDB, tenant).LoadApproval(t.Context(), approval.ID)
	if err != nil {
		t.Fatalf("LoadApproval() after approval error = %v", err)
	}
	if got.Status != "approved" || got.ApprovedBy == nil || *got.ApprovedBy != "integration-test-approver" {
		t.Fatalf("approval after UPDATE = %+v, want status=approved, approved_by=%q", got, "integration-test-approver")
	}

	// DELETE: withheld. An approvals row is a record of what was asked and
	// by which agent (000012_approvals.up.sql's own comment) — closer to a
	// log than to config — and N4 (every write audited) argues for
	// preserving that history rather than letting it be erased. See
	// migrations/000016_stratium_pap_role's own comment.
	tx := beginPAPTenantTx(t, tenant)
	defer func() { _ = tx.Rollback() }()
	_, delErr := tx.ExecContext(t.Context(), `DELETE FROM approvals WHERE id = $1`, approval.ID.String())
	assertWriteDenied(t, "DELETE approvals", "migrations/000016_stratium_pap_role deliberately withholds DELETE on approvals", delErr)
}

// TestIntegration_AuditChain_PAPRoleAppendOnly is N4's own proof for a
// second writer: migrations/000004_audit_ownership.up.sql gives stratium_app
// exactly INSERT and SELECT on audit_chain, and migrations/000016_stratium_
// pap_role gives stratium_pap the identical pair — never UPDATE, never
// DELETE. 000003_audit_chain.up.sql's own DO INSTEAD NOTHING rules are meant
// to make append-only hold "for every role including the owner," so this
// test proves that claim for the new role specifically, the same way
// TestIntegration_ToolCatalog_ServingRoleCannotWrite proves T1 rather than
// leaving 000013's comment as an unverified claim.
//
// UPDATE/DELETE are asserted as a clean no-op — no error, zero rows
// affected — not a permission error. That is deliberately NOT the same
// shape assertWriteDenied checks for tool_catalog/approvals/delegations
// above: this file's own package doc explains why (finding 3) and
// migrations/000016_stratium_pap_role's own comment records the live
// verification this assertion is built on. Asserting a SQLSTATE here would
// test the wrong mechanism — the withheld GRANT, which TestIntegration_
// StratiumApp_GrantsUnchangedAfterPAPRoleMigration already exercises for
// the sibling role — not the rule that actually enforces append-only
// regardless of the grant.
func TestIntegration_AuditChain_PAPRoleAppendOnly(t *testing.T) {
	const tenant = "tenant-pap-role-audit-chain-integration"

	entry := audit.Entry{
		TenantID: tenant, OccurredAt: time.Now().UTC(), EventType: "admin-write",
		Actor: "integration-test:pap-append-only", Decision: "ALLOW", DeniedAtDepth: -1,
		Reason: "pap append-only proof",
	}
	// The real production write (internal/store.AppendAudit), through papDB
	// — this doubles as proof stratium_pap's own INSERT/SELECT grants are
	// sufficient for a real hash-chain append to work at all, the same
	// "prove the positive before the negative means anything" discipline
	// TestIntegration_ToolCatalog_ServingRoleCannotWrite already applies.
	if err := store.New(papDB, tenant).AppendAudit(t.Context(), entry); err != nil {
		t.Fatalf("AppendAudit() via stratium_pap error = %v, want nil", err)
	}

	before := fetchAuditChain(t, tenant)
	if len(before) != 1 {
		t.Fatalf("audit_chain for %s has %d rows after one AppendAudit, want 1", tenant, len(before))
	}

	t.Run("UPDATE", func(t *testing.T) {
		tx := beginPAPTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		res, err := tx.ExecContext(t.Context(), `UPDATE audit_chain SET reason = 'mutated-by-pap' WHERE tenant_id = $1`, tenant)
		if err != nil {
			t.Fatalf("UPDATE audit_chain as stratium_pap error = %v, want nil — "+
				"000003_audit_chain's DO INSTEAD NOTHING rule makes this a no-op, not an error", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 0 {
			t.Fatalf("UPDATE audit_chain affected %d rows (err=%v), want 0", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	})

	t.Run("DELETE", func(t *testing.T) {
		tx := beginPAPTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		res, err := tx.ExecContext(t.Context(), `DELETE FROM audit_chain WHERE tenant_id = $1`, tenant)
		if err != nil {
			t.Fatalf("DELETE audit_chain as stratium_pap error = %v, want nil (a no-op, not an error)", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 0 {
			t.Fatalf("DELETE audit_chain affected %d rows (err=%v), want 0", n, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	})

	after := fetchAuditChain(t, tenant)
	if len(after) != 1 {
		t.Fatalf("audit_chain for %s has %d rows after the UPDATE/DELETE no-ops, want still 1", tenant, len(after))
	}
	if after[0].Reason != entry.Reason {
		t.Errorf("audit_chain row's reason = %q after the UPDATE/DELETE no-ops, want unchanged %q", after[0].Reason, entry.Reason)
	}
	if !reflect.DeepEqual(before[0], after[0]) {
		t.Errorf("audit_chain row changed despite both UPDATE and DELETE being no-ops:\nbefore=%+v\nafter=%+v", before[0], after[0])
	}
}

// TestIntegration_StratiumApp_GrantsUnchangedAfterPAPRoleMigration is N3's
// regression guard, named for this migration specifically. TestIntegration_
// Approvals_ServingRoleCannotUpdate and TestIntegration_ToolCatalog_
// ServingRoleCannotWrite (store_integration_test.go, catalog_integration_
// test.go) already prove stratium_app cannot UPDATE either table — against
// whatever the latest migration happens to be, so a future migration that
// silently widened stratium_app's own grant would already fail one of
// them without this file changing at all. This test exists anyway: the
// brief for this task asks for a test proving the property "after this
// migration," a deliberate, named checkpoint tied to migrations/000016_
// stratium_pap_role rather than pre-existing coverage nobody re-reads with
// this migration in mind. See that migration's own leading comment for the
// one direction a mistake here could take that every other passing test in
// this suite would miss.
func TestIntegration_StratiumApp_GrantsUnchangedAfterPAPRoleMigration(t *testing.T) {
	t.Run("approvals_update_still_denied", func(t *testing.T) {
		const tenant = "tenant-pap-migration-regression-approvals-integration"
		agentID := uuid.New()
		seedAgent(t, tenant, agentID, "pap-migration-regression-agent", models.TrustTierUnverified)
		delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "pap migration regression proof")

		approval := &models.Approval{
			ID: uuid.New(), AgentID: agentID, DelegationID: delegation.ID, RootDelegationID: delegation.ID,
			Subject: "integration-test-subject", RootPrincipal: "integration-test-root-principal",
			ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierExternalComms,
			InputDigest: sha256.Sum256([]byte("pap migration regression proof")),
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		if err := store.New(servingDB, tenant).CreateApproval(t.Context(), approval); err != nil {
			t.Fatalf("CreateApproval() via stratium_app error = %v, want nil", err)
		}

		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin tx on serving connection: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
		}
		_, updateErr := tx.ExecContext(t.Context(),
			`UPDATE approvals SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE id = $2`,
			"integration-test-root-principal", approval.ID.String())
		assertWriteDenied(t, "UPDATE approvals (stratium_app, post-migration-000016)",
			"N3: the PDP's grants do not change — migrations/000016_stratium_pap_role must not touch stratium_app's own GRANT lines",
			updateErr)
	})

	t.Run("tool_catalog_update_still_denied", func(t *testing.T) {
		const tenant = "tenant-pap-migration-regression-tool-catalog-integration"
		resourceField := "file_path"
		seedToolCatalogEntry(t, tenant, "Read", tierPtr(models.ActionTierReadOnly), "read", &resourceField, nil)

		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin tx on serving connection: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
		}
		_, updateErr := tx.ExecContext(t.Context(),
			`UPDATE tool_catalog SET action_tier = $1 WHERE tenant_id = $2 AND tool_name = $3`,
			int64(models.ActionTierDestructive), tenant, "Read")
		assertWriteDenied(t, "UPDATE tool_catalog (stratium_app, post-migration-000016)",
			"N3/T1: migrations/000016_stratium_pap_role must not touch stratium_app's own GRANT lines", updateErr)
	})
}

// TestIntegration_PAPRole_WritesScopedByTenant is the RLS proof this task's
// own brief calls for: "RLS applies to the new role too... confirm what
// that means for a role that writes rather than reads." Every tenant table
// is FORCE ROW LEVEL SECURITY with tenant_id = current_tenant() as both
// USING and WITH CHECK (migrations/000002_rls) — USING filters what a
// write's WHERE clause can even see, WITH CHECK rejects a row a write tries
// to leave (or create) outside app.tenant_id. Every other write proof in
// this file exercises the correctly-scoped path; this is the one that
// exercises both failure shapes deliberately.
func TestIntegration_PAPRole_WritesScopedByTenant(t *testing.T) {
	t.Run("insert_wrong_tenant_id_rejected", func(t *testing.T) {
		const sessionTenant = "tenant-pap-rls-insert-session-integration"
		const rowTenant = "tenant-pap-rls-insert-row-integration"

		tx := beginPAPTenantTx(t, sessionTenant)
		defer func() { _ = tx.Rollback() }()
		_, err := tx.ExecContext(t.Context(), insertAgentQuery,
			uuid.New().String(), rowTenant, "pap-rls-mismatch-agent", "anthropic", "claude",
			int64(models.TrustTierUnverified), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`),
		)
		assertWriteDenied(t, "INSERT agents with tenant_id != app.tenant_id",
			"RLS's WITH CHECK (tenant_id = current_tenant(), migrations/000002_rls) must reject a row naming a "+
				"different tenant than the session's app.tenant_id, for stratium_pap exactly as for any other role", err)
	})

	t.Run("update_other_tenants_row_is_a_silent_no_op", func(t *testing.T) {
		const tenantA = "tenant-pap-rls-update-a-integration"
		const tenantB = "tenant-pap-rls-update-b-integration"

		otherAgentID := uuid.New()
		seedAgent(t, tenantB, otherAgentID, "pap-rls-other-tenant-agent", models.TrustTierUnverified)

		// The WHERE clause names the row by primary key alone, no tenant_id
		// anywhere in the query text — matching store.go's own "no WHERE
		// tenant_id in Go" discipline: RLS's USING clause is what has to do
		// the scoping, not the query. A session bound to tenant A must not
		// be able to reach tenant B's row this way.
		withPAPTenantTx(t, tenantA, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(), `UPDATE agents SET suspended = true WHERE id = $1`, otherAgentID.String())
			if err != nil {
				t.Fatalf("UPDATE agents (cross-tenant) as stratium_pap error = %v, want nil — "+
					"RLS makes this a silent zero-row match, not a permission error", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 0 {
				t.Fatalf("UPDATE agents (cross-tenant) affected %d rows (err=%v), want 0", n, err)
			}
		})

		got, err := store.New(testDB, tenantB).LoadAgent(t.Context(), otherAgentID)
		if err != nil {
			t.Fatalf("LoadAgent() for tenant B's own agent error = %v", err)
		}
		if got.Suspended {
			t.Fatal("tenant B's agent has suspended=true — a write from tenant A's session took effect across the tenant boundary")
		}
	})
}

// TestIntegration_PAPRole_MissingTenantEpochGrantFailsTheWriteClosed is this
// task's own required mutation ("drop the tenant_epoch grant the trigger
// needs and confirm a test catches the now-dead bump"), made a permanent
// regression guard rather than a one-off manual check — the same choice
// migrations/000015_tenant_epoch_trigger's own TestIntegration_TenantEpoch_
// MissingGrantFailsTheWriteClosed already made for stratium_app. Simpler
// than that test's own setup: stratium_pap already holds a real, permanent
// INSERT grant on agents (unlike stratium_app in Phase 12, which had none
// and had to borrow a temporary one on tier_overrides for the same proof),
// so this test only needs to remove the one grant it's actually about.
func TestIntegration_PAPRole_MissingTenantEpochGrantFailsTheWriteClosed(t *testing.T) {
	const tenant = "tenant-pap-role-epoch-grant-fail-closed-integration"

	if _, err := testDB.ExecContext(t.Context(), `REVOKE SELECT, INSERT, UPDATE ON tenant_epoch FROM stratium_pap`); err != nil {
		t.Fatalf("test-scoped REVOKE on tenant_epoch: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testDB.ExecContext(context.Background(), `GRANT SELECT, INSERT, UPDATE ON tenant_epoch TO stratium_pap`); err != nil {
			t.Errorf("cleanup: restore migrations/000016's own GRANT on tenant_epoch: %v", err)
		}
	})

	agentID := uuid.New()
	tx := beginPAPTenantTx(t, tenant)
	defer func() { _ = tx.Rollback() }()
	_, insertErr := tx.ExecContext(t.Context(), insertAgentQuery,
		agentID.String(), tenant, "pap-epoch-fail-closed-agent", "anthropic", "claude",
		int64(models.TrustTierUnverified), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`),
	)
	if insertErr == nil {
		t.Fatal("INSERT agents succeeded despite the trigger having no grant on tenant_epoch — " +
			"want the whole write to fail closed, not land un-bumped")
	}
	var pqErr *pq.Error
	if !errors.As(insertErr, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
		t.Fatalf("INSERT error = %v, want SQLSTATE %s (insufficient_privilege) from the trigger's own write to tenant_epoch",
			insertErr, sqlStatePermissionDenied)
	}
	t.Logf("INSERT agents correctly failed closed when the trigger could not reach tenant_epoch: %v", insertErr)

	// The whole transaction — the agents row AND any partial bump — must
	// have been rejected together, not applied piecemeal.
	withTenantTx(t, tenant, func(tx2 *sql.Tx) {
		var count int
		if err := tx2.QueryRowContext(t.Context(), `SELECT count(*) FROM agents WHERE tenant_id = $1`, tenant).Scan(&count); err != nil {
			t.Fatalf("count agents rows: %v", err)
		}
		if count != 0 {
			t.Fatalf("agents has %d row(s) for %s despite the INSERT failing — the write was not actually rolled back", count, tenant)
		}
	})
}
