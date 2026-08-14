//go:build integration

// Task 1's real-Postgres proof for the revocation epoch trigger
// (migrations/000015_tenant_epoch_trigger,
// .superpowers/sdd/2026-08-14-phase-12-revocation-epoch/task-1-brief.md). A
// trigger cannot be tested with sqlmock -- there is no database to fire one
// -- so every property here needs a real Postgres, the same reason
// escalation_integration_test.go and catalog_integration_test.go are their
// own files rather than additions to store_integration_test.go: every
// package-level var and helper this file uses (testDB, servingDB,
// withTenantTx, seedAgent, seedPolicy, seedDelegation, seedToolCatalogEntry,
// tierPtr, twoHopChain, singleHopDelegation, sqlStatePermissionDenied, ...)
// is already shared across every *_test.go file in this one package without
// an import.
//
// tenant_epoch has existed since the baseline migration (000001) and, until
// migrations/000015, nothing ever wrote it -- the gap this whole file closes.
//
// Extended for Task 2
// (.superpowers/sdd/2026-08-14-phase-12-revocation-epoch/task-2-brief.md):
// TestIntegration_TenantEpoch_LoadForUnseenTenantReturnsSchemaDefault and
// TestIntegration_TenantEpoch_LoadReflectsARealBump close the reader half
// Task 1's own package doc (store.go) left as future work -- store.
// LoadTenantEpoch, proven against this file's same real trigger, not just
// against sqlmock (tenant_epoch_test.go covers that side). Kept in this
// file rather than a new one: they exercise the same table, the same
// trigger, and the same shared fixtures (testDB, seedPolicy, withTenantTx)
// every other test above already depends on -- this package's own
// convention is one file per table/feature, not one per task (see
// catalog_integration_test.go, escalation_integration_test.go).
package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/internal/store"
	"stratium/pkg/models"
)

// readTenantEpoch reads tenant_epoch's row for tenant, tenant-scoped via
// set_config exactly like beginTenantTx (internal/store/store.go): RLS
// applies to SELECT just as it does to writes, so an unscoped read would
// see no row regardless of whether one actually exists. exists is false
// both when no row has ever been created and when RLS itself hid it --
// every test in this file only ever asks about a tenant it alone seeds
// into, so the second case never actually happens here.
func readTenantEpoch(t *testing.T, tenant string) (epoch int64, exists bool) {
	t.Helper()
	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}
	err = tx.QueryRowContext(t.Context(), `SELECT epoch FROM tenant_epoch WHERE tenant_id = $1`, tenant).Scan(&epoch)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, false
	case err != nil:
		t.Fatalf("read tenant_epoch for %s: %v", tenant, err)
	}
	return epoch, true
}

// assertEpochBumped re-reads tenant's epoch and fails t unless a row now
// exists and its value is strictly greater than before -- the property
// every subtest below actually cares about, not any particular delta (the
// two-writes and one-multi-row-statement tests pin exact deltas
// separately, where the brief asks for that).
func assertEpochBumped(t *testing.T, tenant string, before int64) int64 {
	t.Helper()
	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after a governed write, want it created on demand", tenant)
	}
	if after <= before {
		t.Fatalf("epoch = %d after the write, want > %d (before) -- the trigger did not bump", after, before)
	}
	return after
}

// seedTierOverride inserts one tier_overrides row for tenant, mirroring
// seedToolCatalogEntry's own shape (catalog_integration_test.go): a real
// tenant-scoped INSERT via testDB, itself proof that RLS's WITH CHECK
// accepts a correctly tenant-scoped writer. No production seed helper for
// this table exists anywhere in this package yet -- like every one of this
// table's siblings, tier_overrides has no Go writer at all today (only
// LoadAllPolicies/LoadToolCatalog-style readers exist for the governed
// tables) -- so this is necessarily new rather than reused.
func seedTierOverride(t *testing.T, tenant, toolOrVerb string, actionTier, builtinTier models.ActionTier) {
	t.Helper()
	if actionTier < builtinTier {
		t.Fatalf("seedTierOverride(%s): action_tier %s must be >= builtin_tier %s (raise-only CHECK, migrations/000001_baseline)",
			toolOrVerb, actionTier, builtinTier)
	}
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ($1,$2,$3,$4,$5)`,
			tenant, toolOrVerb, int64(actionTier), int64(builtinTier), "integration-test",
		); err != nil {
			t.Fatalf("seed tier override %s: %v", toolOrVerb, err)
		}
	})
}

// TestIntegration_TenantEpoch_CreatesRowOnDemandForUnseenTenant is Task 1's
// decision #1: a tenant with no tenant_epoch row gets one created by its
// first governed write, rather than the trigger silently no-op'ing because
// nothing seeded a row for it first -- see migrations/000015_tenant_epoch_
// trigger's own comment for why "create on demand" was chosen over "seed on
// tenant creation" (this codebase has no tenant-provisioning step to seed
// from at all).
//
// Also pins the specific starting value: 2, not the column's own DEFAULT of
// 1 (migrations/000001_baseline) -- see that same migration comment for why
// 1 is reserved for "no row exists yet" and would make this very write
// invisible to a reader who had cached that default a moment earlier.
func TestIntegration_TenantEpoch_CreatesRowOnDemandForUnseenTenant(t *testing.T) {
	const tenant = "tenant-epoch-create-on-demand-integration"

	if _, exists := readTenantEpoch(t, tenant); exists {
		t.Fatalf("tenant_epoch row for %s already exists before this test's first write -- "+
			"pick a tenant no other test in this package touches", tenant)
	}

	seedPolicy(t, tenant, "first-ever-write", "permit(principal, action, resource);", "allow")

	epoch, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatal("tenant_epoch row still does not exist after a governed write -- the trigger silently no-opped " +
			"instead of creating it on demand")
	}
	if epoch != 2 {
		t.Fatalf("epoch = %d on first creation, want 2 (one past the schema DEFAULT of 1, so this first bump "+
			"is observable against that implicit baseline)", epoch)
	}
}

// TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites is Task 1's core
// proof (migrations/000015_tenant_epoch_trigger): every INSERT, UPDATE, and
// DELETE on policies, agents, tool_catalog, and tier_overrides bumps the
// writing tenant's epoch, and delegations bumps on UPDATE/DELETE. (delegations'
// INSERT case is deliberately not exercised here -- see
// TestIntegration_TenantEpoch_DelegationInsertDoesNotBump's own doc comment
// for why that property needs its own, separate test.)
//
// One dedicated tenant per subtest, not one shared tenant for the whole
// test: every other test in this file also bumps tenant_epoch rows of its
// own, and the suite shares one database (every other
// *_integration_test.go file's own comment on this). A shared tenant here
// would make this test's own before/after deltas depend on run order
// against tests it has no other relationship to.
func TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites(t *testing.T) {
	t.Run("policies", func(t *testing.T) {
		const tenant = "tenant-epoch-policies-integration"
		before, _ := readTenantEpoch(t, tenant)

		id := seedPolicy(t, tenant, "epoch-bump-policy", "permit(principal, action, resource);", "allow")
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
				"bumped", id); err != nil {
				t.Fatalf("UPDATE policies: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM policies WHERE id = $1`, id); err != nil {
				t.Fatalf("DELETE policies: %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)
	})

	t.Run("agents", func(t *testing.T) {
		const tenant = "tenant-epoch-agents-integration"
		before, _ := readTenantEpoch(t, tenant)

		id := uuid.New()
		seedAgent(t, tenant, id, "epoch-bump-agent", models.TrustTierUnverified)
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE agents SET suspended = true WHERE id = $1`,
				id.String()); err != nil {
				t.Fatalf("UPDATE agents: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		// No delegation ever references this agent (a fresh tenant, and this
		// subtest's only agent), so DELETE is not blocked by
		// delegations.agent_id's ON DELETE RESTRICT (migrations/000001_baseline)
		// the way it would be for an agent a real delegation chain uses.
		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM agents WHERE id = $1`, id.String()); err != nil {
				t.Fatalf("DELETE agents: %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)
	})

	t.Run("tool_catalog", func(t *testing.T) {
		const tenant = "tenant-epoch-tool-catalog-integration"
		before, _ := readTenantEpoch(t, tenant)

		resourceField := "file_path"
		seedToolCatalogEntry(t, tenant, "Read", tierPtr(models.ActionTierReadOnly), "read", &resourceField, nil)
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(),
				`UPDATE tool_catalog SET verb = $1 WHERE tenant_id = $2 AND tool_name = $3`,
				"read-updated", tenant, "Read"); err != nil {
				t.Fatalf("UPDATE tool_catalog: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM tool_catalog WHERE tenant_id = $1 AND tool_name = $2`,
				tenant, "Read"); err != nil {
				t.Fatalf("DELETE tool_catalog: %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)
	})

	t.Run("tier_overrides", func(t *testing.T) {
		const tenant = "tenant-epoch-tier-overrides-integration"
		before, _ := readTenantEpoch(t, tenant)

		seedTierOverride(t, tenant, "Bash", models.ActionTierInternalModify, models.ActionTierReadOnly)
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(),
				`UPDATE tier_overrides SET action_tier = $1 WHERE tenant_id = $2 AND tool_or_verb = $3`,
				int64(models.ActionTierDestructive), tenant, "Bash"); err != nil {
				t.Fatalf("UPDATE tier_overrides: %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM tier_overrides WHERE tenant_id = $1 AND tool_or_verb = $2`,
				tenant, "Bash"); err != nil {
				t.Fatalf("DELETE tier_overrides: %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)
	})

	t.Run("delegations_update_and_delete", func(t *testing.T) {
		const tenant = "tenant-epoch-delegations-integration"
		agentID := uuid.New()
		seedAgent(t, tenant, agentID, "epoch-bump-delegations-agent", models.TrustTierUnverified)
		root, child := twoHopChain(t, tenant, agentID)

		// Baseline captured AFTER seeding, not before: the agent INSERT above
		// already bumped once (agents is one of the four unconditional
		// tables), and the two delegation INSERTs (root, child) inside
		// twoHopChain must NOT have bumped further -- that is
		// TestIntegration_TenantEpoch_DelegationInsertDoesNotBump's own
		// property, not re-tested here. This subtest is only about
		// delegations' UPDATE/DELETE.
		before, exists := readTenantEpoch(t, tenant)
		if !exists {
			t.Fatalf("tenant_epoch row for %s does not exist after seeding -- the agent INSERT above should already have created it", tenant)
		}

		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(),
				`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, root.ID.String()); err != nil {
				t.Fatalf("UPDATE delegations (revoke root): %v", err)
			}
		})
		before = assertEpochBumped(t, tenant, before)

		// The child, not the root: the root is self-referencing
		// (root_delegation_id = its own id, migrations/000001_baseline) and
		// that FK has no ON DELETE clause (NO ACTION), so deleting it is not
		// this test's concern to untangle. The child has no descendants and
		// nothing else names it via root_delegation_id or
		// parent_delegation_id, so deleting it exercises this table's DELETE
		// trigger with no FK question attached.
		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `DELETE FROM delegations WHERE id = $1`, child.ID.String()); err != nil {
				t.Fatalf("DELETE delegations (child): %v", err)
			}
		})
		assertEpochBumped(t, tenant, before)
	})
}

// TestIntegration_TenantEpoch_DelegationInsertDoesNotBump is the brief's own
// required negative case, and this file's designated catcher for the "let
// INSERT on delegations bump" mutation (see task-1-report.md): a new
// delegation is purely additive and invalidates no existing decision, so
// bumping on it would invalidate every PEP's cache tenant-wide on every new
// agent session -- see migrations/000015_tenant_epoch_trigger's own leading
// comment for the full argument.
//
// Deliberately its own test, not folded into
// TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites's delegations
// subtest: that test only ever asserts ">" across a sequence of writes that
// starts AFTER the delegation INSERTs already happened, so a regression that
// made INSERT bump too would slip past it unnoticed (an extra bump baked
// into its own "before" reading is invisible to a ">" check). Only a test
// that isolates the INSERT and asserts the epoch is UNCHANGED across it can
// catch that specific mutation.
func TestIntegration_TenantEpoch_DelegationInsertDoesNotBump(t *testing.T) {
	const tenant = "tenant-epoch-delegation-insert-integration"
	agentID := uuid.New()

	// seedAgent's own INSERT does bump (agents is one of the four
	// unconditional tables) -- the baseline is read AFTER it, not before, so
	// this test measures only the delegation INSERT that follows.
	seedAgent(t, tenant, agentID, "epoch-no-bump-agent", models.TrustTierUnverified)
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding the agent", tenant)
	}

	singleHopDelegation(t, tenant, agentID, models.ActionTierInternalModify, "epoch integration: insert must not bump")

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished after a delegation INSERT", tenant)
	}
	if after != before {
		t.Fatalf("epoch = %d after a delegation INSERT, want unchanged at %d -- INSERT on delegations must not bump", after, before)
	}
}

// TestIntegration_TenantEpoch_VisibleWithinTransactionAndRolledBackWithIt
// proves the trigger runs synchronously, inside the same transaction as the
// write it accompanies -- not deferred to commit time and not fired by some
// out-of-band mechanism after the fact. This is this file's designated
// catcher for the "make it fire AFTER the transaction rather than within
// it" mutation: a DEFERRABLE INITIALLY DEFERRED constraint trigger still
// technically commits atomically with the write, but its bump is not
// visible to a read in the same still-open transaction -- only at COMMIT,
// by which point there is no "mid-transaction" window left to observe. A
// plain (non-deferred) AFTER trigger, which is what
// migrations/000015_tenant_epoch_trigger creates, fires immediately after
// the row event and is visible to any later statement in that same
// transaction.
//
// Also proves the other half of "same transaction as the write": a bump
// that is never committed is rolled back with everything else in that
// transaction, exactly like the row it accompanied -- there is no separate
// path by which a bump could survive a rollback of its own write.
func TestIntegration_TenantEpoch_VisibleWithinTransactionAndRolledBackWithIt(t *testing.T) {
	const tenant = "tenant-epoch-same-transaction-integration"

	id := seedPolicy(t, tenant, "same-tx-policy", "permit(principal, action, resource);", "allow")
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
		"mid-transaction", id); err != nil {
		t.Fatalf("UPDATE policies: %v", err)
	}

	var mid int64
	if err := tx.QueryRowContext(t.Context(), `SELECT epoch FROM tenant_epoch WHERE tenant_id = $1`, tenant).Scan(&mid); err != nil {
		t.Fatalf("read epoch inside the still-open transaction: %v", err)
	}
	if mid <= before {
		t.Fatalf("epoch read inside the same, still-uncommitted transaction = %d, want > %d -- the bump is not "+
			"visible until commit, so it is not really running within the write's own transaction", mid, before)
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished after rollback", tenant)
	}
	if after != before {
		t.Fatalf("epoch = %d after rollback, want unchanged at %d -- a bump from a rolled-back write must not survive it",
			after, before)
	}
}

// TestIntegration_TenantEpoch_TwoWritesInOneTransactionBumpTwice pins Task
// 1's decision on density: FOR EACH ROW, not FOR EACH STATEMENT or a
// once-per-transaction dedupe (see migrations/000015_tenant_epoch_trigger's
// own comment for the full justification -- monotonicity is the property
// every consumer needs, density is not). Two separate single-row writes to
// two different governed tables, in one transaction, must bump the shared
// counter twice, not once.
//
// See TestIntegration_TenantEpoch_OneMultiRowStatementBumpsPerRow for the
// complementary case (one statement, two rows) this test cannot itself
// distinguish from FOR EACH STATEMENT semantics.
func TestIntegration_TenantEpoch_TwoWritesInOneTransactionBumpTwice(t *testing.T) {
	const tenant = "tenant-epoch-two-writes-one-tx-integration"

	policyID := seedPolicy(t, tenant, "two-writes-policy", "permit(principal, action, resource);", "allow")
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "two-writes-agent", models.TrustTierUnverified)
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
		"first write", policyID); err != nil {
		t.Fatalf("UPDATE policies (first write): %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `UPDATE agents SET suspended = true WHERE id = $1`,
		agentID.String()); err != nil {
		t.Fatalf("UPDATE agents (second write): %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished", tenant)
	}
	if want := before + 2; after != want {
		t.Fatalf("epoch = %d after two writes in one transaction, want exactly %d (before=%d + 2, one bump per row event)",
			after, want, before)
	}
}

// TestIntegration_TenantEpoch_OneMultiRowStatementBumpsPerRow complements
// TestIntegration_TenantEpoch_TwoWritesInOneTransactionBumpTwice with the
// one case that test cannot distinguish: two separate single-row UPDATE
// statements bump twice under FOR EACH ROW (what
// migrations/000015_tenant_epoch_trigger declares) and, coincidentally,
// also under FOR EACH STATEMENT (which fires once per statement -- twice
// here too, since there are two statements). A single UPDATE that touches
// two rows is what actually tells the two apart: FOR EACH ROW bumps once
// per row (twice here), FOR EACH STATEMENT would bump once for the whole
// statement regardless of how many rows it touched.
func TestIntegration_TenantEpoch_OneMultiRowStatementBumpsPerRow(t *testing.T) {
	const tenant = "tenant-epoch-multi-row-statement-integration"

	seedPolicy(t, tenant, "multi-row-policy-1", "permit(principal, action, resource);", "allow")
	seedPolicy(t, tenant, "multi-row-policy-2", "permit(principal, action, resource);", "allow")
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	withTenantTx(t, tenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = 'multi-row-bump' WHERE tenant_id = $1`, tenant)
		if err != nil {
			t.Fatalf("UPDATE policies (multi-row): %v", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			t.Fatalf("RowsAffected: %v", err)
		} else if n != 2 {
			t.Fatalf("UPDATE affected %d rows, want 2 -- fixture assumption broken, not what this test means to measure", n)
		}
	})

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished", tenant)
	}
	if want := before + 2; after != want {
		t.Fatalf("epoch = %d after one UPDATE touching 2 rows, want exactly %d (before=%d + 2) -- "+
			"FOR EACH ROW must bump once per row, not once per statement", after, want, before)
	}
}

// TestIntegration_TenantEpoch_BumpsForNonOwnerRole is Task 1's RLS proof --
// the brief's own "most likely place for this task to be silently wrong":
// stratium_migrate owns every governed table and tenant_epoch itself
// (deploy/docker/init-db.sql), so a bump performed as testDB works whether
// or not the trigger's own write to tenant_epoch is correctly privileged --
// ownership alone is enough, independent of any GRANT. The serving role
// (stratium/stratium_app) owns nothing, so a bump performed as servingDB
// only works if migrations/000015_tenant_epoch_trigger's
// GRANT SELECT, INSERT, UPDATE ON tenant_epoch TO stratium_app line is both
// present and sufficient -- SELECT included, which this test is also what
// caught missing during development: UPDATE alone let the grant look
// sufficient right up until the upsert's own `epoch = epoch + 1` tried to
// read the column it increments and failed closed instead. Every other test
// in this file uses testDB and would pass identically whether or not that
// grant existed -- this is the one test that would not.
// identically whether or not that grant existed -- this is the one test
// that would not.
//
// Per spec E7/T1, the serving role has no legitimate write of its own on
// any of the four unconditional tables today: policies, agents, and
// tool_catalog grant it SELECT only (migrations/000005, 000007, 000013),
// and tier_overrides grants it nothing at all. That gap is deliberate, not
// a bug this task should close -- a control-plane write is not this role's
// job (V4). This test grants stratium_app a test-scoped, temporary INSERT
// on tier_overrides -- revoked in cleanup -- purely to give servingDB a
// real write to perform; it is not a claim that the serving role should
// hold that grant in production (TestIntegration_ToolCatalog_
// ServingRoleCannotWrite already proves the opposite for the sibling
// table, and nothing here changes that). What this test actually
// exercises is the trigger's own RLS/GRANT interaction on tenant_epoch,
// which does not depend on which table's grant was used to reach it.
func TestIntegration_TenantEpoch_BumpsForNonOwnerRole(t *testing.T) {
	const tenant = "tenant-epoch-non-owner-role-integration"

	if _, err := testDB.ExecContext(t.Context(), `GRANT INSERT ON tier_overrides TO stratium_app`); err != nil {
		t.Fatalf("test-scoped GRANT: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testDB.ExecContext(context.Background(), `REVOKE INSERT ON tier_overrides FROM stratium_app`); err != nil {
			t.Errorf("cleanup: REVOKE test-scoped grant: %v", err)
		}
	})

	before, _ := readTenantEpoch(t, tenant)

	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on serving connection: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(),
		`INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ($1,$2,$3,$4,$5)`,
		tenant, "Bash", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), "integration-test-serving-role",
	); err != nil {
		t.Fatalf("INSERT tier_overrides as the serving role = %v, want nil -- this test's own temporary GRANT should "+
			"have made this succeed; if it did not, the temporary GRANT above is the problem, not the trigger", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after a write by the serving role -- the trigger's own "+
			"write to tenant_epoch likely failed, or migrations/000015's GRANT SELECT, INSERT, UPDATE ON tenant_epoch "+
			"TO stratium_app is missing or incomplete", tenant)
	}
	if after <= before {
		t.Fatalf("epoch = %d after a write by the serving role, want > %d -- a non-owner role's bump did not take effect",
			after, before)
	}
}

// TestIntegration_TenantEpoch_MissingGrantFailsTheWriteClosed is not one of
// the brief's explicitly named tests, but it is a direct proof of a binding
// constraint stated three times over -- the phase plan's global
// constraints, the task brief, and migrations/000015_tenant_epoch_trigger's
// own comment: fail closed. If the trigger cannot bump tenant_epoch (here:
// because the writing role lacks a grant on it, the exact failure mode that
// migration's own comment predicts for a role with a table grant but no
// tenant_epoch grant), the write it accompanies must fail outright, not
// succeed silently un-bumped.
//
// This is not a design choice this trigger's own code implements specially
// -- an unhandled exception in a trigger function aborts the whole
// enclosing transaction by default in Postgres -- but "the default
// happens to be correct" is exactly the kind of claim this codebase does
// not take on faith (house style: back it with a real assertion, not a
// comment). This also doubles as a negative-space check on
// TestIntegration_TenantEpoch_BumpsForNonOwnerRole: that test's temporary
// GRANT on tier_overrides is necessary, not merely present -- reusing the
// identical setup here with tenant_epoch's own grant removed shows the
// write does NOT succeed without it.
func TestIntegration_TenantEpoch_MissingGrantFailsTheWriteClosed(t *testing.T) {
	const tenant = "tenant-epoch-fail-closed-integration"

	if _, err := testDB.ExecContext(t.Context(), `GRANT INSERT ON tier_overrides TO stratium_app`); err != nil {
		t.Fatalf("test-scoped GRANT on tier_overrides: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testDB.ExecContext(context.Background(), `REVOKE INSERT ON tier_overrides FROM stratium_app`); err != nil {
			t.Errorf("cleanup: REVOKE test-scoped grant on tier_overrides: %v", err)
		}
	})
	// The one difference from TestIntegration_TenantEpoch_BumpsForNonOwnerRole:
	// stratium_app's own migrations/000015 grant on tenant_epoch is removed
	// first, so the serving role can reach tier_overrides but the trigger it
	// fires cannot reach tenant_epoch.
	if _, err := testDB.ExecContext(t.Context(), `REVOKE SELECT, INSERT, UPDATE ON tenant_epoch FROM stratium_app`); err != nil {
		t.Fatalf("test-scoped REVOKE on tenant_epoch: %v", err)
	}
	t.Cleanup(func() {
		if _, err := testDB.ExecContext(context.Background(), `GRANT SELECT, INSERT, UPDATE ON tenant_epoch TO stratium_app`); err != nil {
			t.Errorf("cleanup: restore migrations/000015's own GRANT on tenant_epoch: %v", err)
		}
	})

	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on serving connection: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
	}
	_, insertErr := tx.ExecContext(t.Context(),
		`INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ($1,$2,$3,$4,$5)`,
		tenant, "Bash", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), "integration-test-fail-closed",
	)
	if insertErr == nil {
		t.Fatal("INSERT tier_overrides succeeded despite the trigger having no grant on tenant_epoch -- " +
			"want the whole write to fail closed, not land un-bumped")
	}
	var pqErr *pq.Error
	if !errors.As(insertErr, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
		t.Fatalf("INSERT error = %v, want SQLSTATE %s (insufficient_privilege) from the trigger's own write to tenant_epoch",
			insertErr, sqlStatePermissionDenied)
	}
	t.Logf("INSERT tier_overrides correctly failed closed when the trigger could not reach tenant_epoch: %v", insertErr)

	// The row must not exist despite the INSERT attempt: the whole
	// transaction -- the tier_overrides row AND any partial bump -- was
	// rejected together, not applied piecemeal. Read via withTenantTx
	// (app.tenant_id set first): tier_overrides is FORCE ROW LEVEL SECURITY
	// too, so an unscoped count would silently see zero rows regardless of
	// whether the INSERT had actually landed -- the exact trap this
	// package's other integration tests have already lost time to.
	var count int
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT count(*) FROM tier_overrides WHERE tenant_id = $1 AND tool_or_verb = $2`, tenant, "Bash",
		).Scan(&count); err != nil {
			t.Fatalf("count tier_overrides rows: %v", err)
		}
	})
	if count != 0 {
		t.Fatalf("tier_overrides has %d row(s) for %s despite the INSERT failing -- the write was not actually rolled back",
			count, tenant)
	}
}

// TestIntegration_TenantEpoch_OperatorPsqlUpdateBumps is the third of the
// three paths the brief asks this task to verify against (the other two:
// TestIntegration_TenantEpoch_BumpsOnGovernedTableWrites, which writes
// through testDB/database/sql exactly like every other fixture in this
// package -- "the migration role's writes" -- and
// TestIntegration_TenantEpoch_BumpsForNonOwnerRole -- "the serving role's
// writes"). A trigger is a property of the table, not of any particular
// client library -- lib/pq (every other test in this file) and psql both
// speak the same Postgres wire protocol -- so this test is less about
// protocol-level coverage than about the scenario itself: an operator, in
// an incident, running a raw UPDATE by hand, with no application code, not
// even this test package's own Go helpers, anywhere in the path. If the
// trigger were somehow tied to *how* a write arrives rather than to the
// table itself, this is the test that would catch it.
func TestIntegration_TenantEpoch_OperatorPsqlUpdateBumps(t *testing.T) {
	if _, err := exec.LookPath("psql"); err != nil {
		t.Fatalf("psql not found on PATH: %v -- required to prove a direct operator UPDATE cannot bypass the trigger (V1)", err)
	}
	dbURL := os.Getenv("STRATIUM_IT_DATABASE_URL")
	if dbURL == "" {
		t.Fatal("STRATIUM_IT_DATABASE_URL is unset -- run via `make integration`")
	}

	const tenant = "tenant-epoch-psql-operator-integration"
	id := seedPolicy(t, tenant, "psql-operator-policy", "permit(principal, action, resource);", "allow")
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	// One psql invocation, one simple-query message containing both
	// statements: Postgres executes a multi-statement simple-query message
	// as a single implicit transaction, so set_config's is_local scoping
	// (internal/store/store.go's own setTenantQuery comment explains why
	// is_local matters) still applies to the UPDATE that follows it in the
	// same -c string, exactly as it would inside a Go *sql.Tx.
	stmt := fmt.Sprintf(
		"SELECT set_config('app.tenant_id', %s, true); UPDATE policies SET description = 'bumped-by-psql-operator' WHERE id = %s;",
		pq.QuoteLiteral(tenant), pq.QuoteLiteral(id))
	cmd := exec.CommandContext(t.Context(), "psql", dbURL, "-v", "ON_ERROR_STOP=1", "-c", stmt)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("psql UPDATE failed: %v\noutput:\n%s", err, out)
	}

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished after a psql UPDATE", tenant)
	}
	if after <= before {
		t.Fatalf("epoch = %d after a direct psql UPDATE, want > %d -- an operator's raw SQL client bypassed the trigger",
			after, before)
	}
}

// TestIntegration_TenantEpoch_BumpsAreMonotonicAcrossManyWrites is this
// file's designated catcher for the "make the bump non-monotonic" mutation:
// a run of several separate bumps, each in its own transaction, must
// produce a strictly increasing sequence with no repeats and no decreases.
// TestIntegration_TenantEpoch_TwoWritesInOneTransactionBumpTwice already
// pins the exact delta for two writes in one transaction; this test instead
// pins the weaker, more general property every consumer actually depends on
// (V1: "monotonic," not "increments by exactly 1 every time") across many
// separate writes -- a mutation that replaced the increment with, say, a
// constant or a decrement fails on the very first write, and even a subtler
// one (occasionally reusing a value) fails on the first repeat.
func TestIntegration_TenantEpoch_BumpsAreMonotonicAcrossManyWrites(t *testing.T) {
	const tenant = "tenant-epoch-monotonic-integration"
	const writes = 5

	id := seedPolicy(t, tenant, "monotonic-policy", "permit(principal, action, resource);", "allow")
	last, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	for i := 0; i < writes; i++ {
		withTenantTx(t, tenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
				fmt.Sprintf("monotonic-write-%d", i), id); err != nil {
				t.Fatalf("UPDATE policies (write %d): %v", i, err)
			}
		})
		next, exists := readTenantEpoch(t, tenant)
		if !exists {
			t.Fatalf("tenant_epoch row for %s vanished after write %d", tenant, i)
		}
		if next <= last {
			t.Fatalf("epoch = %d after write %d, want strictly greater than the previous value %d -- "+
				"a bump must never reuse or lower the epoch", next, i, last)
		}
		last = next
	}
}

// TestIntegration_TenantEpoch_LoadForUnseenTenantReturnsSchemaDefault is
// Task 2's own real-Postgres proof, complementing every readTenantEpoch-based
// fixture above with the actual reader a future PEP cache will call:
// store.LoadTenantEpoch, not a raw SELECT this package's own test helper
// happens to run. A tenant nothing has ever written for reports 1 -- the
// schema's own DEFAULT (migrations/000001_baseline) and the value
// TestIntegration_TenantEpoch_CreatesRowOnDemandForUnseenTenant already
// establishes as what "no row" must read back as -- never an error, and
// never 0, which this column cannot hold (BIGINT NOT NULL DEFAULT 1) and
// would be indistinguishable from a tenant genuinely observed at that
// (nonexistent) epoch by anything that forgot to check LoadTenantEpoch's
// error return first.
func TestIntegration_TenantEpoch_LoadForUnseenTenantReturnsSchemaDefault(t *testing.T) {
	const tenant = "tenant-epoch-load-unseen-integration"

	if _, exists := readTenantEpoch(t, tenant); exists {
		t.Fatalf("tenant_epoch row for %s already exists before this test's first read -- "+
			"pick a tenant no other test in this package touches", tenant)
	}

	got, err := store.New(testDB, tenant).LoadTenantEpoch(t.Context())
	if err != nil {
		t.Fatalf("LoadTenantEpoch() error = %v, want nil for a tenant with no row", err)
	}
	if got != 1 {
		t.Fatalf("LoadTenantEpoch() = %d, want 1 (the schema's own DEFAULT)", got)
	}
}

// TestIntegration_TenantEpoch_LoadReflectsARealBump closes the loop Task 1's
// own package doc (store.go) left open: store.LoadTenantEpoch, called
// against the real trigger's own output, reports exactly what the trigger
// wrote -- not a value this package caches or derives independently. Two
// bumps, not one: a reader that only happened to see the right value once
// (a caching bug LoadAllPolicies/LoadToolCatalog's own "called fresh every
// time" convention already rules out for every other per-tenant read) would
// still pass a single-bump check by coincidence but fails the second.
func TestIntegration_TenantEpoch_LoadReflectsARealBump(t *testing.T) {
	const tenant = "tenant-epoch-load-real-bump-integration"
	repo := store.New(testDB, tenant)

	id := seedPolicy(t, tenant, "load-real-bump-policy", "permit(principal, action, resource);", "allow")
	first, err := repo.LoadTenantEpoch(t.Context())
	if err != nil {
		t.Fatalf("LoadTenantEpoch() error = %v", err)
	}
	if first != 2 {
		t.Fatalf("LoadTenantEpoch() after the first governed write = %d, want 2 (migrations/000015's own first-bump value)", first)
	}

	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
			"bumped-for-load-test", id); err != nil {
			t.Fatalf("UPDATE policies: %v", err)
		}
	})

	second, err := repo.LoadTenantEpoch(t.Context())
	if err != nil {
		t.Fatalf("LoadTenantEpoch() error = %v", err)
	}
	if second != 3 {
		t.Fatalf("LoadTenantEpoch() after a second governed write = %d, want 3", second)
	}
}
