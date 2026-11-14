//go:build integration

// Integration proofs for the override step of spec §4.4's resolution order
// against a real Postgres (Phase 14 Task 7 — T4/T5/T6). Three things only a
// live database can establish, and which internal/pdpgrpc's own unit tests
// (tier_override_test.go, fakeStore) deliberately do not attempt:
//
//  1. The serving role's GRANT is sufficient to read this table and is
//     nothing more than SELECT (T6).
//  2. An override written the ordinary way reaches a real Decide, through
//     the real serving identity, against real RLS.
//  3. A lowering row inserted DIRECTLY into the table — never passing
//     through the PAP, and satisfying the schema's own
//     tier_overrides_raise_only CHECK because that CHECK compares against a
//     builtin_tier column such a write supplies for itself — is dropped at
//     read time rather than honored.
//
// The third is the one that cannot be proven any other way: it is a claim
// about what the database will happily accept, so faking the database
// assumes away the premise.
//
// The filename USED TO BE load-bearing, and is no longer — recorded here
// because the constraint it encoded is exactly the sort that comes back if
// nobody writes down that it was lifted. `go test` compiles a package's
// files in sorted order and runs tests in declaration order, and
// TestEndToEnd's own proof6_failed_audit_append_blocks_the_decision
// (store_integration_test.go) REVOKEs INSERT on audit_chain from both
// stratium_app and stratium_audit_owner. Every proof below calls Decide,
// which appends an audit row. This file was originally named "decide_..."
// so it would sort ahead of store_integration_test.go, found empirically:
// named tier_override_integration_test.go, both Decide proofs failed with
// "permission denied for table audit_chain" in the full suite while passing
// in isolation.
//
// Phase 14 Task 8 fixed that at the source — proof6 now restores both
// grants in a t.Cleanup (restoreAuditChainInsert, store_integration_test.go)
// and verifies they came back — so the revoke is scoped to that subtest and
// this file may be renamed freely. Confirmed by renaming it to
// zz_tier_override_integration_test.go (sorting after store_) and running
// the full integration suite green. The name is kept only because there is
// no reason to churn it.
package store_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/internal/token"
	"github.com/stratiumdata/stratium/pkg/models"
)

// tierOverrideServer builds a real pdpgrpc.Server for tenant on the SERVING
// connection, not testDB. That is the whole point of these proofs: the PDP
// serves as stratium_app, and every read Decide performs must be within that
// role's grants — including the tier_overrides SELECT
// migrations/000017_tier_overrides_serving_grant adds. Built on testDB, a
// missing or revoked grant would go completely unnoticed here.
//
// escalationServer (escalation_integration_test.go) is the shape this
// mirrors, and its helpers — seedPolicy for the blanket permit,
// escalationSigner, escalationToken — are reused rather than duplicated;
// only the connection differs, and it differs deliberately.
func tierOverrideServer(t *testing.T, tenant string) (*pdpgrpc.Server, *token.Signer) {
	t.Helper()
	seedPolicy(t, tenant, "tier-override-blanket-permit", escalationBlanketPermit, "allow")
	repo := store.New(servingDB, tenant)
	cfg := config.Config{TenantID: tenant, MaxDepth: 5, ApprovalTTL: time.Hour}
	signer := escalationSigner(t)
	return pdpgrpc.NewServer(repo, policy.NewMulti(repo, escalationRegistry()), cfg, signer), signer
}

// plainRootDelegation is escalatingRootDelegation without the escalation
// band: these proofs are about which tier is DERIVED, so a delegation that
// escalates would turn every assertion into a question about approvals
// instead. The ceiling is DESTRUCTIVE so no proof here denies at the
// delegation leg before its derived tier can be read off the response.
func plainRootDelegation(t *testing.T, tenant string, agentID uuid.UUID, principal string) *models.Delegation {
	t.Helper()
	id := uuid.New()
	return seedDelegation(t, &models.Delegation{
		ID: id, TenantID: tenant, UserID: principal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "tier override proof", ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
}

// insertTierOverrideDirectly writes a row bypassing the PAP entirely — the
// database-superuser INSERT read-time re-validation exists for. builtinTier
// is the caller's to choose precisely because that is what such a write
// controls: the schema's tier_overrides_raise_only CHECK compares
// action_tier against THIS value, so a lowering row that declares a low
// enough builtin_tier satisfies the constraint completely.
//
// testDB, not papDB or servingDB: this is deliberately not any legitimate
// write path. seedTierOverride (tenant_epoch_integration_test.go) refuses an
// action_tier below its builtin_tier as a fixture-safety check, which is
// exactly the check this helper must not perform.
func insertTierOverrideDirectly(t *testing.T, tenant, toolOrVerb string, actionTier, builtinTier models.ActionTier) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ($1,$2,$3,$4,$5)`,
			tenant, toolOrVerb, int64(actionTier), int64(builtinTier), "direct-database-write",
		); err != nil {
			t.Fatalf("direct INSERT into tier_overrides (%s): %v", toolOrVerb, err)
		}
	})
}

// TestIntegration_StratiumApp_CanReadButCannotWriteTierOverrides is T6's
// proof, and it is the same shape TestIntegration_ToolCatalog_
// ServingRoleCannotWrite gives tool_catalog: the read must work first, or
// the three write refusals below would be indistinguishable from "this role
// can do nothing at all."
//
// The absent grants are the enforcement. A PDP that could write an override
// would be the component being policed adjusting its own action-tier
// classification — spec defect D1, and precisely what conformance property
// C5 forbids. A future migration widening this by accident fails here rather
// than shipping.
func TestIntegration_StratiumApp_CanReadButCannotWriteTierOverrides(t *testing.T) {
	const tenant = "tenant-tier-override-grant-integration"

	seedTierOverride(t, tenant, "Bash", models.ActionTierDestructive, models.ActionTierReasoning)

	got, err := store.New(servingDB, tenant).LoadTierOverrides(t.Context())
	if err != nil {
		t.Fatalf("LoadTierOverrides() via the serving role error = %v, want nil — "+
			"SELECT must work before INSERT/UPDATE/DELETE's absence means anything "+
			"(migrations/000017_tier_overrides_serving_grant)", err)
	}
	if len(got) != 1 || got["Bash"] != models.ActionTierDestructive {
		t.Fatalf("LoadTierOverrides() via the serving role = %v, want {Bash: DESTRUCTIVE}", got)
	}

	// Each write in its own subtest, so an accidental widening of exactly
	// one grant fails only that subtest and names which verb leaked.
	writes := map[string]string{
		"INSERT": `INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) ` +
			`VALUES ('` + tenant + `', 'Write', 4, 0, 'pdp')`,
		"UPDATE": `UPDATE tier_overrides SET action_tier = 0 WHERE tool_or_verb = 'Bash'`,
		"DELETE": `DELETE FROM tier_overrides WHERE tool_or_verb = 'Bash'`,
	}
	for op, stmt := range writes {
		t.Run(op, func(t *testing.T) {
			tx, err := servingDB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
				t.Fatalf("set tenant: %v", err)
			}

			_, err = tx.ExecContext(t.Context(), stmt)
			if err == nil {
				t.Fatalf("%s tier_overrides as the serving role succeeded, want a permission error — "+
					"T6 requires this grant to be absent (migrations/000017_tier_overrides_serving_grant)", op)
			}
			var pqErr *pq.Error
			if !errors.As(err, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
				t.Fatalf("%s error = %v, want SQLSTATE %s (insufficient_privilege)", op, err, sqlStatePermissionDenied)
			}
			t.Logf("%s tier_overrides as the serving role correctly failed: %v", op, err)
		})
	}
}

// TestIntegration_TierOverride_RaisesTheDerivedTierThroughARealDecide is the
// task's headline property against a real database and the real serving
// identity: an override raises a tool's tier and the change reaches a real
// decision. `ls -la` derives READ_ONLY with no override; the override takes
// it to DESTRUCTIVE.
//
// Everything between the row and the response is real here — the RLS-scoped
// SELECT under stratium_app's own grant, the merge with the tenant's (empty)
// catalog, the re-validation, and authz.DeriveTier itself.
func TestIntegration_TierOverride_RaisesTheDerivedTierThroughARealDecide(t *testing.T) {
	const tenant = "tenant-tier-override-decide-integration"
	const principal = "override-raise@example.com"
	srv, signer := tierOverrideServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "tier-override-raise-agent", models.TrustTierPlatformTrusted)
	delegation := plainRootDelegation(t, tenant, agentID, principal)

	// Bash has no built-in catalog entry and is not a verb, so its baseline
	// is ActionTier's own floor — every tier is a raise, and DESTRUCTIVE is
	// accepted.
	seedTierOverride(t, tenant, "Bash", models.ActionTierDestructive, models.ActionTierReasoning)

	resp, err := srv.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token:    escalationToken(t, signer, delegation.ID),
		AgentId:  agentID.String(),
		Subject:  principal,
		Tool:     "Bash",
		RawInput: "ls -la",
	})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierDestructive) {
		t.Fatalf("DerivedTier = %d, want %d (DESTRUCTIVE): `ls -la` derives READ_ONLY without the override, "+
			"so this is the override reaching the decision, not a coincidence", got, models.ActionTierDestructive)
	}
}

// TestIntegration_TierOverride_DirectlyInsertedLoweringRowIsDroppedAtReadTime
// is the proof read-time re-validation exists for, and the one that needs a
// real database to mean anything.
//
// The tenant catalogs Read as DESTRUCTIVE. A row is then inserted directly
// into tier_overrides claiming INTERNAL_MODIFY for Read, declaring its own
// builtin_tier as REASONING so the schema's tier_overrides_raise_only CHECK
// (action_tier >= builtin_tier) is satisfied — 2 >= 0. The database accepts
// it. The PAP would not have, but the PAP was never involved.
//
// The row is dropped and the resolution falls through to the catalog entry
// beneath it. A mutation that honored dropped rows, or that re-validated
// against the STORED builtin_tier column instead of the live baseline,
// produces INTERNAL_MODIFY here.
func TestIntegration_TierOverride_DirectlyInsertedLoweringRowIsDroppedAtReadTime(t *testing.T) {
	const tenant = "tenant-tier-override-dropped-integration"
	const principal = "override-drop@example.com"
	srv, signer := tierOverrideServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "tier-override-drop-agent", models.TrustTierPlatformTrusted)
	delegation := plainRootDelegation(t, tenant, agentID, principal)

	seedToolCatalogEntry(t, tenant, "Read", tierPtr(models.ActionTierDestructive), "", nil, nil)
	insertTierOverrideDirectly(t, tenant, "Read", models.ActionTierInternalModify, models.ActionTierReasoning)

	resp, err := srv.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token:    escalationToken(t, signer, delegation.ID),
		AgentId:  agentID.String(),
		Subject:  principal,
		Tool:     "Read",
		RawInput: "/tmp/notes.txt",
	})
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if got := resp.GetDerivedTier(); got != int32(models.ActionTierDestructive) {
		t.Fatalf("DerivedTier = %d, want %d (DESTRUCTIVE, the catalog entry beneath the dropped override): "+
			"a lowering row the database accepted must not be honored", got, models.ActionTierDestructive)
	}
}
