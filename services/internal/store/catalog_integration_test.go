//go:build integration

// Task 1's real-Postgres proof for tool_catalog (migrations/000013_tool_catalog).
// A separate file from store_integration_test.go, the same choice
// escalation_integration_test.go's own doc comment already makes and
// justifies at length: every package-level var and helper this file uses
// (testDB, servingDB, withTenantTx, sqlStatePermissionDenied, ...) is
// already shared across every *_test.go file in this one package without an
// import, so there is no reason to grow the existing monolith to add one
// more table's proof to it.
package store_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/lib/pq"

	"stratium/internal/store"
	"stratium/pkg/models"
)

// insertToolCatalogQuery mirrors migrations/000013_tool_catalog's column
// list. id is omitted deliberately: the schema default
// (uuid_generate_v4()) is what every other seed helper in this package
// relies on too (seedAgent's own insertAgentQuery omits it the same way),
// and nothing in this file ever needs a seeded row's id back.
const insertToolCatalogQuery = `INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb, resource_field, command_field)
	VALUES ($1,$2,$3,$4,$5,$6)`

// seedToolCatalogEntry inserts one tool_catalog row for tenant via testDB
// inside a correctly tenant-scoped transaction (withTenantTx), the same
// pattern seedAgent and seedPolicy already use: a successful seed is itself
// proof RLS's WITH CHECK accepts a correctly tenant-scoped writer, not just
// proof that some row landed in the table.
//
// tier is *models.ActionTier, not models.ActionTier: action_tier is
// nullable (migrations/000014_tool_catalog_nullable_tier), and a nil tier
// here seeds a genuine NULL-tier row (a Bash-shaped, command-classified
// entry) rather than only ever being able to seed a fixed one. See
// tierPtr below for the ordinary fixed-tier case.
func seedToolCatalogEntry(
	t *testing.T, tenant, toolName string, tier *models.ActionTier, verb string, resourceField, commandField *string,
) {
	t.Helper()
	var tierArg any
	if tier != nil {
		tierArg = int64(*tier)
	}
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertToolCatalogQuery,
			tenant, toolName, tierArg, verb, resourceField, commandField,
		); err != nil {
			t.Fatalf("seed tool catalog entry %s: %v", toolName, err)
		}
	})
}

// tierPtr builds a fixed, non-NULL action_tier argument for
// seedToolCatalogEntry — the ordinary case, spelled out explicitly rather
// than via a bare value, since a nil *models.ActionTier means something
// different and specific here (see seedToolCatalogEntry's own doc comment).
func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

// assertPermissionDenied fails t unless err is specifically a Postgres
// insufficient_privilege error (SQLSTATE 42501) — not merely a non-nil
// error, per the task brief's own requirement that each denial below be
// asserted for the permission failure it actually is, the same specificity
// TestIntegration_Approvals_ServingRoleCannotUpdate holds its own UPDATE
// probe to.
func assertPermissionDenied(t *testing.T, op string, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s tool_catalog as the serving role succeeded, want a permission error — "+
			"T1 requires this grant to be absent (migrations/000013_tool_catalog)", op)
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
		t.Fatalf("%s error = %v, want SQLSTATE %s (insufficient_privilege)", op, err, sqlStatePermissionDenied)
	}
	t.Logf("%s tool_catalog as the serving role correctly failed: %v", op, err)
}

// TestIntegration_ToolCatalog_ServingRoleCannotWrite is Task 1's T1/E7
// proof: the serving role can read the catalog (SELECT —
// migrations/000013_tool_catalog) but genuinely cannot write it, in any of
// the three ways SQL can write a row. This is the same shape
// TestIntegration_Approvals_ServingRoleCannotUpdate gives approvals
// (migrations/000012_approvals), but complete rather than partial: that
// table's serving role legitimately keeps INSERT for CreateApproval, so
// only UPDATE needed proving absent. tool_catalog has no legitimate PDP
// writer of any kind, so INSERT, UPDATE, and DELETE all need their own
// proof — a passing UPDATE-only test here would say nothing about whether
// INSERT or DELETE were accidentally left grantable.
//
// sqlmock cannot prove any of this (internal/store/catalog_test.go proves
// the Go call shape only, nothing about privilege); only a real Postgres,
// connected as the real serving identity, can — see servingDB's own doc
// comment (store_integration_test.go) for why testDB specifically cannot
// stand in for it here.
//
// Its own tenant, for the reason TestIntegration_LoadAllPolicies_
// RoundTripsPriority's own comment gives: the suite shares one database.
func TestIntegration_ToolCatalog_ServingRoleCannotWrite(t *testing.T) {
	const tenant = "tenant-tool-catalog-grant-integration"
	resourceField := "file_path"

	seedToolCatalogEntry(t, tenant, "Read", tierPtr(models.ActionTierReadOnly), "read", &resourceField, nil)

	// SELECT first, through the serving role itself: this doubles as proof
	// the serving role's own grant is sufficient for LoadToolCatalog to
	// work at all, and that the schema's nullable TEXT columns round-trip
	// correctly against a real Postgres (sqlmock cannot prove that; it
	// fakes the driver). Without this, a role that could read nothing would
	// make the write probes below meaningless — their failure
	// indistinguishable from "nothing works for this role," the same
	// reasoning TestIntegration_Approvals_ServingRoleCannotUpdate applies to
	// CreateApproval before its own UPDATE probe.
	got, err := store.New(servingDB, tenant).LoadToolCatalog(t.Context())
	if err != nil {
		t.Fatalf("LoadToolCatalog() via the serving role error = %v, want nil — "+
			"SELECT must work before INSERT/UPDATE/DELETE's absence means anything", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadToolCatalog() via the serving role returned %d entries, want 1", len(got))
	}
	if got[0].ToolName != "Read" || got[0].ActionTier == nil || *got[0].ActionTier != models.ActionTierReadOnly || got[0].Verb != "read" {
		t.Fatalf("LoadToolCatalog() via the serving role = %+v, want the seeded Read row", got[0])
	}
	if got[0].ResourceField == nil || *got[0].ResourceField != "file_path" {
		t.Fatalf("LoadToolCatalog() via the serving role ResourceField = %v, want %q", got[0].ResourceField, "file_path")
	}
	if got[0].CommandField != nil {
		t.Fatalf("LoadToolCatalog() via the serving role CommandField = %v, want nil (NULL column)", got[0].CommandField)
	}

	// The three write probes: same serving connection, same tenant, raw SQL
	// rather than a Go store method — there is no CreateToolCatalogEntry or
	// similar wrapper because T1 says none should ever exist. Each runs in
	// its own subtest so a future accidental widening of exactly one grant
	// (see the mutation-testing note in the task report) fails only that
	// subtest, not the read proof above or the other two writes. Every
	// probe is scoped by RLS via app.tenant_id, not a WHERE tenant_id
	// clause, matching every other query in this package, and is never
	// committed, only ever rolled back: each write is expected to fail
	// outright, so there is nothing any of these transactions should
	// persist.
	t.Run("INSERT", func(t *testing.T) {
		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin tx on serving connection: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
		}

		_, insertErr := tx.ExecContext(t.Context(), insertToolCatalogQuery,
			tenant, "Write", int64(models.ActionTierInternalModify), "write", nil, nil)
		assertPermissionDenied(t, "INSERT", insertErr)
	})

	t.Run("UPDATE", func(t *testing.T) {
		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin tx on serving connection: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
		}

		_, updateErr := tx.ExecContext(t.Context(),
			`UPDATE tool_catalog SET action_tier = $1 WHERE tool_name = $2`,
			int64(models.ActionTierDestructive), "Read")
		assertPermissionDenied(t, "UPDATE", updateErr)
	})

	t.Run("DELETE", func(t *testing.T) {
		tx, err := servingDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin tx on serving connection: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
		}

		_, deleteErr := tx.ExecContext(t.Context(), `DELETE FROM tool_catalog WHERE tool_name = $1`, "Read")
		assertPermissionDenied(t, "DELETE", deleteErr)
	})

	// Belt-and-suspenders on top of the three permission errors themselves:
	// confirm via testDB (unaffected by the grant, since it owns the table)
	// that the row genuinely never changed.
	final, err := store.New(testDB, tenant).LoadToolCatalog(t.Context())
	if err != nil {
		t.Fatalf("LoadToolCatalog() via testDB error = %v", err)
	}
	if len(final) != 1 || final[0].ToolName != "Read" || final[0].ActionTier == nil || *final[0].ActionTier != models.ActionTierReadOnly {
		t.Fatalf("tool_catalog row changed despite every write being denied: got %+v", final)
	}
}

// TestIntegration_ToolCatalog_NullTierRoundTrips is
// migrations/000014_tool_catalog_nullable_tier's positive proof: a
// Bash-shaped row — NULL action_tier, a command_field — is this table's
// other valid shape (alongside a fixed tier), and ALTER COLUMN action_tier
// DROP NOT NULL must let it be written and read back intact against a real
// Postgres, not merely accepted by sqlmock's faked driver (which cannot
// prove a schema change actually took effect — the same limitation
// TestIntegration_ToolCatalog_ServingRoleCannotWrite's own doc comment
// notes for resource_field/command_field's nullability).
func TestIntegration_ToolCatalog_NullTierRoundTrips(t *testing.T) {
	const tenant = "tenant-tool-catalog-null-tier-roundtrip-integration"
	commandField := "command"

	seedToolCatalogEntry(t, tenant, "Bash", nil, "execute", nil, &commandField)
	// This row must not outlive the test: unlike
	// TestIntegration_ToolCatalog_ServingRoleCannotWrite's seeded row (a
	// fixed, non-NULL tier), a NULL action_tier is the one value
	// migrations/000014's own down migration cannot coexist with (ALTER
	// COLUMN action_tier SET NOT NULL fails while any row anywhere in the
	// table is still NULL — a table-wide constraint, not a per-tenant one).
	// TestEndToEnd's chain_verifies_across_the_migration_boundary subtest
	// (store_integration_test.go) walks every migration down and back up
	// against this same shared database later in the same run, so this
	// cleanup runs regardless of pass or fail, the same "always" guarantee
	// t.Cleanup gives store_test.go's own db.Close().
	//
	// A bare testDB.ExecContext DELETE, with no app.tenant_id set first,
	// would silently delete nothing: tool_catalog is FORCE ROW LEVEL
	// SECURITY (migrations/000013_tool_catalog), which applies RLS even to
	// the table owner, so an unscoped session's current_tenant() is unset
	// and `tenant_id = current_tenant()` matches no row — no error, just a
	// no-op, exactly the silent-not-actually-cleaned-up failure this
	// comment exists to prevent a future edit from reintroducing. set_config
	// first, the same way every write in this file already does.
	t.Cleanup(func() {
		tx, err := testDB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Errorf("cleanup: begin tx: %v", err)
			return
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(context.Background(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
			t.Errorf("cleanup: set_config app.tenant_id: %v", err)
			return
		}
		if _, err := tx.ExecContext(context.Background(), `DELETE FROM tool_catalog WHERE tenant_id = $1`, tenant); err != nil {
			t.Errorf("cleanup: delete tool_catalog rows for tenant %s: %v", tenant, err)
			return
		}
		if err := tx.Commit(); err != nil {
			t.Errorf("cleanup: commit: %v", err)
		}
	})

	got, err := store.New(testDB, tenant).LoadToolCatalog(t.Context())
	if err != nil {
		t.Fatalf("LoadToolCatalog() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadToolCatalog() returned %d entries, want 1", len(got))
	}
	if got[0].ToolName != "Bash" || got[0].Verb != "execute" {
		t.Fatalf("LoadToolCatalog() = %+v, want the seeded Bash row", got[0])
	}
	if got[0].ActionTier != nil {
		t.Fatalf("ActionTier = %v, want nil (NULL action_tier round-tripped through a real Postgres)", got[0].ActionTier)
	}
	if got[0].CommandField == nil || *got[0].CommandField != "command" {
		t.Fatalf("CommandField = %v, want %q", got[0].CommandField, "command")
	}
}

// TestIntegration_ToolCatalog_NullTierRequiresCommandField proves
// migrations/000014_tool_catalog_nullable_tier's CHECK constraint —
// tool_catalog_tier_or_command_field — makes a NULL action_tier with no
// command_field unrepresentable at the database, not merely rejected by
// application code a future caller could bypass. A NULL tier with no
// command_field says "classify something" without saying what field to
// read: it matches neither of this table's two valid shapes (a fixed tier,
// or "extract and classify command_field"), so the database itself must
// refuse to store it — the same "make the bad state unrepresentable, not
// merely handled" discipline 000013's own UNIQUE (tenant_id, tool_name)
// already gets from this file's TestIntegration_ToolCatalog_ServingRoleCannotWrite.
//
// Uses testDB (not servingDB): a CHECK constraint applies to every role
// alike, ownership included, unlike a GRANT — this test is not about who
// is permitted to write, only about what value is accepted once they do,
// the same reasoning TestIntegration_Approvals_StatusCheckConstraintRejectsInvalidValue
// (store_integration_test.go) gives for its own identical choice. The
// transaction is deliberately never committed, only ever rolled back: the
// INSERT is expected to fail, and Postgres aborts the whole transaction on
// a constraint violation.
func TestIntegration_ToolCatalog_NullTierRequiresCommandField(t *testing.T) {
	const tenant = "tenant-tool-catalog-null-tier-check-integration"

	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}

	_, insertErr := tx.ExecContext(t.Context(), insertToolCatalogQuery,
		tenant, "Bash", nil, "execute", nil, nil, // NULL action_tier, NULL command_field
	)
	if insertErr == nil {
		t.Fatal("INSERT with NULL action_tier and NULL command_field succeeded, want a check_violation — " +
			"migrations/000014_tool_catalog_nullable_tier's CHECK constraint must reject it")
	}
	var pqErr *pq.Error
	if !errors.As(insertErr, &pqErr) || pqErr.Code != sqlStateCheckViolation {
		t.Fatalf("INSERT error = %v, want SQLSTATE %s (check_violation)", insertErr, sqlStateCheckViolation)
	}
	t.Logf("INSERT with NULL action_tier and NULL command_field correctly rejected: %v", insertErr)
}
