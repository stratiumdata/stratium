//go:build integration

// Task 1's real-Postgres proof for tool_catalog (migrations/000013_tool_catalog),
// extended by Task 4 with the PAP's own CRUD write path
// (TestIntegration_PAPCRUD_ToolCatalogRoundTrip). A separate file from
// store_integration_test.go, the same choice escalation_integration_test.go's
// own doc comment already makes and justifies at length: every package-level
// var and helper this file uses (testDB, servingDB, papDB, withTenantTx,
// sqlStatePermissionDenied, ...) is already shared across every *_test.go
// file in this one package without an import, so there is no reason to grow
// the existing monolith to add one more table's proof to it.
package store_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
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

// cleanupToolCatalogRows returns a t.Cleanup func that deletes every
// tool_catalog row for tenant. Any test in this package that can leave a
// NULL-action_tier row behind (Task 4's own CreateToolCatalogEntry/
// UpdateToolCatalogEntry, exercised in this file and in
// pap_task4_integration_test.go, not only TestIntegration_ToolCatalog_
// NullTierRoundTrips, this helper's original single caller) must register
// this: a NULL action_tier is the one value migrations/000014_tool_catalog_
// nullable_tier's own DOWN migration cannot coexist with anywhere in the
// TABLE, not merely within one tenant's rows, and TestEndToEnd's
// chain_verifies_across_the_migration_boundary subtest (store_integration_
// test.go) walks every migration down and back up against this same shared
// database later in the same run. Found live: an early version of this
// task's own TestIntegration_PAPCRUD_ToolCatalogRoundTrip left exactly this
// residue and broke that unrelated subtest, which then left the shared
// database mid-downgrade for every test that ran after it — the actual
// failure was several tests removed from its real cause.
//
// A bare testDB.ExecContext DELETE, with no app.tenant_id set first, would
// silently delete nothing: tool_catalog is FORCE ROW LEVEL SECURITY
// (migrations/000013_tool_catalog), which applies RLS even to the table
// owner, so an unscoped session's current_tenant() is unset and
// `tenant_id = current_tenant()` matches no row — no error, just a
// no-op, exactly the silent-not-actually-cleaned-up failure this helper
// exists to prevent. set_config first, the same way every write in this
// file already does.
func cleanupToolCatalogRows(t *testing.T, tenant string) func() {
	return func() {
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
	}
}

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
	// rather than a Go store method — CreateToolCatalogEntry/
	// UpdateToolCatalogEntry now exist (Task 4), but only for the PAP's own
	// write role (stratium_pap, papDB); T1 says the SERVING role (stratium_app,
	// servingDB, this test's own connection) must never gain that grant, so
	// probing it through those methods would just be a roundabout way of
	// running the identical INSERT/UPDATE this raw SQL already runs, against
	// a connection neither method is ever legitimately called with in
	// production. Each runs in
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
	// t.Cleanup gives store_test.go's own db.Close(). See
	// cleanupToolCatalogRows' own doc comment for why every OTHER test in
	// this file (and pap_task4_integration_test.go) that can leave a
	// NULL-tier row behind registers the identical cleanup.
	t.Cleanup(cleanupToolCatalogRows(t, tenant))

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

// TestIntegration_PAPCRUD_ToolCatalogRoundTrip is Task 4's own T1 proof,
// the tool_catalog instance of pap_crud_integration_test.go's own
// *RoundTrip family: create/get/list/update through the real stratium_pap
// connection (papDB), each of this table's three valid row states
// persisting intact end to end, and every write bumping tenant_epoch via
// the pre-existing trigger (migrations/000015_tenant_epoch_trigger already
// names tool_catalog; this task is the first to exercise that path through
// a real Go writer instead of raw SQL — see
// TestIntegration_ToolCatalog_ServingRoleCannotWrite's own updated comment
// on why ITS three write probes still use raw SQL regardless).
func TestIntegration_PAPCRUD_ToolCatalogRoundTrip(t *testing.T) {
	const tenant = "tenant-pap-crud-tool-catalog-integration"
	repo := store.New(papDB, tenant)
	before, _ := readTenantEpoch(t, tenant)
	// This test both creates a NULL-tier row directly (the "Bash" case) and
	// UPDATEs another one into the NULL-tier shape at the end -- either
	// alone is exactly what cleanupToolCatalogRows' own doc comment warns
	// must not outlive this test.
	t.Cleanup(cleanupToolCatalogRows(t, tenant))

	resourceField := "file_path"
	commandField := "command"
	tests := []struct {
		name string
		e    models.ToolCatalogEntry
	}{
		{"fixed tier alone", models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), Verb: "read", ResourceField: &resourceField}},
		{"NULL tier with command_field -- Bash's own shape", models.ToolCatalogEntry{ToolName: "Bash", Verb: "execute", CommandField: &commandField}},
		{"both a fixed tier and a command_field", models.ToolCatalogEntry{ToolName: "mcp__infra__run", ActionTier: tierPtr(models.ActionTierDestructive), Verb: "execute", CommandField: &commandField}},
	}

	var firstCreatedID uuid.UUID
	for i, tt := range tests {
		t.Run("create_"+tt.name, func(t *testing.T) {
			created, err := repo.CreateToolCatalogEntry(t.Context(), tt.e, "integration-operator", time.Now())
			if err != nil {
				t.Fatalf("CreateToolCatalogEntry() error = %v", err)
			}
			if created.ID == uuid.Nil {
				t.Fatal("CreateToolCatalogEntry() returned the zero UUID for id")
			}
			before = assertEpochBumped(t, tenant, before)
			if i == 0 {
				firstCreatedID = created.ID
			}

			got, err := repo.GetToolCatalogEntry(t.Context(), created.ID)
			if err != nil {
				t.Fatalf("GetToolCatalogEntry() error = %v", err)
			}
			if got.ToolName != tt.e.ToolName {
				t.Fatalf("GetToolCatalogEntry().ToolName = %q, want %q", got.ToolName, tt.e.ToolName)
			}
			if (got.ActionTier == nil) != (tt.e.ActionTier == nil) {
				t.Fatalf("ActionTier round-trip: got %v, want a %v value", got.ActionTier, tt.e.ActionTier)
			}
			if got.ActionTier != nil && *got.ActionTier != *tt.e.ActionTier {
				t.Fatalf("ActionTier = %s, want %s", *got.ActionTier, *tt.e.ActionTier)
			}
			if (got.CommandField == nil) != (tt.e.CommandField == nil) {
				t.Fatalf("CommandField round-trip: got %v, want a %v value", got.CommandField, tt.e.CommandField)
			}
		})
	}

	listed, err := repo.ListToolCatalogEntries(t.Context())
	if err != nil {
		t.Fatalf("ListToolCatalogEntries() error = %v", err)
	}
	if len(listed) != len(tests) {
		t.Fatalf("ListToolCatalogEntries() returned %d entries, want %d", len(listed), len(tests))
	}

	// Update moves the first-created entry (fixed tier alone) into the
	// NULL-tier shape -- a full-replace PUT must accept moving a row
	// between any of this table's three valid states, not just persist
	// whichever state it was first created in.
	updated, err := repo.UpdateToolCatalogEntry(t.Context(), firstCreatedID,
		models.ToolCatalogEntry{ToolName: "Read", Verb: "read", CommandField: &commandField}, "integration-operator", time.Now(), true)
	if err != nil {
		t.Fatalf("UpdateToolCatalogEntry() error = %v", err)
	}
	if updated.ActionTier != nil {
		t.Fatalf("UpdateToolCatalogEntry().ActionTier = %v, want nil after moving to the NULL-tier shape", updated.ActionTier)
	}
	assertEpochBumped(t, tenant, before)

	assertAuditTrailMatches(t, tenant, "integration-operator",
		"tool_catalog_created", "tool_catalog_created", "tool_catalog_created", "tool_catalog_updated")
}

// TestIntegration_CreateToolCatalogEntry_NeitherTierNorCommandField_LiveDefenseInDepth
// is the required mutation "let a catalog row with neither a tier nor a
// command_field through," proven the way the task brief itself frames it:
// against a REAL database, through the REAL CreateToolCatalogEntry call —
// not a unit test asserting the Go-side validateToolCatalogFields check
// alone (internal/store/catalog_test.go's own TestStore_
// CreateToolCatalogEntry_MissingTierAndCommandFieldRefusedBeforePersisting),
// which would keep passing even if the DATABASE's own CHECK constraint
// (tool_catalog_tier_or_command_field, migrations/000014_tool_catalog_
// nullable_tier) were somehow ALSO broken, so long as the Go check alone
// still caught it. This test cannot make that mistake: it asserts only the
// OUTCOME (ErrInvalidRequest, not a crash) through the full stack, so it
// passes for the same reason regardless of which of the two layers
// (validateToolCatalogFields, or isCheckViolation catching the database's
// own refusal) is the one actually doing the catching today — confirmed by
// running it with validateToolCatalogFields's own check temporarily deleted
// during this task's own mutation-testing pass: it kept passing, because
// the database CHECK constraint is what actually holds the line.
func TestIntegration_CreateToolCatalogEntry_NeitherTierNorCommandField_LiveDefenseInDepth(t *testing.T) {
	const tenant = "tenant-tool-catalog-neither-tier-nor-command-live-integration"
	repo := store.New(papDB, tenant)

	_, err := repo.CreateToolCatalogEntry(t.Context(),
		models.ToolCatalogEntry{ToolName: "mystery-tool", Verb: "run"}, // no ActionTier, no CommandField
		"integration-operator", time.Now())
	if err == nil {
		t.Fatal("CreateToolCatalogEntry() error = nil, want a refusal for a row with neither a tier nor a command_field")
	}
	if !errors.Is(err, store.ErrInvalidRequest) {
		t.Fatalf("CreateToolCatalogEntry() error = %v, want errors.Is(_, store.ErrInvalidRequest) -- "+
			"the task brief's own requirement is that this surfaces as a clean 400, never an unrecognized crash", err)
	}
}
