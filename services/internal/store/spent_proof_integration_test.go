//go:build integration

// Integration proofs for the spent-`jti` store (spec §4.7.2 K8, Phase 15
// Task 3) against a real Postgres. Four of the five properties below cannot
// be established any other way, and the fifth is only honest this way:
//
//  1. A uniqueness constraint refuses a replay. That is a claim about what
//     the database will and will not accept, so a mock assumes the premise.
//  2. The constraint is on the PAIR. A second tenant reusing the same
//     client-chosen `jti` must be unaffected — only a live constraint can
//     show which columns it actually covers.
//  3. The reaper deletes. Under FORCE ROW LEVEL SECURITY a DELETE with no
//     app.tenant_id set affects zero rows silently, so "the reaper returned
//     nil" proves nothing at all; these tests count rows before and after.
//  4. stratium_app's grants are exactly INSERT, SELECT, DELETE — a GRANT is
//     invisible to any test that does not authenticate as the granted role.
//  5. The jti length CHECK refuses an over-long value with a SQLSTATE that is
//     not a replay's.
//
// Every one of them runs on servingDB, never testDB. testDB authenticates as
// stratium_migrate, which owns these tables and therefore holds every
// privilege on them regardless of what any GRANT says — see servingDB's own
// doc comment in store_integration_test.go. Run against testDB, this whole
// file would pass with migration 000018's GRANT line deleted.
package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lib/pq"

	"stratium/internal/store"
)

// spentProofJTIs reads back every spent_proofs row visible to tenant, in a
// stable order. Through servingDB and a tenant-scoped transaction, so it is
// simultaneously the SELECT half of the grant proof and an RLS observation:
// what it returns is what the serving identity can actually see for that
// tenant, not what the table contains.
func spentProofJTIs(t *testing.T, tenant string) []string {
	t.Helper()
	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx as the serving role: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id = %s: %v", tenant, err)
	}
	rows, err := tx.QueryContext(t.Context(), `SELECT jti FROM spent_proofs ORDER BY jti`)
	if err != nil {
		t.Fatalf("SELECT spent_proofs as the serving role: %v — "+
			"migrations/000018_spent_proofs GRANTs SELECT precisely so this works", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var jti string
		if err := rows.Scan(&jti); err != nil {
			t.Fatalf("scan jti: %v", err)
		}
		out = append(out, jti)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate spent_proofs: %v", err)
	}
	return out
}

// spend is SpendProof with the fatal-on-error boilerplate folded in, for the
// fixture writes whose success is a precondition rather than the property
// under test.
func spend(t *testing.T, tenant, jti string, expiresAt time.Time) {
	t.Helper()
	if err := store.New(servingDB, tenant).SpendProof(t.Context(), jti, expiresAt); err != nil {
		t.Fatalf("SpendProof(%s, %s) error = %v, want nil", tenant, jti, err)
	}
}

// TestIntegration_SpendProof_FirstSpendSucceedsAndAReplayCollides is K8
// itself: a proof is spendable exactly once.
//
// The refusal comes from spent_proofs' primary key, not from any check in Go
// — SpendProof issues a plain INSERT and never reads the table first — which
// is the same argument this codebase makes everywhere else for a constraint
// over a check. Dropping that constraint in migration 000018 makes the second
// call return nil here.
func TestIntegration_SpendProof_FirstSpendSucceedsAndAReplayCollides(t *testing.T) {
	const tenant = "tenant-spent-proof-replay-integration"
	const jti = "spend-once-jti"
	repo := store.New(servingDB, tenant)
	expiry := time.Now().Add(time.Hour)

	if err := repo.SpendProof(t.Context(), jti, expiry); err != nil {
		t.Fatalf("first SpendProof() error = %v, want nil", err)
	}

	err := repo.SpendProof(t.Context(), jti, expiry)
	if !errors.Is(err, store.ErrProofSpent) {
		t.Fatalf("replayed SpendProof() error = %v, want store.ErrProofSpent", err)
	}

	// The failed insert must also have written nothing. A second row would
	// mean the collision came from somewhere other than the constraint.
	if got := spentProofJTIs(t, tenant); len(got) != 1 || got[0] != jti {
		t.Fatalf("spent_proofs for %s = %v, want exactly [%q]", tenant, got, jti)
	}
}

// TestIntegration_SpendProof_TheSameJTIInAnotherTenantDoesNotCollide is why
// the constraint is on (tenant_id, jti) rather than on jti alone.
//
// A `jti` is chosen by the client, so two tenants can pick the same value
// with no coordination and no wrongdoing. On a jti-only constraint the second
// tenant's honest first use collides — one tenant could deny another's
// requests by guessing or observing its identifiers, and the collision would
// disclose that a value had been spent in a tenant RLS otherwise hides
// entirely. This test is the one that notices that mutation; the replay proof
// above passes under it unchanged.
//
// The third assertion is what keeps this from being satisfied by simply
// having no constraint at all: within tenant A, the same value still
// collides.
func TestIntegration_SpendProof_TheSameJTIInAnotherTenantDoesNotCollide(t *testing.T) {
	const tenantA = "tenant-spent-proof-cross-a-integration"
	const tenantB = "tenant-spent-proof-cross-b-integration"
	const jti = "identical-jti-across-tenants"
	expiry := time.Now().Add(time.Hour)

	spend(t, tenantA, jti, expiry)

	if err := store.New(servingDB, tenantB).SpendProof(t.Context(), jti, expiry); err != nil {
		t.Fatalf("SpendProof() of the same jti in a DIFFERENT tenant error = %v, want nil — "+
			"the constraint is on (tenant_id, jti), so tenant %s spending it says nothing about tenant %s",
			err, tenantA, tenantB)
	}

	if err := store.New(servingDB, tenantA).SpendProof(t.Context(), jti, expiry); !errors.Is(err, store.ErrProofSpent) {
		t.Fatalf("replay within tenant %s error = %v, want store.ErrProofSpent — "+
			"cross-tenant reuse being allowed must not mean the pair stopped constraining anything",
			tenantA, err)
	}

	// Each tenant sees its own row and only its own: the same RLS boundary,
	// observed from both sides.
	if got := spentProofJTIs(t, tenantA); len(got) != 1 || got[0] != jti {
		t.Fatalf("spent_proofs for %s = %v, want exactly [%q]", tenantA, got, jti)
	}
	if got := spentProofJTIs(t, tenantB); len(got) != 1 || got[0] != jti {
		t.Fatalf("spent_proofs for %s = %v, want exactly [%q]", tenantB, got, jti)
	}
}

// TestIntegration_ReapSpentProofs_DeletesExpiredRowsAndSparesUnexpiredOnes is
// the proof that the reaper does something, and it is deliberately built so
// that "it ran without an error" cannot satisfy it.
//
// The trap it exists for: spent_proofs is FORCE ROW LEVEL SECURITY, so a
// DELETE issued on a connection that never set app.tenant_id matches zero
// rows — no error, no warning, RowsAffected 0. A reaper written against the
// pool instead of beginTenantTx therefore reports success forever while the
// table grows until something unrelated breaks and takes the blame. Both
// assertions here fail under that implementation: the count is 0, and the
// expired rows are still readable afterwards.
//
// The unexpired row and the other tenant's expired row are two more mutants
// in the same test. A reaper that dropped its expires_at predicate takes
// reap-live with it; a reaper that somehow reached across tenants takes the
// other tenant's row and returns 3.
func TestIntegration_ReapSpentProofs_DeletesExpiredRowsAndSparesUnexpiredOnes(t *testing.T) {
	const tenant = "tenant-spent-proof-reap-integration"
	const otherTenant = "tenant-spent-proof-reap-other-integration"
	repo := store.New(servingDB, tenant)

	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)

	spend(t, tenant, "reap-expired-1", past)
	spend(t, tenant, "reap-expired-2", past)
	spend(t, tenant, "reap-live", future)
	spend(t, otherTenant, "reap-other-expired", past)

	before := spentProofJTIs(t, tenant)
	if len(before) != 3 {
		t.Fatalf("spent_proofs for %s before the reap = %v, want 3 rows", tenant, before)
	}

	reaped, err := repo.ReapSpentProofs(t.Context())
	if err != nil {
		t.Fatalf("ReapSpentProofs() error = %v, want nil", err)
	}
	if reaped != 2 {
		t.Fatalf("ReapSpentProofs() = %d, want 2 — a reaper that returns 0 without an error is "+
			"what a DELETE looks like when RLS filtered it to nothing (see ReapSpentProofs' own doc comment)",
			reaped)
	}

	// The count is the reaper's own report; this is the independent check on
	// it, read back through a separate transaction.
	if got := spentProofJTIs(t, tenant); len(got) != 1 || got[0] != "reap-live" {
		t.Fatalf("spent_proofs for %s after the reap = %v, want exactly [reap-live]", tenant, got)
	}
	if got := spentProofJTIs(t, otherTenant); len(got) != 1 || got[0] != "reap-other-expired" {
		t.Fatalf("spent_proofs for %s after another tenant's reap = %v, want exactly "+
			"[reap-other-expired] — the sweep is scoped by RLS to the tenant that ran it", otherTenant, got)
	}
}

// TestIntegration_SpentProofs_ServingRoleGrantsAreExactlyInsertSelectDelete
// pins migration 000018's GRANT line from both directions, and then checks
// that it widened nothing else.
//
// The positive half has to come first: without it, the refusals below would
// be indistinguishable from "this role can do nothing at all" — the same
// ordering TestIntegration_ToolCatalog_ServingRoleCannotWrite and
// TestIntegration_StratiumApp_CanReadButCannotWriteTierOverrides already use.
//
// The three configuration tables are re-checked here even though each already
// has its own dedicated proof, because this is the migration that gives the
// PDP a write it did not have. The claim being defended is not "approvals is
// still read-mostly" — that is 000012's test — it is "adding INSERT and
// DELETE on replay state added exactly that and nothing adjacent", which only
// means something asserted alongside the new grant.
func TestIntegration_SpentProofs_ServingRoleGrantsAreExactlyInsertSelectDelete(t *testing.T) {
	const tenant = "tenant-spent-proof-grant-integration"
	repo := store.New(servingDB, tenant)

	// INSERT, then SELECT, then DELETE, all through the real methods on the
	// real serving identity.
	spend(t, tenant, "grant-proof-expired", time.Now().Add(-time.Hour))
	if got := spentProofJTIs(t, tenant); len(got) != 1 {
		t.Fatalf("spent_proofs for %s = %v, want 1 row", tenant, got)
	}
	reaped, err := repo.ReapSpentProofs(t.Context())
	if err != nil || reaped != 1 {
		t.Fatalf("ReapSpentProofs() = (%d, %v), want (1, nil)", reaped, err)
	}

	// UPDATE is the verb deliberately absent from the GRANT: a spent proof is
	// never un-spent or re-dated. See migration 000018's own comment.
	refusals := map[string]string{
		"UPDATE spent_proofs": `UPDATE spent_proofs SET expires_at = NOW() + INTERVAL '100 years'`,

		// E7 (§4.6.1): the PDP creates pending approvals and never dispositions
		// one, and never deletes the record of having asked.
		"UPDATE approvals": `UPDATE approvals SET status = 'approved'`,
		"DELETE approvals": `DELETE FROM approvals`,

		// T1 (§4.4.2): the catalog is control-plane configuration.
		"INSERT tool_catalog": `INSERT INTO tool_catalog (tenant_id, tool_name, verb) ` +
			`VALUES ('` + tenant + `', 'Read', 'read')`,

		// T6 (§4.4.2): an override the PDP could write is the policed
		// component rewriting its own action-tier classification.
		"INSERT tier_overrides": `INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) ` +
			`VALUES ('` + tenant + `', 'Write', 4, 0, 'pdp')`,
	}
	for label, stmt := range refusals {
		t.Run(label, func(t *testing.T) {
			// No fixture rows needed: Postgres checks table privileges before
			// it looks at a single row, so these fail on an empty table just
			// as they would on a full one.
			tx, err := servingDB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatalf("begin: %v", err)
			}
			defer func() { _ = tx.Rollback() }()
			if _, err := tx.ExecContext(t.Context(),
				`SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
				t.Fatalf("set tenant: %v", err)
			}

			_, err = tx.ExecContext(t.Context(), stmt)
			if err == nil {
				t.Fatalf("%s as the serving role succeeded, want insufficient_privilege — "+
					"the absent GRANT is the enforcement", label)
			}
			var pqErr *pq.Error
			if !errors.As(err, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
				t.Fatalf("%s error = %v, want SQLSTATE %s (insufficient_privilege)",
					label, err, sqlStatePermissionDenied)
			}
		})
	}
}

// TestIntegration_SpentProofs_HaveExactlyOneUniqueIndex is the structural
// guard behind SpendProof's 23505 → ErrProofSpent inference.
//
// That mapping is only sound while the primary key is the table's ONLY
// uniqueness constraint. A migration adding a second one — say
// UNIQUE (tenant_id, some_new_column) — would make violations of that
// constraint come back to a caller as "dpop proof already spent", and an
// operator chasing a replay storm would go hunting an attacker who does not
// exist. Both branches still deny, so this is a diagnosability defect rather
// than a security one; it fails in the safe direction, and silently, which is
// exactly the kind this project keeps deciding a comment cannot hold shut.
// TestRLSCoversEveryTable (migrations/migrations_test.go) exists for the same
// shape of drift.
//
// Asserted against the live schema, on testDB: this is an observation about
// what the migrations produced, not about what any role may do, so it wants
// the connection that can see the catalog rather than the serving identity.
// The index NAME is pinned alongside the count — replacing the primary key
// with a differently-named unique index keeps the count at 1 while making
// SpendProof's doc comment, which says "the primary key", quietly wrong.
func TestIntegration_SpentProofs_HaveExactlyOneUniqueIndex(t *testing.T) {
	rows, err := testDB.QueryContext(t.Context(),
		`SELECT idx.relname FROM pg_index i
		   JOIN pg_class tbl ON tbl.oid = i.indrelid
		   JOIN pg_class idx ON idx.oid = i.indexrelid
		  WHERE tbl.relname = 'spent_proofs' AND i.indisunique
		  ORDER BY idx.relname`)
	if err != nil {
		t.Fatalf("read unique indexes on spent_proofs: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan index name: %v", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate unique indexes: %v", err)
	}

	if len(names) != 1 || names[0] != "spent_proofs_pkey" {
		t.Fatalf("unique indexes on spent_proofs = %v, want exactly [spent_proofs_pkey] — "+
			"store.SpendProof maps ANY unique_violation on this table to ErrProofSpent, which is "+
			"only true while the primary key is the only one. Adding another means a violation of "+
			"it now reports as a replay; either narrow that mapping (inspect the constraint name "+
			"on the *pq.Error) or reconsider the new constraint", names)
	}
}

// TestIntegration_SpendProof_RefusesAnOverlongJTI covers the one thing on
// this write path that is entirely attacker-chosen. A `jti` arrives inside a
// client-supplied JWT and is stored on the decision path, so an unbounded one
// is a write-amplification lever; spent_proofs_jti_len is the bound.
//
// The two inputs differ in exactly one property — length. Same repeated
// character, same tenant, same expiry, one byte apart across the boundary —
// so the refusal cannot be attributed to anything but the CHECK. Asserting
// the SQLSTATE rather than just "an error" is the other half: a check
// violation must not reach a caller looking like a replay, or an operator
// chasing a replay storm follows a broken client instead.
func TestIntegration_SpendProof_RefusesAnOverlongJTI(t *testing.T) {
	const tenant = "tenant-spent-proof-jti-length-integration"
	repo := store.New(servingDB, tenant)
	expiry := time.Now().Add(time.Hour)

	if err := repo.SpendProof(t.Context(), strings.Repeat("j", 255), expiry); err != nil {
		t.Fatalf("SpendProof() with a 255-character jti error = %v, want nil — "+
			"the bound must accept its own limit, or the test below proves only that long strings fail", err)
	}

	err := repo.SpendProof(t.Context(), strings.Repeat("j", 256), expiry)
	if err == nil {
		t.Fatal("SpendProof() with a 256-character jti error = nil, want the CHECK to refuse it")
	}
	if errors.Is(err, store.ErrProofSpent) {
		t.Fatalf("SpendProof() error = %v, want a write failure, NOT ErrProofSpent", err)
	}
	var pqErr *pq.Error
	if !errors.As(err, &pqErr) || pqErr.Code != sqlStateCheckViolation {
		t.Fatalf("SpendProof() error = %v, want SQLSTATE %s (check_violation) from spent_proofs_jti_len",
			err, sqlStateCheckViolation)
	}
}
