//go:build integration

// Task 2's real-Postgres proofs for resource_label_rules
// (migrations/000019_resource_label_rules). A separate file from
// store_integration_test.go, the same choice catalog_integration_test.go and
// escalation_integration_test.go already make and justify: every package-level
// var and helper used here (testDB, servingDB, papDB, withTenantTx,
// withPAPTenantTx, assertWriteDenied, readTenantEpoch, assertEpochBumped) is
// already shared across every *_test.go file in this one package without an
// import, so there is no reason to grow the existing monolith.
//
// Everything below needs a live database by necessity, not by preference. RLS,
// a UNIQUE constraint, a GRANT's absence, a CHECK constraint, and a trigger are
// all schema behaviour; sqlmock fakes the driver and can prove none of it.
// resource_label_test.go proves the Go call shapes and holds the write-time
// validation; this file proves what the schema itself does and does not do.
package store_test

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/internal/store"
	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// beginServingTenantTx begins a transaction on servingDB with app.tenant_id
// set and returns it uncommitted, for a caller that expects its own write to
// FAIL and needs to inspect the error before rolling back. This is
// beginPAPTenantTx's (pap_role_integration_test.go) counterpart for the serving
// identity — that file factored the shape out of the copies
// catalog_integration_test.go and store_integration_test.go had inlined; this
// is the same factoring, one connection over.
func beginServingTenantTx(t *testing.T, tenant string) *sql.Tx {
	t.Helper()
	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on serving connection: %v", err)
	}
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
	}
	return tx
}

// insertResourceLabelRuleRawQuery is store's own (unexported) insert
// reproduced here, for the probes below that must reach the table WITHOUT
// going through CreateResourceLabelRule's Go-side validation — the only way to
// ask what the schema alone accepts. It names id nowhere: the schema's
// uuid_generate_v4() DEFAULT supplies it, exactly as insertToolCatalogQuery's
// own raw counterpart in catalog_integration_test.go does.
const insertResourceLabelRuleRawQuery = `INSERT INTO resource_label_rules (tenant_id, prefix, hierarchy, level)
	VALUES ($1,$2,$3,$4)`

// createRule writes one rule through the real admin-plane identity
// (stratium_pap_login, papDB) and the real Go write path, failing the test if
// it does not land. A successful write here is itself proof of three things at
// once: that stratium_pap's GRANT covers this table, that RLS's WITH CHECK
// accepts a correctly tenant-scoped writer, and that the audit append N4
// requires (which shares the transaction) succeeds for this role too.
func createRule(t *testing.T, tenant string, rule classification.Rule) models.ResourceLabelRule {
	t.Helper()
	created, err := store.New(papDB, tenant).CreateResourceLabelRule(
		t.Context(), labelRule(rule), "operator-integration", time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("CreateResourceLabelRule(%+v) for %s error = %v, want nil", rule, tenant, err)
	}
	if created.ID == uuid.Nil {
		t.Fatalf("CreateResourceLabelRule(%+v) for %s returned the zero UUID — the id is the handle the "+
			"update-by-id and delete-by-id routes name", rule, tenant)
	}
	return created
}

// labelRule lifts a classification.Rule fixture into the
// models.ResourceLabelRule shape the PAP-facing write methods take. The
// fixtures in this file stay classification.Rule because that is what the
// decision path reads back through LoadResourceLabelRules, and asserting a
// round trip against the type the DECISION sees is the point of most of them;
// see models.ResourceLabelRule's own doc comment for why the two shapes are
// separate at all.
func labelRule(rule classification.Rule) models.ResourceLabelRule {
	return models.ResourceLabelRule{Prefix: rule.Prefix, Hierarchy: rule.Hierarchy, Level: rule.Level}
}

// loadRules reads a tenant's rules through the real SERVING identity
// (stratium_app, servingDB) — the role that actually performs this read on the
// decision path. testDB would also work and would also be RLS-scoped (FORCE
// ROW LEVEL SECURITY applies to the owner too), but it would not additionally
// prove the PDP's own SELECT grant exists.
func loadRules(t *testing.T, tenant string) []classification.Rule {
	t.Helper()
	rules, err := store.New(servingDB, tenant).LoadResourceLabelRules(t.Context())
	if err != nil {
		t.Fatalf("LoadResourceLabelRules() for %s error = %v, want nil", tenant, err)
	}
	return rules
}

func assertRules(t *testing.T, tenant string, got, want []classification.Rule) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("LoadResourceLabelRules() for %s returned %d rules, want %d: %+v", tenant, len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s rule[%d] = %+v, want %+v", tenant, i, got[i], want[i])
		}
	}
}

// TestIntegration_ResourceLabelRules_RoundTrip writes a tenant's whole rule set
// through the PAP role and reads it back through the PDP role, field for field,
// against a real Postgres.
//
// The fixture is built so a mixup cannot pass. No value is repeated across any
// of the four rows' twelve fields; both hierarchies appear; casing varies
// (`NATO` written, `NATO` read back) so a silent normalisation on either the
// write or the read path shows up as a wrong value rather than as nothing; and
// the empty-prefix catch-all is present, which is both R7's construct and the
// row a reflexive "required field" guard would have refused. The expected
// slice is spelled out in ORDER BY prefix order — '' sorts first — so the
// query's own ordering is asserted here too, against a real planner rather
// than against sqlmock's replayed rows.
func TestIntegration_ResourceLabelRules_RoundTrip(t *testing.T) {
	const tenant = "tenant-resource-label-roundtrip-integration"

	written := []classification.Rule{
		{Prefix: "/reports/q3", Hierarchy: "NATO", Level: "restricted"},
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/data/public/", Hierarchy: "commercial", Level: "INTERNAL"},
	}
	for _, r := range written {
		createRule(t, tenant, r)
	}

	// ORDER BY prefix: "" < "/data/" < "/data/public/" < "/reports/q3".
	assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{
		{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/data/public/", Hierarchy: "commercial", Level: "INTERNAL"},
		{Prefix: "/reports/q3", Hierarchy: "NATO", Level: "restricted"},
	})
}

// TestIntegration_ResourceLabelRules_DuplicatePrefixCollides is the corrected
// UNIQUE (tenant_id, prefix) key's own proof, and the second subtest is the
// whole point of the correction.
//
// The plan originally called for UNIQUE (tenant_id, prefix, hierarchy). Under
// that key the "different hierarchy" case below would have been ACCEPTED,
// leaving the tenant with one prefix carrying two answers — a pair no resource
// can satisfy, because CheckCap reads exactly one classification and one
// hierarchy per resource. pkg/classification.Resolve correctly refuses to
// resolve it, so the only symptom would be total silent denial under that
// prefix with nothing naming the cause. A test that collided only two
// IDENTICAL rows would pass under the old, wrong key and prove nothing about
// the correction, so both cases are here and the different-hierarchy one is
// the load-bearing half.
//
// Each subtest re-reads afterwards: a refusal that had nonetheless overwritten
// or removed the first rule would be a different, quieter defect than the one
// being tested for, and errors.Is alone cannot see it.
func TestIntegration_ResourceLabelRules_DuplicatePrefixCollides(t *testing.T) {
	t.Run("different hierarchy -- the case the corrected key exists to forbid", func(t *testing.T) {
		const tenant = "tenant-resource-label-collide-hierarchy-integration"
		first := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
		createRule(t, tenant, first)

		second := classification.Rule{Prefix: "/data/", Hierarchy: "commercial", Level: "PUBLIC"}
		_, err := store.New(papDB, tenant).CreateResourceLabelRule(t.Context(), labelRule(second), "operator-integration", time.Now().UTC())
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want ErrAlreadyExists — UNIQUE (tenant_id, prefix) "+
				"must refuse a second rule on the same prefix even in another hierarchy, because a resource "+
				"carries exactly one hierarchy and the pair is one no resource could ever satisfy", second, err)
		}

		assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{first})
	})

	t.Run("same hierarchy, same level", func(t *testing.T) {
		const tenant = "tenant-resource-label-collide-identical-integration"
		first := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
		createRule(t, tenant, first)

		_, err := store.New(papDB, tenant).CreateResourceLabelRule(t.Context(), labelRule(first), "operator-integration", time.Now().UTC())
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want ErrAlreadyExists", first, err)
		}

		assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{first})
	})

	t.Run("the catch-all is unique too", func(t *testing.T) {
		// The empty prefix is a legal value, so it is also a value the key must
		// hold to one answer. Without this, an implementation that special-cased
		// '' anywhere on the write path would pass every other case here.
		const tenant = "tenant-resource-label-collide-catchall-integration"
		first := classification.Rule{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"}
		createRule(t, tenant, first)

		second := classification.Rule{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"}
		_, err := store.New(papDB, tenant).CreateResourceLabelRule(t.Context(), labelRule(second), "operator-integration", time.Now().UTC())
		if !errors.Is(err, store.ErrAlreadyExists) {
			t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want ErrAlreadyExists for a second catch-all", second, err)
		}

		assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{first})
	})
}

// TestIntegration_ResourceLabelRules_SamePrefixInTwoTenantsIsScopedByRLS is
// both halves of one property: the UNIQUE key is per-tenant, and RLS — not any
// WHERE clause in Go — is what keeps one tenant's rules out of the other's
// read.
//
// BOTH TENANTS CARRY THE SAME PREFIX, deliberately. A two-tenant test where
// each tenant used a different prefix could not distinguish "RLS scoped the
// read" from "the rows never overlapped in the first place": every assertion
// would pass against a store with no tenant boundary at all, as long as the
// fixtures happened not to collide. Here the shared prefix carries a DIFFERENT
// hierarchy and a DIFFERENT level in each tenant, so a boundary failure is
// visible three ways — a wrong row count, a foreign prefix, and a foreign
// label on the prefix both tenants share.
//
// The write itself is the other half: tenant B's rule on the same prefix must
// be ACCEPTED, which is what proves the constraint is (tenant_id, prefix) and
// not prefix alone. A key on prefix alone would let one tenant deny another's
// writes by guessing at its paths.
func TestIntegration_ResourceLabelRules_SamePrefixInTwoTenantsIsScopedByRLS(t *testing.T) {
	const tenantA = "tenant-resource-label-rls-a-integration"
	const tenantB = "tenant-resource-label-rls-b-integration"

	sharedInA := classification.Rule{Prefix: "/shared/", Hierarchy: "nato", Level: "TOP-SECRET"}
	onlyInA := classification.Rule{Prefix: "/a-only/", Hierarchy: "nato", Level: "CONFIDENTIAL"}
	sharedInB := classification.Rule{Prefix: "/shared/", Hierarchy: "commercial", Level: "PUBLIC"}
	onlyInB := classification.Rule{Prefix: "/b-only/", Hierarchy: "commercial", Level: "HIGHLY-CONFIDENTIAL"}

	createRule(t, tenantA, sharedInA)
	createRule(t, tenantA, onlyInA)
	// Not a helper call by accident: this write is the assertion that the same
	// prefix in a second tenant does NOT collide. createRule fatals on error,
	// so a per-prefix key would fail the test right here.
	createRule(t, tenantB, sharedInB)
	createRule(t, tenantB, onlyInB)

	// ORDER BY prefix: "/a-only/" < "/shared/", "/b-only/" < "/shared/".
	assertRules(t, tenantA, loadRules(t, tenantA), []classification.Rule{onlyInA, sharedInA})
	assertRules(t, tenantB, loadRules(t, tenantB), []classification.Rule{onlyInB, sharedInB})
}

// TestIntegration_ResourceLabelRules_LevelNotInItsHierarchyIsRefused is the
// write-time validation the brief requires, proven end to end: refused, and
// nothing persisted.
//
// The first fixture is the sharp one. PUBLIC is a REAL level — of `commercial`
// — so a check that only asked "is this string a level somewhere?" would
// accept it under `nato`. Only a check that ranks the level WITHIN its
// hierarchy refuses it, which is what pkg/classification.Index does.
func TestIntegration_ResourceLabelRules_LevelNotInItsHierarchyIsRefused(t *testing.T) {
	const tenant = "tenant-resource-label-invalid-level-integration"

	for _, bad := range []classification.Rule{
		{Prefix: "/data/", Hierarchy: "nato", Level: "PUBLIC"},
		{Prefix: "/data/x/", Hierarchy: "natoo", Level: "UNCLASSIFIED"},
	} {
		_, err := store.New(papDB, tenant).CreateResourceLabelRule(t.Context(), labelRule(bad), "operator-integration", time.Now().UTC())
		if !errors.Is(err, store.ErrInvalidRequest) {
			t.Fatalf("CreateResourceLabelRule(%+v) error = %v, want ErrInvalidRequest", bad, err)
		}
	}

	if got := loadRules(t, tenant); len(got) != 0 {
		t.Fatalf("LoadResourceLabelRules() = %+v, want empty — a refused rule must not have been persisted", got)
	}
}

// TestIntegration_ResourceLabelRules_SchemaDoesNotEnforceHierarchyValidity
// pins the LIMIT of the check above, rather than leaving the limit as a claim
// in a comment. R9 says write-time validation is "a better error message, not
// the enforcement," and this is what that means concretely: the same
// unrankable row CreateResourceLabelRule refuses is accepted by Postgres when
// written directly, and comes back out of the read path unchanged.
//
// This test exists so nothing downstream may assume an unrankable hierarchy is
// impossible. A stale read, an in-flight migration, and a direct psql write all
// produce exactly this row; the enforcement — a label the system cannot rank
// never reaching a permissive branch — is CheckCap's, which is Task 3's to
// close. If this test ever starts failing because a CHECK constraint was added,
// read migrations/000019's own comment on why one is not there before
// "fixing" it.
//
// The STRUCTURAL floor the schema does carry is asserted in the same breath: an
// empty hierarchy or an empty level is refused by the CHECK constraint, because
// NOT NULL alone is satisfied by ''. That is the half of validity expressible in
// SQL without duplicating pkg/classification.Levels.
func TestIntegration_ResourceLabelRules_SchemaDoesNotEnforceHierarchyValidity(t *testing.T) {
	const tenant = "tenant-resource-label-schema-floor-integration"

	unrankable := classification.Rule{Prefix: "/data/x/", Hierarchy: "natoo", Level: "UNCLASSIFIED"}
	if _, err := store.New(papDB, tenant).CreateResourceLabelRule(
		t.Context(), labelRule(unrankable), "operator-integration", time.Now().UTC(),
	); !errors.Is(err, store.ErrInvalidRequest) {
		t.Fatalf("fixture is not actually refusable through the Go write path: error = %v", err)
	}

	// Committed, not rolled back: the point is not merely that Postgres accepts
	// the statement but that the row then EXISTS and the read path hands it
	// straight to a caller. withPAPTenantTx fatals if either the INSERT or the
	// commit fails.
	withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertResourceLabelRuleRawQuery,
			tenant, unrankable.Prefix, unrankable.Hierarchy, unrankable.Level); err != nil {
			t.Fatalf("raw INSERT of an unrankable hierarchy error = %v, want nil — the schema deliberately does "+
				"not enforce hierarchy validity, and a test asserting it did would be asserting a guarantee "+
				"nothing downstream is entitled to rely on", err)
		}
	})
	assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{unrankable})

	// The empty-hierarchy and empty-level floors. Each probe gets its OWN
	// transaction: a failed statement aborts the whole transaction in Postgres,
	// so a second probe sharing one would come back as 25P02 (in_failed_sql_
	// transaction) and could never observe the CHECK it is actually about.
	for _, bad := range []classification.Rule{
		{Prefix: "/empty-hierarchy/", Hierarchy: "", Level: "SECRET"},
		{Prefix: "/empty-level/", Hierarchy: "nato", Level: ""},
	} {
		tx := beginPAPTenantTx(t, tenant)
		_, err := tx.ExecContext(t.Context(), insertResourceLabelRuleRawQuery,
			tenant, bad.Prefix, bad.Hierarchy, bad.Level)
		_ = tx.Rollback()

		if err == nil {
			t.Fatalf("raw INSERT of %+v succeeded, want the resource_label_rules_hierarchy_level_present "+
				"CHECK to refuse it — NOT NULL alone is satisfied by an empty string", bad)
		}
		var pqErr *pq.Error
		if !errors.As(err, &pqErr) || pqErr.Code != sqlStateCheckViolation {
			t.Fatalf("raw INSERT of %+v error = %v, want SQLSTATE %s (check_violation)", bad, err, sqlStateCheckViolation)
		}
	}
}

// TestIntegration_ResourceLabelRules_ServingRoleCanReadAndCannotWrite is
// T1/T6/E7's proof for this table, in the shape
// TestIntegration_ToolCatalog_ServingRoleCannotWrite established: the PDP's own
// identity can read the rules it needs on the decision path, and genuinely
// cannot write them, in any of the three ways SQL can write a row.
//
// The SELECT comes first and is not a formality. Without it, the three write
// probes below would be indistinguishable from "nothing works for this role" —
// a connection with no privileges at all would pass them exactly as well.
//
// All three verbs, not one: a passing UPDATE-only probe would say nothing about
// whether INSERT or DELETE had been left grantable, and unlike approvals (whose
// serving role legitimately keeps INSERT) this table has no legitimate PDP
// writer of any kind. Each verb is its own subtest so that a future widening of
// exactly one grant fails only that subtest rather than being masked by the
// first failure.
//
// Every probe is scoped by RLS via app.tenant_id, never a WHERE tenant_id
// clause, matching every query in the package under test, and none is ever
// committed: each is expected to fail outright, so there is nothing any of
// these transactions should persist.
func TestIntegration_ResourceLabelRules_ServingRoleCanReadAndCannotWrite(t *testing.T) {
	const tenant = "tenant-resource-label-serving-grant-integration"
	const otherTenant = "tenant-resource-label-serving-grant-other-integration"
	seeded := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	createRule(t, tenant, seeded)

	// A row belonging to a SECOND tenant, seeded inside this test rather than
	// inherited from whatever else the suite happens to have written. It is what
	// makes the owner-read at the end of this test mean anything: see that
	// assertion's own comment. Measured, not assumed — dropping FORCE from the
	// migration left this test PASSING when run alone via -run, and killed it
	// only when twelve other tenants' rows from earlier tests in this file
	// happened to be present. A proof that depends on sibling tests having run
	// first is not a proof.
	createRule(t, otherTenant, classification.Rule{Prefix: "/other/", Hierarchy: "commercial", Level: "PUBLIC"})

	assertRules(t, tenant, loadRules(t, tenant), []classification.Rule{seeded})

	t.Run("INSERT", func(t *testing.T) {
		tx := beginServingTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		_, err := tx.ExecContext(t.Context(), insertResourceLabelRuleRawQuery,
			tenant, "/other/", "commercial", "PUBLIC")
		assertWriteDenied(t, "INSERT resource_label_rules (stratium_app)",
			"T1/T6: the PDP must never be able to write the labels it reads — a PDP that could relabel a "+
				"capped resource down to PUBLIC could allow itself anything (spec defect D1)", err)
	})

	t.Run("UPDATE", func(t *testing.T) {
		tx := beginServingTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		_, err := tx.ExecContext(t.Context(),
			`UPDATE resource_label_rules SET level = $1 WHERE prefix = $2`, "UNCLASSIFIED", seeded.Prefix)
		assertWriteDenied(t, "UPDATE resource_label_rules (stratium_app)",
			"T1/T6: lowering an existing label is the same escalation as writing a new one", err)
	})

	t.Run("DELETE", func(t *testing.T) {
		tx := beginServingTenantTx(t, tenant)
		defer func() { _ = tx.Rollback() }()
		_, err := tx.ExecContext(t.Context(),
			`DELETE FROM resource_label_rules WHERE prefix = $1`, seeded.Prefix)
		assertWriteDenied(t, "DELETE resource_label_rules (stratium_app)",
			"T1/T6: removing a label unlabels the subtree, which is a configuration change like any other", err)
	})

	// Two properties in one assertion, both of which need the OWNER connection.
	//
	// Belt-and-suspenders on top of the three permission errors above: testDB
	// owns the table, so its access is unaffected by any GRANT, and it can
	// therefore confirm the row genuinely never changed rather than only that
	// three statements returned errors.
	//
	// And FORCE ROW LEVEL SECURITY, which nothing else here can prove. Without
	// FORCE, RLS applies to every role EXCEPT the table's owner — ENABLE and the
	// tenant_isolation policy would both still be present and every
	// tenant-scoped read and write in this file would behave identically, since
	// stratium_app and stratium_pap are not owners. This is the only read in the
	// package that goes through the owner, so the exact-slice assertion here is
	// the only thing that can notice: with FORCE dropped, testDB sees every
	// tenant's rules, including otherTenant's, and the count check fails.
	assertRules(t, tenant, storeRulesViaOwner(t, tenant), []classification.Rule{seeded})
}

// storeRulesViaOwner reads through testDB (stratium_migrate, the table owner)
// rather than the serving role — used only where the point is to observe the
// table's true contents independently of whatever grants the role under test
// holds, and, because the owner is exactly the role FORCE ROW LEVEL SECURITY
// exists to bind, to observe that FORCE is present at all. Its one caller
// explains both.
func storeRulesViaOwner(t *testing.T, tenant string) []classification.Rule {
	t.Helper()
	rules, err := store.New(testDB, tenant).LoadResourceLabelRules(t.Context())
	if err != nil {
		t.Fatalf("LoadResourceLabelRules() via testDB for %s error = %v", tenant, err)
	}
	return rules
}

// TestIntegration_ResourceLabelRules_EpochBumpsOnEveryWrite answers the brief's
// "check whether the Phase 12 trigger covers this table and say so" with a
// measurement rather than a reading of migration text.
//
// It does NOT: migrations/000015_tenant_epoch_trigger names policies, agents,
// tool_catalog, tier_overrides and delegations, and could not have named a
// table created four migrations later. migrations/000019 therefore attaches
// 000015's own shared bump_tenant_epoch() function to this table itself, and
// this test is what proves that attachment real.
//
// All three verbs, because 000019 claims all three: an UPDATE that corrects a
// level and a DELETE that removes a rule change what a cached decision would
// evaluate to exactly as much as the INSERT that added it. A labelling change
// that did not invalidate a cached decision would be a stale authorization
// decision — which is the entire purpose of the epoch (V1).
func TestIntegration_ResourceLabelRules_EpochBumpsOnEveryWrite(t *testing.T) {
	const tenant = "tenant-resource-label-epoch-integration"
	rule := classification.Rule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}

	before, _ := readTenantEpoch(t, tenant)

	createRule(t, tenant, rule)
	afterInsert := assertEpochBumped(t, tenant, before)

	withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(),
			`UPDATE resource_label_rules SET level = $1 WHERE prefix = $2`, "TOP-SECRET", rule.Prefix)
		if err != nil {
			t.Fatalf("UPDATE resource_label_rules as stratium_pap error = %v, want nil", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("UPDATE affected %d rows (err=%v), want 1 — RLS must scope it to this tenant's own row", n, err)
		}
	})
	afterUpdate := assertEpochBumped(t, tenant, afterInsert)

	withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(),
			`DELETE FROM resource_label_rules WHERE prefix = $1`, rule.Prefix)
		if err != nil {
			t.Fatalf("DELETE resource_label_rules as stratium_pap error = %v, want nil", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("DELETE affected %d rows (err=%v), want 1", n, err)
		}
	})
	assertEpochBumped(t, tenant, afterUpdate)

	if got := loadRules(t, tenant); len(got) != 0 {
		t.Fatalf("LoadResourceLabelRules() = %+v, want empty after the DELETE", got)
	}
}
