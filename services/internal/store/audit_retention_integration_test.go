//go:build integration

// The schema half of conformance property C17
// (internal/authz/conformance_test.go). Its sibling is
// TestEntry_RecordsOnlyADigestOfTheInput in pkg/audit, which pins the Go
// type; this pins what the database will actually hold, because a column can
// be added by a migration without touching audit.Entry at all.
//
// Named to sort before store_integration_test.go, which is convention rather
// than necessity here: that file's proof6 irreversibly REVOKEs INSERT on
// audit_chain, and every test below only reads information_schema. It needs
// no INSERT and so is unaffected either way -- but the file ordering in this
// package has been load-bearing before, and a reader should not have to
// re-derive that this one is safe.
package store_test

import (
	"slices"
	"testing"
)

// TestIntegration_AuditChain_RetainsADigestNeverTheInput is a drift guard.
// Nothing here can fail today.
//
// C17 as originally written -- "crypto-shredding a tenant's key renders
// inputs unrecoverable while the chain still verifies" -- presumed this
// system retains decision inputs under a per-tenant key. It does not: spec
// 4.9 records input_digest, a SHA-256, and never the input. So the property
// C17 reached for is already true and more strongly than it asked, since
// there is no ciphertext to mishandle and no key whose destruction could go
// wrong.
//
// The exposure is a future migration adding an input-bearing column -- for
// dry-run replay (spec N6, still blocked for exactly this reason), or to
// debug a support ticket. Pinning the column set by name means that addition
// cannot happen without editing this list, which puts it in front of a
// reviewer alongside the reason it matters.
//
// Scope, stated honestly: this guards the AUDIT path, which is where 4.9's
// decision lives and the only place a decision's input would plausibly be
// retained. It is not a proof that no table anywhere holds an input --
// "input-shaped column" is not mechanically decidable, and a guard that
// pretended otherwise would be the kind of claim this suite exists to
// prevent.
func TestIntegration_AuditChain_RetainsADigestNeverTheInput(t *testing.T) {
	// Derived from the migrations that build this table (000003, 000006,
	// 000010), not read back from a live database -- an expectation copied
	// from the thing it checks proves nothing. Both sides are sorted in Go
	// below rather than by the query, because Postgres's collation is not
	// ASCII order ("decision" sorts before "declared_tier") and a hand-sorted
	// literal that has to match it is a second thing to get wrong. It was
	// wrong, twice, before this test caught it.
	want := []string{
		"action", "actor", "agent_id", "chain_depth", "declared_tier",
		"decision", "delegation_id", "denied_at_depth", "denied_leg",
		"derived_tier", "entry_hash", "event_type", "input_digest",
		"occurred_at", "policy_id", "policy_source", "prev_hash",
		"root_delegation_id", "reason", "seq", "tenant_id", "tool_name",
		"unevaluated_policy_ids",
	}
	slices.Sort(want)

	rows, err := testDB.QueryContext(t.Context(),
		`SELECT column_name FROM information_schema.columns
		  WHERE table_schema = 'public' AND table_name = 'audit_chain'`)
	if err != nil {
		t.Fatalf("read audit_chain's columns: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var got []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan column name: %v", err)
		}
		got = append(got, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate columns: %v", err)
	}
	slices.Sort(got)

	// A mismatch names both sides rather than just "differs": the point of
	// failing is to show WHICH column appeared.
	if len(got) != len(want) {
		t.Fatalf("audit_chain has %d columns, want %d.\n got: %v\nwant: %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("audit_chain's columns changed at index %d: got %q, want %q.\n"+
				"full got: %v\n\nIf a migration added a column that can carry a decision's "+
				"RAW INPUT rather than a digest of it, C17 stops being true and the "+
				"conformance suite must be corrected rather than this list widened.",
				i, got[i], want[i], got)
		}
	}

	// The digest column is a fixed-width hash. A migration widening it to
	// TEXT would be the shape that could hold an input.
	var dataType string
	if err := testDB.QueryRowContext(t.Context(),
		`SELECT data_type FROM information_schema.columns
		  WHERE table_schema = 'public' AND table_name = 'audit_chain'
		    AND column_name = 'input_digest'`).Scan(&dataType); err != nil {
		t.Fatalf("read input_digest's type: %v", err)
	}
	if dataType != "bytea" {
		t.Fatalf("input_digest is %q, want \"bytea\" -- a digest, not a value that could carry the input", dataType)
	}
}
