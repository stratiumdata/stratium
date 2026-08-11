package store

import (
	"context"
	"database/sql"
	"fmt"

	"stratium/internal/policy"
)

// loadAllPoliciesQuery loads every enabled policy for a tenant, regardless of
// language — what policy.Multi (internal/policy/multi.go) needs to discover
// which languages a tenant has authored before it knows which per-language
// groups to prepare, without asking one language at a time. No WHERE
// tenant_id clause, per the package doc: RLS is the only implementation of
// the tenant boundary. idx_policies_tenant_enabled indexes (tenant_id,
// enabled), so RLS's rewrite plus this query's own enabled = true still
// reaches that index. ORDER BY id makes the result deterministic across
// calls — an unordered load would give a compiled policy set an unstable
// identity, which makes any future cache key (see StoredPolicy.Version's own
// doc comment) meaningless and "why did this decision differ" unanswerable.
//
// policies.effect is deliberately not selected. Phase 4a Task 4 dropped it
// from StoredPolicy: no engine reads it — all four derive effect from the
// policy text — and it can actively disagree with that text (a row stored
// effect='deny' whose text says permit(...) still evaluates to ALLOW), so
// trusting this column at read time would let a PAP screen listing policies
// by policies.effect show the opposite of what the policy actually does. The
// database column itself stays: a future PAP write path may populate it. If
// one ever does, that write path must validate the value agrees with the
// policy text it is attached to before persisting, rather than this query
// trusting whatever was last written — the same discipline every engine's
// own Prepare already applies today by ignoring the column and parsing the
// text instead.
const loadAllPoliciesQuery = `SELECT id, name, language, policy_content, priority, version ` +
	`FROM policies WHERE enabled = true ORDER BY id`

// scanPolicyRows scans every row of a loadAllPoliciesQuery result into
// StoredPolicy. Kept as its own named function the same way scanDelegation
// (store.go) and scanAuditTail (audit.go) are: separating "map one row" from
// "run a query inside a transaction" reads better than interleaving them, a
// readability call this package makes for every multi-column scan regardless
// of how many callers a given query has.
func scanPolicyRows(rows *sql.Rows) ([]policy.StoredPolicy, error) {
	policies := make([]policy.StoredPolicy, 0)
	for rows.Next() {
		var p policy.StoredPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Language, &p.Text, &p.Priority, &p.Version); err != nil {
			return nil, fmt.Errorf("scan policy row: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rows: %w", err)
	}
	return policies, nil
}

// LoadAllPolicies loads the tenant's enabled policies across every language,
// ordered by id. A tenant with no policies at all is an ordinary, empty
// result, not an error: the caller gets a non-nil, zero-length slice and a
// nil error, prepares an empty policy set from it, and evaluates to zero
// verdicts — default-deny handles the rest downstream (see
// policy.PolicyEngine.Prepare's own doc comment).
//
// policies.policy_content is the policy text column; it maps to
// StoredPolicy.Text, not a same-named field.
//
// Priority is loaded but never ordered by. ORDER BY stays on id: priority is
// provenance only (spec Y7), so sorting the compiled set by it would suggest
// an evaluation order that authz.FoldVerdicts does not have, and would make
// the set's identity change whenever an operator renumbered policies without
// changing any of them.
func (s *Store) LoadAllPolicies(ctx context.Context) ([]policy.StoredPolicy, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, loadAllPoliciesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load all policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	policies, err := scanPolicyRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: load all policies: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return policies, nil
}
