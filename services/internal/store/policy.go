package store

import (
	"context"
	"database/sql"
	"fmt"

	"stratium/internal/policy"
)

// loadPoliciesQuery loads a tenant's policies for one language. Two filters
// beyond RLS's own rewrite to tenant_id = current_tenant(): language,
// because a tenant may hold policies for engines other than the one about
// to compile them, and enabled = true, because a disabled policy that still
// evaluates is a policy an operator believes they turned off. ORDER BY id
// makes the result deterministic across calls — an unordered load would
// give a compiled policy set an unstable identity, which makes any future
// cache key meaningless and "why did this decision differ" unanswerable.
//
// No WHERE tenant_id clause, per the package doc: RLS is the only
// implementation of the tenant boundary. idx_policies_tenant_enabled
// indexes (tenant_id, enabled), so RLS's rewrite plus this query's own
// enabled = true still reaches that index.
const loadPoliciesQuery = `SELECT id, name, language, policy_content, effect, priority, version ` +
	`FROM policies WHERE language = $1 AND enabled = true ORDER BY id`

// loadAllPoliciesQuery is loadPoliciesQuery's sibling: every enabled policy
// regardless of language, for policy.Multi (internal/policy/multi.go), which
// must discover which languages a tenant has authored before it knows which
// per-language groups to prepare — it cannot ask LoadPolicies one language at
// a time without already knowing the answer. Not loadPoliciesQuery called
// with an empty-string language: an empty string silently meaning
// "everything" is exactly the kind of overload that reads as a bug at 3am,
// so this is a separate query with no language predicate at all, not one
// bound to "". Same enabled = true filter, same ORDER BY id, same absence of
// a WHERE tenant_id clause — see loadPoliciesQuery's own doc comment for why.
const loadAllPoliciesQuery = `SELECT id, name, language, policy_content, effect, priority, version ` +
	`FROM policies WHERE enabled = true ORDER BY id`

// scanPolicyRows scans every row of a loadPoliciesQuery or
// loadAllPoliciesQuery result into StoredPolicy, in the shared column order
// both queries select. Extracted once so LoadPolicies and LoadAllPolicies
// cannot drift into scanning different column orders as one is edited
// without the other — the two queries' SELECT lists must stay identical for
// this to stay correct, which is exactly why they are written out next to
// each other above rather than the shared columns being assembled from a
// third constant.
func scanPolicyRows(rows *sql.Rows) ([]policy.StoredPolicy, error) {
	policies := make([]policy.StoredPolicy, 0)
	for rows.Next() {
		var p policy.StoredPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Language, &p.Text, &p.Effect, &p.Priority, &p.Version); err != nil {
			return nil, fmt.Errorf("scan policy row: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rows: %w", err)
	}
	return policies, nil
}

// LoadPolicies loads the tenant's enabled policies for language, ordered by
// id. A tenant with no policies for language is an ordinary, empty result,
// not an error: the caller gets a non-nil, zero-length slice and a nil
// error, prepares an empty policy set from it, and evaluates to zero
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
func (s *Store) LoadPolicies(ctx context.Context, language string) ([]policy.StoredPolicy, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, loadPoliciesQuery, language)
	if err != nil {
		return nil, fmt.Errorf("store: load policies (language=%q): %w", language, err)
	}
	defer func() { _ = rows.Close() }()

	policies, err := scanPolicyRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: load policies (language=%q): %w", language, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return policies, nil
}

// LoadAllPolicies loads the tenant's enabled policies across every language,
// ordered by id — the sibling LoadPolicies needs so a caller can discover
// which languages exist before asking for any one of them by name (see
// loadAllPoliciesQuery). Same empty-is-not-an-error contract as LoadPolicies:
// a tenant with no policies at all gets a non-nil, zero-length slice and a
// nil error.
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
