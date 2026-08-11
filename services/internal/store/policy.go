package store

import (
	"context"
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

	policies := make([]policy.StoredPolicy, 0)
	for rows.Next() {
		var p policy.StoredPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Language, &p.Text, &p.Effect, &p.Priority, &p.Version); err != nil {
			return nil, fmt.Errorf("store: scan policy row (language=%q): %w", language, err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate policy rows (language=%q): %w", language, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return policies, nil
}
