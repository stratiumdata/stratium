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
const loadPoliciesQuery = `SELECT id, name, language, policy_content, effect, version ` +
	`FROM policies WHERE language = $1 AND enabled = true ORDER BY id`

// LoadPolicies loads the tenant's enabled policies for language, ordered by
// id. A tenant with no policies for language is an ordinary, empty result,
// not an error: the caller gets a non-nil, zero-length slice and a nil
// error, prepares an empty policy set from it, and evaluates to zero
// verdicts — default-deny handles the rest downstream (see
// policy.PolicyEngine.Prepare's own doc comment).
//
// policies.policy_content is the policy text column; it maps to
// StoredPolicy.Text, not a same-named field. StoredPolicy.Priority has no
// column in this schema at all — it is left at its Go zero value, which is
// consistent with StoredPolicy's own doc comment (Priority is
// provenance-only, and nothing may sort, filter, or short-circuit
// evaluation by it): there is genuinely nothing stored under that name to
// read back, so zero is not a loss of data, just an absence of it.
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
		if err := rows.Scan(&p.ID, &p.Name, &p.Language, &p.Text, &p.Effect, &p.Version); err != nil {
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
