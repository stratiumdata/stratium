package store

import (
	"context"
	"database/sql"
	"fmt"

	"stratium/pkg/models"
)

// ToolCatalogEntry is defined in pkg/models, not here: see that file's own
// doc comment for why Task 2 moved it out of this package once internal/authz
// needed to resolve tiers and extract fields from a whole catalog, not just
// receive rows from this package's own loader.

// loadToolCatalogQuery loads every tool_catalog row RLS scopes the
// transaction to. id and tenant_id are both real columns
// (migrations/000013_tool_catalog) but neither is selected: id has no
// reader yet — this is the first load the table gets, and the table has no
// update-by-id or delete-by-id path for the PDP to ever need one (see the
// migration's own GRANT comment) — and tenant_id is redundant with the
// Store this method already runs through, the same reasoning
// loadAllPoliciesQuery (policy.go) applies to leaving its own tenant_id
// column unselected. Selecting either would be exactly the
// plumbed-but-never-populated field this project's house style rules out.
const loadToolCatalogQuery = `SELECT tool_name, action_tier, verb, resource_field, command_field ` +
	`FROM tool_catalog ORDER BY tool_name`

// scanToolCatalogRows scans every row of a loadToolCatalogQuery result —
// the same "map one row" / "run a query inside a transaction" split
// scanPolicyRows (policy.go) and scanAuditTail (audit.go) already keep
// separate in this package.
func scanToolCatalogRows(rows *sql.Rows) ([]models.ToolCatalogEntry, error) {
	entries := make([]models.ToolCatalogEntry, 0)
	for rows.Next() {
		var e models.ToolCatalogEntry
		var actionTier int64
		var resourceField, commandField sql.NullString

		if err := rows.Scan(&e.ToolName, &actionTier, &e.Verb, &resourceField, &commandField); err != nil {
			return nil, fmt.Errorf("scan tool catalog row: %w", err)
		}

		// Fail loudly on an out-of-range tier, the same discipline
		// scanDelegation and scanApproval already apply to their own tier
		// columns: a corrupt row must error, never silently decode as
		// ActionTierReasoning (the zero value) and read back as though the
		// tenant really did declare this tool harmless.
		tier, err := models.ParseActionTier(int(actionTier))
		if err != nil {
			return nil, fmt.Errorf("tool catalog %q action_tier: %w", e.ToolName, err)
		}
		e.ActionTier = tier

		if resourceField.Valid {
			v := resourceField.String
			e.ResourceField = &v
		}
		if commandField.Valid {
			v := commandField.String
			e.CommandField = &v
		}

		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tool catalog rows: %w", err)
	}
	return entries, nil
}

// LoadToolCatalog loads the tenant's whole tool catalog, ordered by
// tool_name — the only selected column guaranteed unique per tenant (the
// UNIQUE (tenant_id, tool_name) constraint), so ordering by it is a
// complete, deterministic order with no ties to break, the same property
// loadAllPoliciesQuery gets from ORDER BY id.
//
// A tenant with no catalog rows — every tenant, until the control plane
// populates one — is an ordinary, empty result: a non-nil, zero-length
// slice and a nil error, never an error of its own. A caller resolving tier
// (spec §4.4.2 T1) falls back to the built-in map in exactly that case, the
// same "nothing configured" fallback LoadAllPolicies' own empty result
// already supports for the policy engines — but that fallback is that
// caller's decision to make, not this function's: LoadToolCatalog reports
// what the tenant has, nothing more.
func (s *Store) LoadToolCatalog(ctx context.Context) ([]models.ToolCatalogEntry, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, loadToolCatalogQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load tool catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries, err := scanToolCatalogRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: load tool catalog: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return entries, nil
}
