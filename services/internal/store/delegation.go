package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"stratium/pkg/models"
)

// insertDelegationQuery creates one delegations row. created_at, revoked,
// and revoked_at are deliberately absent from the column list: a delegation
// this function creates is never pre-revoked, and created_at's schema
// default (NOW()) is the row's true creation instant — there is no
// legitimate caller-supplied value for any of the three, so the schema
// defaults (NOW(), false, NULL) are simply correct rather than merely
// convenient to omit.
//
// tenant_id binds to the Store's own tenantID (see CreateDelegation), not a
// column read from d — matching the package doc's "never a per-call
// argument."
const insertDelegationQuery = `INSERT INTO delegations (
	id, tenant_id, user_id, agent_id, approved_tools, max_action_tier,
	classification_caps, resource_constraints, purpose, expires_at,
	parent_delegation_id, root_delegation_id, depth, chain_agent_ids
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`

// ErrScopeWidens indicates a child delegation would not narrow its parent:
// models.ScopeNarrows found at least one dimension that is equal-or-wider.
// The reason string ScopeNarrows returned is wrapped in below, not
// discarded, so a caller can log or surface exactly which dimension failed.
var ErrScopeWidens = errors.New("store: child delegation does not narrow its parent")

// jsonMarshal is package-level so a test can force a marshal failure on
// demand. None of Delegation's JSONB-backed fields ([]string,
// map[string]string, []uuid.UUID) has a value that makes the real
// encoding/json.Marshal fail, so exercising "a marshal error must abort the
// insert, never fall back to an empty JSONB value" needs this seam instead
// of a naturally-failing fixture.
var jsonMarshal = json.Marshal

// CreateDelegation persists d as a new delegations row, tenant-scoped via
// beginTenantTx exactly like every other method in this package: no WHERE
// tenant_id in this file, RLS is the only boundary.
//
// If d is a child (ParentDelegationID set), the parent is loaded inside this
// same transaction and models.ScopeNarrows(parent, d) must return "" before
// any INSERT is attempted. That call is the only place this scope check may
// live — do not reimplement, inline, or partially duplicate any part of it
// here; it is the most heavily mutation-tested function in this repository,
// including the omission cases (a child that sheds a ceiling by leaving a
// map entry out rather than widening one). Validating and inserting inside
// one transaction, rather than as two separate calls, is what keeps a
// concurrent revocation of the parent from landing in the gap between the
// check and the write.
//
// root_delegation_id and depth are computed here from the freshly loaded
// parent, never trusted from d: a root points at its own id with depth 0
// (the self-referencing FK admits no other value for a brand-new row, since
// nothing else can exist yet for it to point at); a child inherits its
// parent's root and depth+1. Both are structural consequences of chain
// position, not a caller's choice, so d's own RootDelegationID/Depth fields
// are never read.
func (s *Store) CreateDelegation(ctx context.Context, d *models.Delegation) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	rootID, depth := d.ID, 0
	if d.ParentDelegationID != nil {
		parent, loadErr := scanDelegation(tx.QueryRowContext(ctx, loadDelegationQuery, d.ParentDelegationID.String()))
		if loadErr != nil {
			if errors.Is(loadErr, sql.ErrNoRows) {
				return fmt.Errorf("%w: parent delegation %s", ErrNotFound, *d.ParentDelegationID)
			}
			return fmt.Errorf("store: load parent delegation %s: %w", *d.ParentDelegationID, loadErr)
		}
		if reason := models.ScopeNarrows(parent, d); reason != "" {
			return fmt.Errorf("%w: %s", ErrScopeWidens, reason)
		}
		rootID, depth = parent.RootDelegationID, parent.Depth+1
	}

	approvedTools, err := jsonMarshal(d.ApprovedTools)
	if err != nil {
		return fmt.Errorf("store: marshal approved_tools: %w", err)
	}
	classificationCaps, err := jsonMarshal(d.ClassificationCaps)
	if err != nil {
		return fmt.Errorf("store: marshal classification_caps: %w", err)
	}
	resourceConstraints, err := jsonMarshal(d.ResourceConstraints)
	if err != nil {
		return fmt.Errorf("store: marshal resource_constraints: %w", err)
	}
	chainAgentIDs, err := jsonMarshal(d.ChainAgentIDs)
	if err != nil {
		return fmt.Errorf("store: marshal chain_agent_ids: %w", err)
	}

	_, err = tx.ExecContext(ctx, insertDelegationQuery,
		d.ID.String(), s.tenantID, d.UserID, d.AgentID.String(), approvedTools, int64(d.MaxActionTier),
		classificationCaps, resourceConstraints, d.Purpose, d.ExpiresAt,
		d.ParentDelegationID, rootID.String(), int64(depth), chainAgentIDs,
	)
	if err != nil {
		return fmt.Errorf("store: insert delegation %s: %w", d.ID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
