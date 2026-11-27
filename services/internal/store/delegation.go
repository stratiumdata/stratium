package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
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
//
// escalate_at is appended at the end rather than grouped next to
// max_action_tier, matching loadDelegationQuery's own column order in
// store.go and for the same reason: appending is the one place to add a
// column that shifts no existing positional arg below.
const insertDelegationQuery = `INSERT INTO delegations (
	id, tenant_id, user_id, agent_id, approved_tools, max_action_tier,
	classification_caps, resource_constraints, purpose, expires_at,
	parent_delegation_id, root_delegation_id, depth, chain_agent_ids, escalate_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

// ErrScopeWidens indicates a child delegation would not narrow its parent:
// permset.ScopeNarrows found at least one dimension that is equal-or-wider.
// The reason string ScopeNarrows returned is wrapped in below, not
// discarded, so a caller can log or surface exactly which dimension failed.
var ErrScopeWidens = errors.New("store: child delegation does not narrow its parent")

// ErrEscalateAtUnreachable indicates d.EscalateAt is set above d.MaxActionTier.
// DelegationLeg denies once the tier exceeds MaxActionTier before it ever
// checks EscalateAt (deny overrides escalate — see that function's own doc
// comment), so a threshold above the ceiling could never fire. Rejected here
// at write time rather than persisted as a rule with no effect: the same
// semantically-dead class Phase 4a swept out of every policy engine, one
// layer up.
var ErrEscalateAtUnreachable = errors.New("store: escalate_at exceeds max_action_tier and could never fire")

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
// same transaction and permset.ScopeNarrows(parent, d) must return "" before
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
//
// This is also the one place that rejects an EscalateAt set above
// MaxActionTier (ErrEscalateAtUnreachable) — deliberately here and not in
// pdpgrpc.CreateDelegation, even though that RPC handler does its own
// pre-policy validation of the wire request. Its RequestedScope has no
// escalate_at field at all today, so d.EscalateAt is always nil on that
// path; a check placed there would itself be unreachable — exactly the
// defect this rejection exists to prevent, one layer up. This function is
// the one place every caller of CreateDelegation funnels through regardless
// of transport, today's pdpgrpc handler and any future direct caller alike,
// so it is the only place the check can actually be exercised by everyone
// who can set the field.
func (s *Store) CreateDelegation(ctx context.Context, d *models.Delegation) error {
	// A self-contained property of d alone — no parent row, no database
	// access needed — so it is checked before opening a transaction, unlike
	// ScopeNarrows below, which needs the parent loaded first.
	if d.EscalateAt != nil && *d.EscalateAt > d.MaxActionTier {
		return fmt.Errorf("%w: escalate_at %s exceeds max_action_tier %s",
			ErrEscalateAtUnreachable, d.EscalateAt.String(), d.MaxActionTier.String())
	}

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
		if reason := permset.ScopeNarrows(parent, d); reason != "" {
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

	// d.EscalateAt (a *models.ActionTier) is passed directly, unconverted,
	// the same way d.ParentDelegationID and d.RevokedAt already are
	// elsewhere in this package: database/sql's default parameter
	// converter maps a nil pointer to SQL NULL and a non-nil one to its
	// pointee's value, so there is no separate nil-check-and-substitute
	// step to keep in sync with EscalateAt's own nil-means-never-escalate
	// contract.
	_, err = tx.ExecContext(ctx, insertDelegationQuery,
		d.ID.String(), s.tenantID, d.UserID, d.AgentID.String(), approvedTools, int64(d.MaxActionTier),
		classificationCaps, resourceConstraints, d.Purpose, d.ExpiresAt,
		d.ParentDelegationID, rootID.String(), int64(depth), chainAgentIDs, d.EscalateAt,
	)
	if err != nil {
		return fmt.Errorf("store: insert delegation %s: %w", d.ID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// --- PAP write (Task 4): V4, delegation revocation ---

// eventTypeDelegationRevoked is the audit_chain.event_type value for this
// table's one PAP write operation (N4).
const eventTypeDelegationRevoked = "delegation_revoked"

// revokeDelegationQuery sets exactly the two columns V4 names — revoked and
// revoked_at — and returns every column loadDelegationQuery selects, in the
// identical order, so its result can be handed straight to scanDelegation
// (store.go) rather than a second, parallel scan function this file would
// otherwise need to keep in sync with that one by hand. Column list
// duplicated as a literal, not shared via a Go constant, matching this
// package's own existing precedent for two queries against the same table
// with different WHERE/SET clauses (e.g. policy.go's getPolicyQuery and
// listPoliciesQuery both spell out the identical policies column list
// separately).
const revokeDelegationQuery = `UPDATE delegations SET revoked = true, revoked_at = $1 WHERE id = $2 RETURNING ` +
	`id, tenant_id, user_id, agent_id, approved_tools, max_action_tier, ` +
	`classification_caps, resource_constraints, purpose, expires_at, ` +
	`created_at, revoked, revoked_at, parent_delegation_id, ` +
	`root_delegation_id, depth, chain_agent_ids, escalate_at`

// RevokeDelegation sets revoked and revoked_at on the id row and audits the
// write, inside one transaction (N4) — V4's entire write surface. Nothing
// here implements cascade denial: DelegationLeg (internal/authz/delegation.go)
// already checks Revoked at every hop of a chain it is handed, on every
// decision, so a descendant of the row this method revokes is denied the
// next time its own chain is loaded and evaluated — this method only
// supplies the write that flag was always missing (spec §4.8.1 V4: "nothing
// SETS revoked, because setting it is a control-plane write under E7/T1, not
// a PDP one").
//
// No identity check beyond the role gate cmd/stratium-pap/server.go's
// routeTable applies (spec N7's own contrast, §4.10.1, "taking away requires
// only a role"): revocation REDUCES authority, so — unlike DecideApproval,
// which grants it — a role is sufficient here on its own. The worst outcome
// of a wrongly-scoped revocation is that something stops working, which
// fails closed; there is no equivalent worst case in the other direction for
// this method to guard against.
//
// Revoking an already-revoked delegation is not refused: RETURNING still
// finds the row regardless of its current revoked value, so a second revoke
// is accepted as a harmless, idempotent no-op that still produces its own
// audit entry — unlike DecideApproval's 'pending'-only rule, there is no
// "already happened, refuse" state for a monotonic flag with no reversal
// (this table has no un-revoke path at all).
//
// now sets BOTH revoked_at and the audit entry's OccurredAt, the same
// single-clock-read discipline DecideApproval and UpdateTierOverride already
// use.
func (s *Store) RevokeDelegation(ctx context.Context, id uuid.UUID, actor string, now time.Time) (*models.Delegation, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	d, err := scanDelegation(tx.QueryRowContext(ctx, revokeDelegationQuery, now, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: delegation %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("store: revoke delegation %s: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:         s.tenantID,
		OccurredAt:       now,
		EventType:        eventTypeDelegationRevoked,
		Actor:            actor,
		AgentID:          &d.AgentID,
		DelegationID:     &d.ID,
		RootDelegationID: &d.RootDelegationID,
		ChainDepth:       int16(d.Depth), //nolint:gosec // G115: depth is schema-checked >= 0 and bounded by maxChainWalk (64)
		Decision:         "ALLOW",
		DeniedAtDepth:    noDenial,
		Reason:           "delegation revoked",
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return d, nil
}

// --- PAP read (Task 6): the list the revoke action was missing ---
//
// Task 4 built POST /v1/delegations/{id}/revoke keyed by an id no endpoint
// returned, and said so in its own comment ("discovering which delegation to
// revoke is Task 6's UI concern"). This is that endpoint's store half.

// listDelegationsQuery selects every delegations column loadDelegationQuery
// does, in the identical order, so both feed the same scanDelegation. Column
// list spelled out as a literal rather than shared through a Go constant,
// matching revokeDelegationQuery's own precedent above.
//
// Revoked rows are included, not filtered out, for the same reason
// listApprovalsQuery includes decided approvals (see its own doc comment):
// nothing else can reach them — there is no GET /v1/delegations/{id} — and a
// revocation an operator cannot see afterward is a revocation they cannot
// confirm took effect. Delegation.Revoked and RevokedAt are both already on
// the wire, so a screen wanting only live grants filters client-side.
//
// ORDER BY created_at DESC, id: newest first, matching listApprovalsQuery's
// reasoning for a table that accumulates rather than one keyed by a name, and
// with the same id tiebreak for the same reason.
const listDelegationsQuery = `SELECT id, tenant_id, user_id, agent_id, approved_tools, max_action_tier, ` +
	`classification_caps, resource_constraints, purpose, expires_at, ` +
	`created_at, revoked, revoked_at, parent_delegation_id, ` +
	`root_delegation_id, depth, chain_agent_ids, escalate_at ` +
	`FROM delegations ` +
	`WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1::timestamptz, $2::uuid)) ` +
	`ORDER BY created_at DESC, id DESC LIMIT $3`

// listActiveRootDelegationsQuery is one principal's live sessions: the root
// delegations issued to them that are neither revoked nor expired.
const listActiveRootDelegationsQuery = `SELECT id, tenant_id, user_id, agent_id, approved_tools, max_action_tier, ` +
	`classification_caps, resource_constraints, purpose, expires_at, ` +
	`created_at, revoked, revoked_at, parent_delegation_id, ` +
	`root_delegation_id, depth, chain_agent_ids, escalate_at ` +
	`FROM delegations ` +
	`WHERE user_id = $1 AND parent_delegation_id IS NULL AND revoked = false AND expires_at > $2 ` +
	`ORDER BY created_at DESC, id DESC LIMIT $3`

// ListDelegations loads every delegation the tenant has, newest first,
// revoked and expired ones included. A tenant with none is an ordinary, empty
// result — never an error, and never a nil slice.
//
// No WHERE tenant_id: RLS via beginTenantTx is the only tenant boundary, as
// everywhere else in this package. Not audited: N4 covers writes.
func (s *Store) ListDelegations(ctx context.Context, before *ListCursor, limit int) ([]models.Delegation, *ListCursor, error) {
	limit = clampListLimit(limit)
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()

	at, id := cursorArgs(before)
	// One more than the page, to learn whether there is a next one.
	rows, err := tx.QueryContext(ctx, listDelegationsQuery, at, id, int64(limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("store: list delegations: %w", err)
	}
	delegations, err := collectDelegations(rows)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("store: commit: %w", err)
	}

	var next *ListCursor
	if len(delegations) > limit {
		delegations = delegations[:limit]
		last := delegations[limit-1]
		next = &ListCursor{At: last.CreatedAt, ID: last.ID}
	}
	return delegations, next, nil
}

// ListActiveRootDelegations returns up to limit of principal's live sessions,
// newest first, and whether there were more than that.
func (s *Store) ListActiveRootDelegations(
	ctx context.Context, principal string, now time.Time, limit int,
) (delegations []models.Delegation, more bool, err error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listActiveRootDelegationsQuery, principal, now, int64(limit+1))
	if err != nil {
		return nil, false, fmt.Errorf("store: list active root delegations: %w", err)
	}
	delegations, err = collectDelegations(rows)
	if err != nil {
		return nil, false, err
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("store: commit: %w", err)
	}
	if len(delegations) > limit {
		return delegations[:limit], true, nil
	}
	return delegations, false, nil
}

// collectDelegations scans every row of a delegation query and closes rows.
// The result is never nil, so an empty list marshals as [].
func collectDelegations(rows *sql.Rows) ([]models.Delegation, error) {
	defer func() { _ = rows.Close() }()
	delegations := make([]models.Delegation, 0)
	for rows.Next() {
		d, err := scanDelegation(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan delegation row: %w", err)
		}
		delegations = append(delegations, *d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate delegation rows: %w", err)
	}
	return delegations, nil
}

// A delegation is bound to at most one key for its whole life: bound_jkt
// (migration 000024) holds that key's RFC 7638 thumbprint, NULL until the
// first binding. It is read and written by these two methods only, and is
// deliberately not part of loadDelegationQuery: the caller that needs it
// (pdpgrpc) asks for it by name.
const delegationKeyQuery = `SELECT COALESCE(bound_jkt, '') FROM delegations WHERE id = $1`

// bindDelegationKeyQuery records $1 unless a key is already recorded, and
// returns whichever key the row holds afterwards. One statement, so two
// callers racing to bind first see the same winner.
const bindDelegationKeyQuery = `UPDATE delegations SET bound_jkt = COALESCE(bound_jkt, $1) WHERE id = $2 RETURNING bound_jkt`

// DelegationKey returns the thumbprint of the key the delegation is bound
// to, or "" if it has never been bound.
func (s *Store) DelegationKey(ctx context.Context, id uuid.UUID) (string, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var jkt string
	if err := tx.QueryRowContext(ctx, delegationKeyQuery, id.String()).Scan(&jkt); err != nil {
		return "", delegationKeyError(id, err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit: %w", err)
	}
	return jkt, nil
}

// BindDelegationKey records jkt as the delegation's key unless one is
// already recorded, and returns the key it is bound to afterwards. The
// caller compares: a different answer means another key got there first.
func (s *Store) BindDelegationKey(ctx context.Context, id uuid.UUID, jkt string) (string, error) {
	if jkt == "" {
		return "", fmt.Errorf("%w: empty key thumbprint", ErrInvalidRequest)
	}
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var bound string
	if err := tx.QueryRowContext(ctx, bindDelegationKeyQuery, jkt, id.String()).Scan(&bound); err != nil {
		return "", delegationKeyError(id, err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("store: commit: %w", err)
	}
	return bound, nil
}

func delegationKeyError(id uuid.UUID, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: delegation %s", ErrNotFound, id)
	}
	return fmt.Errorf("store: delegation %s key: %w", id, err)
}
