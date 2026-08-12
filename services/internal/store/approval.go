package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// Approval is one row of the approvals table (migrations/000012_approvals):
// the record of a single escalated decision, from the moment CreateApproval
// creates it pending through whatever disposition the control plane later
// writes directly against the row (E7 — see that migration's own comment on
// the grants that enforce it).
type Approval struct {
	ID       uuid.UUID
	TenantID string

	AgentID          uuid.UUID
	DelegationID     uuid.UUID
	RootDelegationID uuid.UUID

	// Subject is the requesting principal on the escalated call itself
	// (authz.Principal.Subject / DecideRequest.subject) — who asked, not
	// who may approve. RootPrincipal, below, is the only identity C21
	// permits to satisfy that.
	Subject string

	// RootPrincipal is the chain's root delegation's UserID — the only
	// identity permitted to approve (spec C21). At chain depth > 0 the
	// immediate delegator is an agent, and routing approval to an agent
	// would let the chain approve itself.
	RootPrincipal string

	ToolName    string
	Action      string
	DerivedTier models.ActionTier

	// InputDigest binds this approval to one specific request. Reused
	// unchanged from the audit chain's own notion of request identity
	// (a SHA-256 digest of the raw tool input) rather than inventing a
	// second one — see migrations/000012's own comment.
	InputDigest [32]byte

	// Status is a closed vocabulary ('pending', 'approved', 'denied')
	// enforced by a CHECK constraint in the migration, deliberately not
	// re-validated here: this package never writes anything but 'pending'
	// (see CreateApproval), and never writes this column at all on any
	// other value, so there is no Go-side path that needs to reject a bad
	// one. Left as a plain string, matching this codebase's existing
	// pattern for other CHECK-constrained columns (audit_chain.decision,
	// audit_chain.denied_leg) rather than a typed enum.
	Status string

	RequestedAt time.Time
	ExpiresAt   time.Time

	ApprovedBy *string
	ApprovedAt *time.Time
}

// loadApprovalQuery reads every column of one approvals row by id.
const loadApprovalQuery = `SELECT id, tenant_id, agent_id, delegation_id, root_delegation_id, ` +
	`subject, root_principal, tool_name, action, derived_tier, input_digest, ` +
	`status, requested_at, expires_at, approved_by, approved_at ` +
	`FROM approvals WHERE id = $1`

// insertApprovalQuery creates one approvals row. id, tenant_id, and the
// lifecycle columns (status, requested_at, approved_by, approved_at) are
// deliberately absent from the column list — see CreateApproval's own doc
// comment for why each is a schema default rather than a caller-supplied
// value.
const insertApprovalQuery = `INSERT INTO approvals (
	id, tenant_id, agent_id, delegation_id, root_delegation_id,
	subject, root_principal, tool_name, action, derived_tier,
	input_digest, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`

// CreateApproval persists a as a new, pending approvals row, tenant-scoped
// via beginTenantTx exactly like every other write in this package: no
// WHERE tenant_id in this file, RLS is the only boundary.
//
// tenant_id binds to the Store's own tenantID, never a.TenantID — matching
// CreateDelegation's own treatment of d.TenantID (see the package doc's
// "never a per-call argument"). id is caller-supplied (a.ID), the same
// pattern CreateDelegation uses for d.ID: the schema's own
// DEFAULT uuid_generate_v4() exists as a safety net for a manual insert,
// not something this function relies on.
//
// status, requested_at, approved_by, and approved_at are absent from
// insertApprovalQuery's column list entirely — the same treatment
// CreateDelegation gives created_at/revoked/revoked_at (delegation.go):
// there is no legitimate caller-supplied value for any of the four. A
// freshly created approval is always 'pending' (E7 — the PDP creates
// pending records, full stop; 'approved'/'denied' only ever happen via a
// control-plane UPDATE this package never issues), always requested now
// (NOW(), the row's true creation instant, not a Go-computed timestamp that
// could disagree with it), and has no approver yet (NULL, NULL). The schema
// defaults are simply correct, not merely convenient to omit — so a's own
// Status/RequestedAt/ApprovedBy/ApprovedAt fields are never read by this
// function, whatever a caller sets them to.
func (s *Store) CreateApproval(ctx context.Context, a *Approval) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, insertApprovalQuery,
		a.ID.String(), s.tenantID, a.AgentID.String(), a.DelegationID.String(), a.RootDelegationID.String(),
		a.Subject, a.RootPrincipal, a.ToolName, a.Action, int64(a.DerivedTier),
		a.InputDigest[:], a.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("store: insert approval %s: %w", a.ID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// LoadApproval loads one approvals row by id. RLS scopes it to the tenant
// fixed at New; a row for another tenant, or no row at all, is ErrNotFound
// either way — the same indistinguishable-by-design guarantee LoadAgent and
// LoadChain give (store.go's package doc).
func (s *Store) LoadApproval(ctx context.Context, id uuid.UUID) (*Approval, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	a, err := scanApproval(tx.QueryRowContext(ctx, loadApprovalQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: approval %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("store: load approval %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return a, nil
}

// scanApproval scans one loadApprovalQuery row into an Approval.
//
// derived_tier decodes through models.ParseActionTier — the same
// fail-loudly discipline scanDelegation (store.go) applies to
// max_action_tier/escalate_at: a corrupt or out-of-range tier must error,
// never silently become ActionTierReasoning (the zero value) and read back
// as though the request really was that innocuous.
//
// approved_by/approved_at scan through nullable intermediates
// (sql.NullString / sql.NullTime) because Approval models both as pointers
// — a NULL row (every 'pending' approval, and any row not yet actioned)
// must decode to nil, not the Go zero value for a bare string/time.Time,
// the same nullable-pointer discipline scanDelegation already applies to
// parent_delegation_id/revoked_at.
func scanApproval(row *sql.Row) (*Approval, error) {
	var a Approval
	var derivedTier int64
	var inputDigest []byte
	var approvedBy sql.NullString
	var approvedAt sql.NullTime

	err := row.Scan(
		&a.ID, &a.TenantID, &a.AgentID, &a.DelegationID, &a.RootDelegationID,
		&a.Subject, &a.RootPrincipal, &a.ToolName, &a.Action, &derivedTier,
		&inputDigest, &a.Status, &a.RequestedAt, &a.ExpiresAt, &approvedBy, &approvedAt,
	)
	if err != nil {
		return nil, err // includes sql.ErrNoRows; LoadApproval distinguishes with errors.Is
	}

	tier, err := models.ParseActionTier(int(derivedTier))
	if err != nil {
		return nil, fmt.Errorf("store: approval %s derived_tier: %w", a.ID, err)
	}
	a.DerivedTier = tier

	// input_digest is NOT NULL in the schema (migrations/000012's own
	// comment explains why this table, unlike audit_chain, has no "no
	// digest" case) — a length other than 32 is a truncated or corrupt
	// digest, never a legitimately shorter one, and must fail loudly rather
	// than silently copy a partial value into a's fixed [32]byte array.
	if len(inputDigest) != 32 {
		return nil, fmt.Errorf("store: approval %s input_digest has length %d, want 32", a.ID, len(inputDigest))
	}
	copy(a.InputDigest[:], inputDigest)

	if approvedBy.Valid {
		v := approvedBy.String
		a.ApprovedBy = &v
	}
	if approvedAt.Valid {
		v := approvedAt.Time
		a.ApprovedAt = &v
	}

	return &a, nil
}
