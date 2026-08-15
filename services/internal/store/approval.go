package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// Approval is defined in pkg/models, not here: see that file's own doc
// comment for why Task 3 moved it out of this package once internal/pdpgrpc
// needed to construct and read the full row, not just persist it.

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
func (s *Store) CreateApproval(ctx context.Context, a *models.Approval) error {
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
func (s *Store) LoadApproval(ctx context.Context, id uuid.UUID) (*models.Approval, error) {
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
// row is a rowScanner (store.go), not a *sql.Row: ListApprovals below scans
// the same sixteen columns out of a *sql.Rows, and this is the pairing that
// interface exists for — see its own doc comment.
func scanApproval(row rowScanner) (*models.Approval, error) {
	var a models.Approval
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

// --- PAP write (Task 4): E7, the approve action itself ---
//
// Everything below is the control-plane half of E7 that CreateApproval/
// LoadApproval (above, Task 3) deliberately left absent: the ONLY path by
// which approvals.status ever leaves 'pending'. migrations/000012_approvals'
// own GRANT line withholds UPDATE from stratium_app entirely — the PDP has
// no path to either 'approved' or 'denied', by construction, not by
// convention — so DecideApproval exists on this Store at all only because a
// Store constructed with stratium_pap's own connection (papDB in the
// integration suite; STRATIUM_PAP_DATABASE_URL in the real binary) is the
// one identity that GRANT actually permits it for. See migrations/000016_
// stratium_pap_role's own comment for the grant this method depends on.

// loadApprovalForUpdateQuery is loadApprovalQuery plus FOR UPDATE:
// DecideApproval reads this exact row and then writes it, inside one
// transaction, and without the row lock two concurrent decisions on the SAME
// approval could both read status = 'pending', both pass N7 and the pending
// check below, and the second write would silently overwrite the first's
// outcome instead of being refused as ErrApprovalNotPending. FOR UPDATE
// blocks the second transaction's SELECT until the first commits (or rolls
// back); by the time it proceeds, the row it sees is already 'approved' or
// 'denied', so the second decision is correctly refused rather than racing
// the first to the UPDATE.
const loadApprovalForUpdateQuery = loadApprovalQuery + ` FOR UPDATE`

// updateApprovalDecisionQuery writes exactly the three columns E7 names —
// status, approved_by, approved_at — leaving every other column (including
// requested_at, expires_at, and the six request-identity columns
// models.Approval.Verify later compares against) untouched: a decision
// disposes of a pending request, it does not redefine what was asked.
const updateApprovalDecisionQuery = `UPDATE approvals SET status = $1, approved_by = $2, approved_at = $3 WHERE id = $4`

// ErrApprovalNotPending indicates a Decide call targeted an approval whose
// status is already 'approved' or 'denied'. Without this, a second decision
// on the same row would be an ordinary overwrite — not a security hole (N7
// still gates who may issue it), but a silent, unaudited-as-a-refusal loss
// of the first disposition's own meaning, and (paired with
// loadApprovalForUpdateQuery's row lock) what makes two concurrent decisions
// on one approval resolve to "one wins, one is refused" rather than
// "whichever commits last wins."
var ErrApprovalNotPending = errors.New("store: approval is not pending")

// ErrApproverNotRootPrincipal is N7's own sentinel (spec §4.10.1): "an
// approval requires the operator's identity to equal the approval's
// root_principal. A role is necessary and never sufficient." operatorIdentity
// is compared against the row THIS TRANSACTION just loaded and locked, never
// against anything the HTTP request itself supplied claiming to be the
// approver (cmd/stratium-pap/approvals.go's decideApproval passes only
// op.ApproverIdentity, resolved from the operator's own verified token — see
// that field's own doc comment, server.go) — the same "load and compare
// against the stored value, never trust the request to name it" discipline
// this store package already holds ValidateChain-adjacent checks to
// elsewhere (e.g. CreateDelegation loading the parent fresh rather than
// trusting a caller-supplied root_delegation_id/depth).
var ErrApproverNotRootPrincipal = errors.New("store: operator is not this approval's root principal")

// eventTypeApprovalApproved and eventTypeApprovalDenied are
// audit_chain.event_type values for this table's one write operation's two
// outcomes (N4) — one constant per distinct kind of write, matching every
// other CRUD file in this package.
const (
	eventTypeApprovalApproved = "approval_approved"
	eventTypeApprovalDenied   = "approval_denied"
)

// DecideApproval sets an approval's disposition — 'approved' if approve,
// 'denied' otherwise — plus approved_by and approved_at, and audits the
// write, inside one transaction (N4). This is E7's entire write surface: the
// PDP only ever reads this table (LoadApproval) or creates a pending row
// (CreateApproval); nothing else in this codebase ever changes 'pending' to
// anything else.
//
// Order of checks matters and is deliberate: N7 (operatorIdentity must equal
// the loaded row's own RootPrincipal) is checked BEFORE the pending check,
// so an operator who is not this approval's root principal is refused
// identically whether the row is still pending or was already decided —
// ErrApproverNotRootPrincipal never leaks "was this already decided" to
// someone N7 has already ruled out, which ErrApprovalNotPending would.
//
// approved_by is written as a.RootPrincipal — the row's OWN, already-loaded
// value — not operatorIdentity: by the time that line runs the two are
// proven equal, and echoing the canonical stored value back rather than a
// second, separately-sourced copy of the "same" string is what keeps
// approved_by provably equal to root_principal by construction, not by
// coincidence of two code paths agreeing today.
//
// now sets BOTH approved_at and the audit entry's OccurredAt — the same
// single-clock-read discipline UpdateTierOverride established for a write
// with no other row-level timestamp its own audit entry could instead reuse
// via RETURNING.
func (s *Store) DecideApproval(
	ctx context.Context, id uuid.UUID, approve bool, operatorIdentity, actor string, now time.Time,
) (*models.Approval, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	a, err := scanApproval(tx.QueryRowContext(ctx, loadApprovalForUpdateQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: approval %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("store: load approval %s: %w", id, err)
	}

	if a.RootPrincipal != operatorIdentity {
		return nil, fmt.Errorf("%w: approval %s", ErrApproverNotRootPrincipal, id)
	}
	if a.Status != "pending" {
		return nil, fmt.Errorf("%w: approval %s is already %q", ErrApprovalNotPending, id, a.Status)
	}

	status, eventType, decision := "denied", eventTypeApprovalDenied, "DENY"
	if approve {
		status, eventType, decision = "approved", eventTypeApprovalApproved, "ALLOW"
	}

	if _, err := tx.ExecContext(ctx, updateApprovalDecisionQuery, status, a.RootPrincipal, now, id.String()); err != nil {
		return nil, fmt.Errorf("store: decide approval %s: %w", id, err)
	}
	a.Status = status
	approvedBy := a.RootPrincipal
	a.ApprovedBy = &approvedBy
	a.ApprovedAt = &now

	// AgentID/DelegationID/RootDelegationID/ToolName/Action/DerivedTier/
	// InputDigest are copied from the approval this decision concerns —
	// together they fully identify WHICH escalation was decided — never the
	// approval's own id: this phase's "never log... an approval id" rule
	// (task brief), honored here by construction rather than by remembering
	// not to reach for a's ID field below. Reason names the outcome, not the
	// row.
	entry := audit.Entry{
		TenantID:         s.tenantID,
		OccurredAt:       now,
		EventType:        eventType,
		Actor:            actor,
		AgentID:          &a.AgentID,
		DelegationID:     &a.DelegationID,
		RootDelegationID: &a.RootDelegationID,
		ToolName:         a.ToolName,
		Action:           a.Action,
		DerivedTier:      int16(a.DerivedTier), //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
		Decision:         decision,
		DeniedAtDepth:    noDenial,
		Reason:           "escalation " + status,
		InputDigest:      a.InputDigest,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return a, nil
}

// --- PAP read (Task 6): the list the approve/deny actions were missing ---
//
// Task 4 built POST /v1/approvals/{id}/approve and .../deny keyed by an id no
// endpoint returned, and said so in its own comment ("discovering a pending
// approval's id is Task 6's UI concern"). This is that endpoint's store half.

// listApprovalsQuery selects every approvals column loadApprovalQuery does,
// in the identical order, so both feed the same scanApproval.
//
// It returns EVERY status, not only 'pending', and this is the deliberate
// answer to the one question Task 6's brief left open. Four reasons, in
// descending weight:
//
//  1. There is no other way to reach a decided approval. Task 4 built no
//     GET /v1/approvals/{id}, and this phase adds none. A 'pending'-only
//     filter here would make every approved and denied row permanently
//     unreachable through the admin plane's API — the admin plane being the
//     only component holding credentials to read them. "What did we approve
//     last quarter, and who approved it?" would have no answer at all, which
//     is a strange property for the surface that owns the approval history.
//  2. The name is /v1/approvals — the collection — not
//     /v1/approvals/pending. Every sibling list query in this package
//     (policies, agents, tier_overrides, tool_catalog) returns its whole
//     table for the tenant, unfiltered. An endpoint named after a table that
//     silently returns a subset lies by omission: an operator who lists and
//     sees nothing concludes "no approvals," and would be wrong.
//  3. status is on the wire (models.Approval.Status, tagged as of Task 6),
//     so restricting the "pending approvals" screen to pending rows is one
//     predicate in the client — where it is visible and changeable — rather
//     than a server-side rule with no way to ask past it.
//  4. It discloses nothing new. A viewer can already GET the full text of
//     every stored policy; an approval row is a tool name, an action, a tier,
//     and a one-way digest.
//
// The cost is honest and stated: this returns the whole table, and approvals
// accumulate. That is a pagination problem, identical in kind to the one
// ListPolicies and ListAgents already have and equally unsolved for them, and
// it is not an argument for answering a different question than the one asked.
//
// ORDER BY requested_at DESC, not the ORDER BY <name> every other list query
// in this package uses: approvals have no name, and unlike the config tables
// those queries serve, this one is closer to a log — newest first is the
// order both of its readers want (an operator working a pending queue, and an
// operator investigating what happened most recently). id breaks ties, since
// requested_at carries no uniqueness constraint and two escalations recorded
// in the same microsecond must still come back in a stable order.
const listApprovalsQuery = `SELECT id, tenant_id, agent_id, delegation_id, root_delegation_id, ` +
	`subject, root_principal, tool_name, action, derived_tier, input_digest, ` +
	`status, requested_at, expires_at, approved_by, approved_at ` +
	`FROM approvals ORDER BY requested_at DESC, id`

// ListApprovals loads every approval the tenant has, newest first. A tenant
// with none is an ordinary, empty result — never an error, and never a nil
// slice (see the make below).
//
// No WHERE tenant_id, exactly as in every other method in this package: RLS,
// via beginTenantTx, is the only tenant boundary in this codebase, and a
// second, redundant predicate here would imply to the next reader that the
// predicate is what does the work.
//
// This read is not audited. N4 covers writes; no GET handler in the PAP
// audits, and an entry per list would bury the write records that chain
// exists to preserve under reads of them.
func (s *Store) ListApprovals(ctx context.Context) ([]models.Approval, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listApprovalsQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list approvals: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// make, not var: an empty list must marshal as [] and never as null — a
	// UI should not have to tell "no approvals" apart from "the field is
	// missing."
	approvals := make([]models.Approval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan approval row: %w", err)
		}
		approvals = append(approvals, *a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate approval rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return approvals, nil
}
