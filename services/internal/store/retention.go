package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/stratiumdata/stratium/pkg/audit"
)

// retention.go deletes old sessions. A session is a root delegation, the
// delegations made under it and their approvals. Nothing here touches the
// audit chain, which keeps the whole history.
//
// What may be deleted is decided twice. The queries below choose sessions
// every part of which expired before a cutoff the caller sets. The database
// (migrations/000028_session_retention) then refuses the serving role any
// delete of a delegation or approval that has not expired at all, so a
// mistake here can lose a record but cannot remove a live one.

// EventTypeSessionsReaped is the audit entry a sweep writes when it deleted
// anything.
const EventTypeSessionsReaped = "sessions_reaped"

// reaperActor is who that entry is attributed to.
const reaperActor = "stratium-pdp"

// selectDeadSessionsQuery finds roots whose whole chain is past the cutoff:
// the root, every delegation naming it as root (a child may outlive its
// parent), and every approval asked under it. Oldest first, so a sweep that
// cannot finish still makes progress.
//
// ponytail: scans the tenant's root delegations each sweep; add an index on
// (tenant_id, expires_at) WHERE parent_delegation_id IS NULL if a sweep ever
// shows up as slow.
const selectDeadSessionsQuery = `SELECT r.id FROM delegations r ` +
	`WHERE r.parent_delegation_id IS NULL AND r.expires_at < $1 ` +
	`AND NOT EXISTS (SELECT 1 FROM delegations d WHERE d.root_delegation_id = r.id AND d.expires_at >= $1) ` +
	`AND NOT EXISTS (SELECT 1 FROM approvals a WHERE a.root_delegation_id = r.id AND a.expires_at >= $1) ` +
	`ORDER BY r.expires_at LIMIT $2`

// Approvals first: they reference the delegations and nothing cascades to
// them. Then every delegation of the chain in one statement, by root, so the
// order within the chain does not matter.
const deleteSessionApprovalsQuery = `DELETE FROM approvals WHERE root_delegation_id = ANY($1::uuid[])`

const deleteSessionDelegationsQuery = `DELETE FROM delegations WHERE root_delegation_id = ANY($1::uuid[])`

// ReapExpiredSessions deletes up to batch sessions every part of which
// expired before cutoff, and returns how many sessions it deleted. Fewer than
// batch means there are no more. A sweep that deleted anything records one
// audit entry saying how much.
func (s *Store) ReapExpiredSessions(ctx context.Context, cutoff time.Time, batch int) (int, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, selectDeadSessionsQuery, cutoff, int64(batch))
	if err != nil {
		return 0, fmt.Errorf("store: find expired sessions: %w", err)
	}
	// Read to the end and closed before the deletes: one connection carries
	// one result set at a time.
	roots, err := collectIDs(rows)
	if err != nil {
		return 0, fmt.Errorf("store: find expired sessions: %w", err)
	}
	if len(roots) == 0 {
		return 0, tx.Commit()
	}

	res, err := tx.ExecContext(ctx, deleteSessionApprovalsQuery, pq.Array(roots))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions' approvals: %w", err)
	}
	approvals, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions' approvals: row count: %w", err)
	}
	res, err = tx.ExecContext(ctx, deleteSessionDelegationsQuery, pq.Array(roots))
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions' delegations: %w", err)
	}
	delegations, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: delete expired sessions' delegations: row count: %w", err)
	}

	if err := s.appendAuditTx(ctx, tx, audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    time.Now(),
		EventType:     EventTypeSessionsReaped,
		Actor:         reaperActor,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason: fmt.Sprintf("%d sessions that had wholly expired before %s were deleted: %d delegations, %d approvals",
			len(roots), cutoff.UTC().Format(time.RFC3339), delegations, approvals),
	}); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return len(roots), nil
}

// collectIDs reads a one-column result of ids to the end and closes it.
func collectIDs(rows *sql.Rows) ([]string, error) {
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
