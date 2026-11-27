// tool_use.go holds the two reads behind "a tool call ran without a
// decision": the PDP's check of one reported tool call against the decisions
// already in audit_chain, and the PAP's per-delegation count of the reports
// that found none. Neither adds a table: a decision's audit row already
// carries the delegation, the tool name and a digest of the input.
package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// The audit_chain event_type values these queries read. EventTypeDecision is
// what every Decide writes; EventTypeUnmatchedToolUse is what the PDP writes
// when a reported tool call has no ALLOW decision to its name.
const (
	EventTypeDecision         = "decision"
	EventTypeUnmatchedToolUse = "unmatched_tool_use"
)

// No WHERE tenant_id: RLS via beginTenantTx is the only tenant boundary, as
// everywhere else in this package. idx_audit_chain_delegation_id narrows the
// scan to one delegation's rows, and a delegation lives no longer than its
// TTL, so there is no time bound to add.
const hasAllowDecisionQuery = `SELECT EXISTS (SELECT 1 FROM audit_chain ` +
	`WHERE delegation_id = $1 AND event_type = 'decision' AND decision = 'ALLOW' ` +
	`AND tool_name = $2 AND input_digest = $3)`

// HasAllowDecision reports whether audit_chain holds an ALLOW decision for
// this delegation, tool name and input digest.
func (s *Store) HasAllowDecision(ctx context.Context, delegationID uuid.UUID, tool string, inputDigest [32]byte) (bool, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()

	var found bool
	if err := tx.QueryRowContext(ctx, hasAllowDecisionQuery, delegationID, tool, inputDigest[:]).Scan(&found); err != nil {
		return false, fmt.Errorf("store: look up allow decision: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("store: commit: %w", err)
	}
	return found, nil
}

// ponytail: counts over the whole audit log on every list; if that gets slow,
// add a partial index on (delegation_id) WHERE event_type = 'unmatched_tool_use'.
const countUnmatchedToolUsesQuery = `SELECT delegation_id, COUNT(*) FROM audit_chain ` +
	`WHERE event_type = 'unmatched_tool_use' AND delegation_id = ANY($1::uuid[]) ` +
	`GROUP BY delegation_id`

// CountUnmatchedToolUses returns, per delegation, how many reported tool
// calls found no ALLOW decision. A delegation with none is absent from the map.
func (s *Store) CountUnmatchedToolUses(ctx context.Context, delegationIDs []uuid.UUID) (map[uuid.UUID]int, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	ids := make([]string, len(delegationIDs))
	for i, id := range delegationIDs {
		ids[i] = id.String()
	}
	rows, err := tx.QueryContext(ctx, countUnmatchedToolUsesQuery, pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("store: count unmatched tool uses: %w", err)
	}
	defer func() { _ = rows.Close() }()

	counts := make(map[uuid.UUID]int)
	for rows.Next() {
		var id uuid.UUID
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("store: scan unmatched tool use count: %w", err)
		}
		counts[id] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate unmatched tool use counts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return counts, nil
}
