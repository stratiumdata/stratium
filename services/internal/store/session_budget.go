package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// session_budget.go is the shared half of the per-session call budget
// (internal/pdpgrpc/budget.go): one row for each busy session, which every
// PDP for the tenant draws on, so the rate holds across them. See
// migrations/000029_session_budgets for the table.

// leaseSessionTokensQuery refills a session's bucket for the time since it
// was last touched, takes up to $5 whole tokens from it, and returns how many
// it took. A session with no row starts full.
//
// $3 is the burst, $4 the tokens a second, $5 how many are wanted.
//
// The refill is written out three times because an upsert's SET list cannot
// name a value once and reuse it. now() is the transaction's start, so the
// three agree. Elapsed time is floored at zero and updated_at never moves
// back: two PDPs' transactions can reach the row in the opposite order to the
// one they started in.
const leaseSessionTokensQuery = `INSERT INTO session_budgets AS b (session_id, tenant_id, tokens, last_taken, updated_at) ` +
	`VALUES ($1, $2, $3::float8 - LEAST($3::float8, $5::float8), LEAST($3::float8, $5::float8)::int, now()) ` +
	`ON CONFLICT (session_id) DO UPDATE SET ` +
	`last_taken = LEAST($5::float8, floor(LEAST($3::float8, b.tokens + ` +
	`GREATEST(0, extract(epoch FROM now() - b.updated_at)) * $4::float8)))::int, ` +
	`tokens = LEAST($3::float8, b.tokens + GREATEST(0, extract(epoch FROM now() - b.updated_at)) * $4::float8) ` +
	`- LEAST($5::float8, floor(LEAST($3::float8, b.tokens + ` +
	`GREATEST(0, extract(epoch FROM now() - b.updated_at)) * $4::float8))), ` +
	`updated_at = GREATEST(now(), b.updated_at) ` +
	`RETURNING last_taken`

// reapSessionBudgetsQuery forgets sessions nobody has called under since $1.
// A row left that long has refilled completely, which is what no row means.
const reapSessionBudgetsQuery = `DELETE FROM session_budgets WHERE updated_at < $1`

// LeaseSessionTokens takes up to want tokens from session's shared budget, of
// burst tokens refilling at perSecond, and returns how many it got. Zero means
// the session has used its budget for now, across every PDP.
func (s *Store) LeaseSessionTokens(ctx context.Context, session uuid.UUID, burst, perSecond float64, want int) (int, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var taken int
	if err := tx.QueryRowContext(ctx, leaseSessionTokensQuery,
		session.String(), s.tenantID, burst, perSecond, want).Scan(&taken); err != nil {
		return 0, fmt.Errorf("store: lease session tokens: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return taken, nil
}

// ReapSessionBudgets deletes the budget rows of sessions untouched since
// idleSince and returns how many went.
func (s *Store) ReapSessionBudgets(ctx context.Context, idleSince time.Time) (int64, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, reapSessionBudgetsQuery, idleSince)
	if err != nil {
		return 0, fmt.Errorf("store: reap session budgets: %w", err)
	}
	reaped, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: reap session budgets: row count: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return reaped, nil
}
