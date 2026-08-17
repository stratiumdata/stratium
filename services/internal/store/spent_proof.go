package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrProofSpent indicates a DPoP proof's jti was already recorded as spent
// for this tenant: the caller replayed a proof (spec §4.7.2 K8).
//
// It exists as its own sentinel rather than folding into ErrAlreadyExists
// because the two mean different things to whoever is reading a log at 3am.
// ErrAlreadyExists is a naming collision an operator authored — two policies
// called the same thing — and maps to 409 Conflict on the admin surface.
// This is an attack signature, or a broken client retrying a proof it must
// mint fresh each time. Both deny; only one of them means someone should look
// at where the proofs are coming from.
//
// The jti itself is deliberately not carried in this error. A caller that
// wants to correlate already has the value it passed in, and an error string
// is the one place a credential-adjacent identifier reliably ends up in logs
// this phase is otherwise careful to keep it out of (§4.7.2 K10).
var ErrProofSpent = errors.New("store: dpop proof already spent")

// insertSpentProofQuery records one spent proof. A plain INSERT, deliberately
// not INSERT ... ON CONFLICT DO NOTHING: see SpendProof's doc comment.
const insertSpentProofQuery = `INSERT INTO spent_proofs (tenant_id, jti, expires_at) VALUES ($1,$2,$3)`

// reapSpentProofsQuery deletes this tenant's expired rows. NOW() rather than
// a Go-supplied instant, for the same reason approvals.requested_at defaults
// to NOW() (migrations/000012): the database clock is the one clock every PDP
// replica sharing this database agrees on, so the reaping boundary does not
// move depending on which replica happened to run the sweep.
//
// There is no WHERE tenant_id here and there must not be. Row-level security
// is the tenant boundary — see the package doc — and this statement is the
// one in this package where that is most load-bearing: under FORCE ROW LEVEL
// SECURITY a DELETE on a connection with no app.tenant_id set matches nothing
// at all, silently.
const reapSpentProofsQuery = `DELETE FROM spent_proofs WHERE expires_at <= NOW()`

// SpendProof records jti as spent for this tenant, returning ErrProofSpent if
// it already was. expiresAt is the instant after which the row may be reaped:
// the proof's own iat plus the configured freshness window (§4.7.2 K9), past
// which internal/dpop.Verify refuses the proof for staleness whether or not
// this table still remembers it.
//
// # How a replay is distinguished from any other write failure
//
// The INSERT is plain. A replay comes back as a Postgres unique_violation
// (SQLSTATE 23505) against spent_proofs' primary key, which isUniqueViolation
// recognises and which nothing else on this table can produce: spent_proofs
// has exactly one uniqueness constraint, the primary key on (tenant_id, jti),
// so 23505 here means a replay and cannot mean anything else. That inference
// is a property of the schema, not of this code — a future migration adding a
// second unique constraint to this table breaks it, and would have to revisit
// this function.
//
// Every other failure keeps its own error, wrapped with context and NOT
// matching ErrProofSpent: a permission error, a lost connection, a CHECK
// violation from an over-long jti. Both outcomes deny at the caller, which is
// the point of failing closed — but an operator staring at a spike of denials
// needs to know whether they are watching a replay storm or a database
// falling over, and those two answers demand opposite responses.
//
// This is deliberately NOT `ON CONFLICT DO NOTHING` with the outcome inferred
// from RowsAffected. That shape reads as though it handles the collision, and
// it does — but it reports zero rows for a conflict and would report zero
// rows just as happily if RLS silently refused the write, which is exactly
// the class of confusion the reaper below has to be careful about. An error
// that names its own SQLSTATE cannot be confused with an empty result.
func (s *Store) SpendProof(ctx context.Context, jti string, expiresAt time.Time) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, insertSpentProofQuery, s.tenantID, jti, expiresAt); err != nil {
		if isUniqueViolation(err) {
			return ErrProofSpent
		}
		return fmt.Errorf("store: spend dpop proof: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// ReapSpentProofs deletes this tenant's expired spent-proof rows and returns
// how many it removed. An unbounded table on the decision path degrades every
// future request (§4.7.2 K8), so something must call this on a schedule.
//
// # It reaps one tenant, and that is the design, not a limitation
//
// A reader expects a reaper to sweep every tenant, and writing one here would
// be a mistake in three separate ways.
//
// It could not work as written. RLS applies to stratium_app on this table
// like every other, so a DELETE issued with no app.tenant_id set matches zero
// rows — no error, no warning, a reaper that runs forever, reports success,
// and never deletes anything while the table grows until something else
// breaks and gets blamed. Going through beginTenantTx is what makes this
// function delete at all, which is why
// TestIntegration_ReapSpentProofs_DeletesExpiredRowsAndSparesUnexpiredOnes
// asserts that rows actually disappear rather than that the call returned
// nil.
//
// It could not discover its own workload. A cross-tenant sweep needs the set
// of tenants, and there is no tenants table in this schema — tenant_id is an
// opaque TEXT column with no backing relation anywhere (the same observation
// migrations/000012_approvals.up.sql makes about root_principal). The obvious
// SELECT DISTINCT tenant_id FROM spent_proofs is itself filtered by the same
// policy, so the loop cannot even enumerate what to iterate over.
//
// It would need a privilege this system deliberately does not issue. Reaching
// every tenant's rows means BYPASSRLS, or ownership, or a policy exception —
// a role that can read and delete across every tenant, which would be the
// first such role in this schema and a far larger blast radius than reaping
// justifies. migrations/000002_rls.up.sql's own comment is explicit that the
// guarantee in every setup rests on the serving role holding none of those.
//
// And none of it is needed: the tenant is fixed at New from startup
// configuration and a PDP process serves exactly one (see the package doc), so
// each process reaping its own tenant covers every tenant that has a PDP.
// Coverage is a property of the deployment, not of one sweep.
//
// # Its failure must be visible
//
// Hence both return values, and a caller that discards either has given up
// the only two signals this operation produces. A non-nil error is a reaper
// that did not run. A count is what distinguishes a reaper that ran from a
// reaper that worked: "no error" is also what a silently RLS-blocked DELETE
// returns, so a scheduled caller should log the count and an operator should
// treat a reaper pinned at zero against a growing table as the same kind of
// alarm as an error.
func (s *Store) ReapSpentProofs(ctx context.Context) (int64, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, reapSpentProofsQuery)
	if err != nil {
		return 0, fmt.Errorf("store: reap spent dpop proofs: %w", err)
	}
	reaped, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: reap spent dpop proofs: row count: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return reaped, nil
}
