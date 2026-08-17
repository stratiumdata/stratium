package store

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

// The real proofs for this file are in spent_proof_integration_test.go: a
// uniqueness constraint, row-level security, and a GRANT are all properties
// of a live database and cannot be established against a mock. What sqlmock
// can establish, and what the integration suite cannot cheaply, is the two
// things below.
//
// First, WHICH failure becomes ErrProofSpent. Integration can produce a
// collision, but producing a different write failure on the same statement
// means revoking a grant mid-suite — a manoeuvre this package has been bitten
// by before (see decide_tier_override_integration_test.go's own file comment
// on the audit_chain revoke). Here both cases are the identical call
// differing in exactly one property: the SQLSTATE the driver returns.
//
// Second, that the reaper's DELETE is issued inside a tenant transaction.
// sqlmock matches expectations in order (newMockStore's doc comment), so a
// reaper rewritten to run against the pool directly fails to meet ExpectBegin
// — which is the silent-no-op mutant caught at unit speed, ahead of the
// integration proof that it genuinely deletes.

func TestStore_SpendProof_UniqueViolationIsErrProofSpent(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertSpentProofQuery)).
		WithArgs(testTenant, "proof-jti-1", sqlmock.AnyArg()).
		WillReturnError(&pq.Error{
			Code:    sqlStateUniqueViolation,
			Message: `duplicate key value violates unique constraint "spent_proofs_pkey"`,
		})
	mock.ExpectRollback()

	err := s.SpendProof(context.Background(), "proof-jti-1", time.Now().Add(time.Minute))
	if !errors.Is(err, ErrProofSpent) {
		t.Errorf("SpendProof() error = %v, want ErrProofSpent", err)
	}

	assertExpectationsMet(t, mock)
}

// The negative control for the test above, and it differs from it in exactly
// one respect: the SQLSTATE. Same statement, same arguments, same *pq.Error
// type, same non-nil outcome — so this passing establishes that the SQLSTATE
// is what decides, rather than "some errors are not replays" for any of the
// other reasons a differently-shaped fixture would also have supplied.
//
// insufficient_privilege specifically, because that is the failure a botched
// GRANT actually produces on this path, and a mutant that reported every
// failed insert as a replay would tell an operator that a permissions outage
// was an attack.
func TestStore_SpendProof_ADifferentSQLStateIsNotErrProofSpent(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertSpentProofQuery)).
		WithArgs(testTenant, "proof-jti-1", sqlmock.AnyArg()).
		WillReturnError(&pq.Error{
			Code:    "42501",
			Message: `permission denied for table spent_proofs`,
		})
	mock.ExpectRollback()

	err := s.SpendProof(context.Background(), "proof-jti-1", time.Now().Add(time.Minute))
	if err == nil {
		t.Fatal("SpendProof() error = nil, want the write failure to propagate")
	}
	if errors.Is(err, ErrProofSpent) {
		t.Errorf("SpendProof() error = %v, want a plain write failure, NOT ErrProofSpent: "+
			"a permissions outage reported as a replay sends an operator hunting an attacker", err)
	}

	assertExpectationsMet(t, mock)
}

// A first spend commits. Without this, a mutant that returned ErrProofSpent
// unconditionally would satisfy both tests above.
func TestStore_SpendProof_FirstSpendCommits(t *testing.T) {
	s, mock := newMockStore(t)
	expiry := time.Now().Add(time.Minute)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertSpentProofQuery)).
		WithArgs(testTenant, "proof-jti-1", expiry).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.SpendProof(context.Background(), "proof-jti-1", expiry); err != nil {
		t.Errorf("SpendProof() error = %v, want nil", err)
	}

	assertExpectationsMet(t, mock)
}

// The reaper's DELETE must run inside a transaction that has already set
// app.tenant_id. Ordered expectations make that structural: issue the DELETE
// on the pool instead, or before set_config, and sqlmock reports the
// unsatisfied expectation. The count is returned rather than swallowed, since
// it is the only evidence that separates a reaper that worked from one RLS
// silently filtered to nothing.
func TestStore_ReapSpentProofs_DeletesInsideATenantTxAndReturnsTheCount(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(reapSpentProofsQuery)).
		WillReturnResult(sqlmock.NewResult(0, 7))
	mock.ExpectCommit()

	reaped, err := s.ReapSpentProofs(context.Background())
	if err != nil {
		t.Fatalf("ReapSpentProofs() error = %v, want nil", err)
	}
	if reaped != 7 {
		t.Errorf("ReapSpentProofs() = %d, want 7 (the rows the DELETE affected)", reaped)
	}

	assertExpectationsMet(t, mock)
}

// A reaper whose DELETE fails must say so. "The reaper ran" is not evidence
// it did anything, and an error swallowed here is the failure mode §4.7.2 K8
// calls out by name: a table that grows until something else breaks and gets
// blamed instead.
func TestStore_ReapSpentProofs_PropagatesTheDeleteFailure(t *testing.T) {
	s, mock := newMockStore(t)
	deleteErr := errors.New("connection reset during the sweep")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(reapSpentProofsQuery)).WillReturnError(deleteErr)
	mock.ExpectRollback()

	reaped, err := s.ReapSpentProofs(context.Background())
	if !errors.Is(err, deleteErr) {
		t.Errorf("ReapSpentProofs() error = %v, want it to wrap %v", err, deleteErr)
	}
	if reaped != 0 {
		t.Errorf("ReapSpentProofs() = %d on failure, want 0", reaped)
	}

	assertExpectationsMet(t, mock)
}
