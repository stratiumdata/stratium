package main

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
)

const checkQuery = `SELECT pg_has_role(current_user, $1, 'member')`

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func TestCheckNotAuditOwner_NotAMember(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(checkQuery)).
		WithArgs(auditOwnerRole).
		WillReturnRows(sqlmock.NewRows([]string{"pg_has_role"}).AddRow(false))

	if err := checkNotAuditOwner(context.Background(), db); err != nil {
		t.Fatalf("checkNotAuditOwner() error = %v, want nil", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// This is the case the whole task exists to prevent: refuse to start named,
// not a live tamper path being missed.
func TestCheckNotAuditOwner_IsAMember_RefusesWithNamedError(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectQuery(regexp.QuoteMeta(checkQuery)).
		WithArgs(auditOwnerRole).
		WillReturnRows(sqlmock.NewRows([]string{"pg_has_role"}).AddRow(true))

	err := checkNotAuditOwner(context.Background(), db)
	if !errors.Is(err, ErrServingIdentityIsAuditOwner) {
		t.Fatalf("checkNotAuditOwner() error = %v, want errors.Is(_, ErrServingIdentityIsAuditOwner)", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// A missing role must surface as ErrAuditOwnerRoleMissing, a named,
// legible error naming migration 000004 — not the raw 42704 SQL error.
func TestCheckNotAuditOwner_RoleDoesNotExist(t *testing.T) {
	db, mock := newMockDB(t)
	undefinedRole := &pq.Error{
		Code:    sqlStateUndefinedObject,
		Message: `role "stratium_audit_owner" does not exist`,
	}
	mock.ExpectQuery(regexp.QuoteMeta(checkQuery)).
		WithArgs(auditOwnerRole).
		WillReturnError(undefinedRole)

	err := checkNotAuditOwner(context.Background(), db)
	if !errors.Is(err, ErrAuditOwnerRoleMissing) {
		t.Fatalf("checkNotAuditOwner() error = %v, want errors.Is(_, ErrAuditOwnerRoleMissing)", err)
	}
	if !regexp.MustCompile(`does not exist`).MatchString(err.Error()) {
		t.Errorf("error %q does not carry the underlying SQL message", err.Error())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// A generic query failure (connection reset, timeout, ...) must propagate
// as itself, not get mislabeled as either named case above.
func TestCheckNotAuditOwner_GenericQueryErrorPropagates(t *testing.T) {
	db, mock := newMockDB(t)
	connErr := errors.New("connection reset by peer")
	mock.ExpectQuery(regexp.QuoteMeta(checkQuery)).
		WithArgs(auditOwnerRole).
		WillReturnError(connErr)

	err := checkNotAuditOwner(context.Background(), db)
	if err == nil {
		t.Fatal("checkNotAuditOwner() error = nil, want the underlying query error")
	}
	if errors.Is(err, ErrServingIdentityIsAuditOwner) || errors.Is(err, ErrAuditOwnerRoleMissing) {
		t.Fatalf("checkNotAuditOwner() error = %v, want neither named error for a generic failure", err)
	}
	if !errors.Is(err, connErr) {
		t.Errorf("checkNotAuditOwner() error = %v, want it to wrap %v", err, connErr)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
