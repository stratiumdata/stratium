package store

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestStore_LeaseSessionTokens_ReturnsWhatTheDatabaseTook(t *testing.T) {
	s, mock := newMockStore(t)
	session := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(leaseSessionTokensQuery)).
		WithArgs(session.String(), testTenant, 100.0, 20.0, 20).
		WillReturnRows(sqlmock.NewRows([]string{"last_taken"}).AddRow(7))
	mock.ExpectCommit()

	got, err := s.LeaseSessionTokens(context.Background(), session, 100, 20, 20)
	if err != nil || got != 7 {
		t.Fatalf("LeaseSessionTokens() = %d, %v; want 7, nil", got, err)
	}
	assertExpectationsMet(t, mock)
}

func TestStore_LeaseSessionTokens_FailureRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(leaseSessionTokensQuery)).WillReturnError(errors.New("connection reset"))
	mock.ExpectRollback()

	if _, err := s.LeaseSessionTokens(context.Background(), uuid.New(), 100, 20, 20); err == nil {
		t.Fatal("LeaseSessionTokens() error = nil, want the query's failure")
	}
	assertExpectationsMet(t, mock)
}

func TestStore_ReapSessionBudgets(t *testing.T) {
	s, mock := newMockStore(t)
	idleSince := time.Now().Add(-time.Hour)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(reapSessionBudgetsQuery)).WithArgs(idleSince).
		WillReturnResult(sqlmock.NewResult(0, 4))
	mock.ExpectCommit()

	if n, err := s.ReapSessionBudgets(context.Background(), idleSince); err != nil || n != 4 {
		t.Fatalf("ReapSessionBudgets() = %d, %v; want 4, nil", n, err)
	}
	assertExpectationsMet(t, mock)
}
