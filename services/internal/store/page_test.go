package store

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestClampListLimit(t *testing.T) {
	for in, want := range map[int]int{-1: listDefaultLimit, 0: listDefaultLimit, 7: 7, listMaxLimit: listMaxLimit, 1 << 30: listMaxLimit} {
		if got := clampListLimit(in); got != want {
			t.Errorf("clampListLimit(%d) = %d, want %d", in, got, want)
		}
	}
}

// A page asks the database for one row more than it returns. That row is
// dropped, and its presence is what makes a cursor to the next page.
func TestStore_ListApprovals_PageAndCursor(t *testing.T) {
	s, mock := newMockStore(t)
	newest := time.Now().UTC().Truncate(time.Second)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}

	rows := sqlmock.NewRows(approvalColumns())
	for i, id := range ids {
		listApprovalRow(rows, id, "pending", newest.Add(-time.Duration(i)*time.Minute))
	}
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listApprovalsQuery)).WithArgs(nil, nil, int64(3)).WillReturnRows(rows)
	mock.ExpectCommit()

	got, next, err := s.ListApprovals(context.Background(), nil, 2)
	if err != nil {
		t.Fatalf("ListApprovals() error = %v", err)
	}
	if len(got) != 2 || got[0].ID != ids[0] || got[1].ID != ids[1] {
		t.Fatalf("page = %d rows, want the newest two", len(got))
	}
	if next == nil || next.ID != ids[1] || !next.At.Equal(newest.Add(-time.Minute)) {
		t.Fatalf("next cursor = %+v, want the last row returned", next)
	}
	assertExpectationsMet(t, mock)

	// The next page starts from that cursor; a short page has no cursor.
	mock.ExpectBegin()
	expectSetTenant(mock)
	last := sqlmock.NewRows(approvalColumns())
	listApprovalRow(last, ids[2], "pending", newest.Add(-2*time.Minute))
	mock.ExpectQuery(regexp.QuoteMeta(listApprovalsQuery)).
		WithArgs(next.At, next.ID.String(), int64(3)).WillReturnRows(last)
	mock.ExpectCommit()

	got, after, err := s.ListApprovals(context.Background(), next, 2)
	if err != nil || len(got) != 1 || after != nil {
		t.Fatalf("second page = %d rows, cursor %+v, %v; want 1 row and no cursor", len(got), after, err)
	}
	assertExpectationsMet(t, mock)
}

// The largest page a caller can get is listMaxLimit, whatever it asks for.
func TestStore_ListDelegations_LimitIsClamped(t *testing.T) {
	s, mock := newMockStore(t)
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listDelegationsQuery)).
		WithArgs(nil, nil, int64(listMaxLimit+1)).
		WillReturnRows(sqlmock.NewRows(delegationColumns()))
	mock.ExpectCommit()

	if _, _, err := s.ListDelegations(context.Background(), nil, 1<<30); err != nil {
		t.Fatalf("ListDelegations() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}

func TestStore_ListActiveRootDelegations_ReportsWhenThereAreMore(t *testing.T) {
	s, mock := newMockStore(t)
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listActiveRootDelegationsQuery)).
		WithArgs("alice@example.com", now, int64(1)).
		WillReturnRows(sqlmock.NewRows(delegationColumns()))
	mock.ExpectCommit()

	got, more, err := s.ListActiveRootDelegations(context.Background(), "alice@example.com", now, 0)
	if err != nil || len(got) != 0 || more {
		t.Fatalf("ListActiveRootDelegations() = %d rows, more %v, %v; want none", len(got), more, err)
	}
	assertExpectationsMet(t, mock)
}
