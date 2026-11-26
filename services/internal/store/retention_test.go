package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Nothing past the cutoff: nothing is deleted and nothing is audited.
func TestStore_ReapExpiredSessions_NothingToDelete(t *testing.T) {
	s, mock := newMockStore(t)
	cutoff := time.Now().Add(-90 * 24 * time.Hour)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(selectDeadSessionsQuery)).WithArgs(cutoff, int64(50)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}))
	mock.ExpectCommit()

	if n, err := s.ReapExpiredSessions(context.Background(), cutoff, 50); n != 0 || err != nil {
		t.Fatalf("ReapExpiredSessions() = %d, %v; want 0, nil", n, err)
	}
	assertExpectationsMet(t, mock)
}

// Approvals go first, then the delegations, both for exactly the sessions the
// query chose, and one audit entry says how much went.
func TestStore_ReapExpiredSessions_DeletesApprovalsThenDelegationsAndAudits(t *testing.T) {
	s, mock := newMockStore(t)
	cutoff := time.Now().Add(-90 * 24 * time.Hour)
	a, b := uuid.NewString(), uuid.NewString()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(selectDeadSessionsQuery)).WithArgs(cutoff, int64(50)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(a).AddRow(b))
	mock.ExpectExec(regexp.QuoteMeta(deleteSessionApprovalsQuery)).WithArgs(pq.Array([]string{a, b})).
		WillReturnResult(sqlmock.NewResult(0, 3))
	mock.ExpectExec(regexp.QuoteMeta(deleteSessionDelegationsQuery)).WithArgs(pq.Array([]string{a, b})).
		WillReturnResult(sqlmock.NewResult(0, 5))
	entry := expectAuditAppendCapturing(mock)
	mock.ExpectCommit()

	n, err := s.ReapExpiredSessions(context.Background(), cutoff, 50)
	if n != 2 || err != nil {
		t.Fatalf("ReapExpiredSessions() = %d, %v; want 2, nil", n, err)
	}
	if entry.eventType != EventTypeSessionsReaped ||
		!strings.Contains(entry.reason, "2 sessions") || !strings.Contains(entry.reason, "5 delegations, 3 approvals") {
		t.Errorf("audit entry = %q, %q; want a %s entry counting 2 sessions, 5 delegations, 3 approvals",
			entry.eventType, entry.reason, EventTypeSessionsReaped)
	}
	assertExpectationsMet(t, mock)
}

// A failed delete rolls the whole sweep back: no half-deleted session.
func TestStore_ReapExpiredSessions_DeleteFailureRollsBack(t *testing.T) {
	s, mock := newMockStore(t)
	cutoff := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(selectDeadSessionsQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.NewString()))
	mock.ExpectExec(regexp.QuoteMeta(deleteSessionApprovalsQuery)).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(regexp.QuoteMeta(deleteSessionDelegationsQuery)).WillReturnError(errors.New("refused"))
	mock.ExpectRollback()

	if _, err := s.ReapExpiredSessions(context.Background(), cutoff, 50); err == nil {
		t.Fatal("ReapExpiredSessions() error = nil, want the delete's failure")
	}
	assertExpectationsMet(t, mock)
}

// capturedAudit is what expectAuditAppendCapturing read off the INSERT.
type capturedAudit struct{ eventType, reason string }

// capture is a sqlmock argument that accepts any string and remembers it.
type capture struct{ into *string }

func (c capture) Match(v driver.Value) bool {
	s, ok := v.(string)
	if ok {
		*c.into = s
	}
	return ok
}

// expectAuditAppendCapturing expects appendAuditTx's three statements on an
// empty chain and returns the event type and reason the INSERT carried, by
// their positions in insertAuditQuery's column list.
func expectAuditAppendCapturing(mock sqlmock.Sqlmock) *capturedAudit {
	got := &capturedAudit{}
	const columns, eventTypeAt, reasonAt = 22, 4, 17
	args := make([]driver.Value, columns)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[eventTypeAt] = capture{&got.eventType}
	args[reasonAt] = capture{&got.reason}

	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	return got
}
