package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// These reuse newMockStore, expectSetTenant (store_test.go),
// expectAdvisoryLock (audit_test.go), and auditArgsWithEventType,
// auditArgsCapturingReason, expectLiveDelegations (agent_caps_test.go).

func expectEscalationBeforeRead(mock sqlmock.Sqlmock, id uuid.UUID, before any) {
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentEscalationForUpdateQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"escalate_at"}).AddRow(before))
}

// expectEscalationWrite registers the UPDATE and the operator's own audit row.
func expectEscalationWrite(mock sqlmock.Sqlmock, id uuid.UUID, value any, eventType string, now time.Time) {
	mock.ExpectQuery(regexp.QuoteMeta(updateAgentEscalationQuery)).
		WithArgs(id.String(), value).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventType)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// expectContainmentRow registers the second, containment audit row and
// captures its reason.
func expectContainmentRow(mock sqlmock.Sqlmock, reason *string) {
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsCapturingReason(reason)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
}

// Setting the first threshold NARROWS the agent's grant (a human now stands
// in front of the band), so it writes exactly one audit row and no
// containment verdict. Before Task 1 of the plan this was misrecorded as a
// widening.
func TestSetAgentEscalation_FirstThresholdIsNotAWidening(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectEscalationBeforeRead(mock, id, nil)
	expectEscalationWrite(mock, id, sql.NullInt16{Int16: 4, Valid: true}, eventTypeAgentEscalationSet, now)
	mock.ExpectCommit()
	expectLiveDelegations(mock, 3)

	view, err := s.SetAgentEscalation(context.Background(), id, models.ActionTierDestructive, "operator@example.com")
	if err != nil {
		t.Fatalf("SetAgentEscalation() error = %v", err)
	}
	if view.EscalateAt == nil || *view.EscalateAt != models.ActionTierDestructive {
		t.Errorf("EscalateAt = %v, want DESTRUCTIVE", view.EscalateAt)
	}
	if view.LiveDelegations != 3 || view.Applies != "at next issuance" {
		t.Errorf("view = %+v, want 3 live delegations, applies at next issuance", view)
	}
	assertExpectationsMet(t, mock)
}

// Removing or raising a threshold lets an agent act unattended where a human
// was asked before: both are widenings, and both must leave a containment row
// naming escalate_at. This is also the test that pins escalationGrant's
// MaxTier: at the zero value every threshold reads as unreachable and
// neither case would be recorded.
func TestAgentEscalation_RemovingOrRaisingIsAuditedAsWidening(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(s *Store, id uuid.UUID) error
		value any
		event string
	}{
		{"cleared", func(s *Store, id uuid.UUID) error {
			return s.ClearAgentEscalation(context.Background(), id, "operator@example.com")
		}, sql.NullInt16{}, eventTypeAgentEscalationCleared},
		{"raised", func(s *Store, id uuid.UUID) error {
			_, err := s.SetAgentEscalation(context.Background(), id, models.ActionTierDestructive, "operator@example.com")
			return err
		}, sql.NullInt16{Int16: 4, Valid: true}, eventTypeAgentEscalationSet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			id, now := uuid.New(), time.Now().UTC()
			var reason string

			mock.ExpectBegin()
			expectSetTenant(mock)
			expectEscalationBeforeRead(mock, id, int64(models.ActionTierInternalModify))
			expectEscalationWrite(mock, id, tc.value, tc.event, now)
			expectContainmentRow(mock, &reason)
			mock.ExpectCommit()
			if tc.name == "raised" {
				expectLiveDelegations(mock, 0)
			}

			if err := tc.write(s, id); err != nil {
				t.Fatalf("write error = %v", err)
			}
			if !strings.HasPrefix(reason, "agent grant widened: ") || !strings.Contains(reason, "escalate_at") {
				t.Errorf("containment reason = %q, want a widening naming escalate_at", reason)
			}
			assertExpectationsMet(t, mock)
		})
	}
}

// Lowering a threshold asks a human sooner: narrowing, so no verdict.
func TestSetAgentEscalation_LoweringIsNotAWidening(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectEscalationBeforeRead(mock, id, int64(models.ActionTierDestructive))
	expectEscalationWrite(mock, id, sql.NullInt16{Int16: 2, Valid: true}, eventTypeAgentEscalationSet, now)
	mock.ExpectCommit()
	expectLiveDelegations(mock, 0)

	if _, err := s.SetAgentEscalation(context.Background(), id, models.ActionTierInternalModify, "op"); err != nil {
		t.Fatalf("SetAgentEscalation() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}

func TestSetAgentEscalation_RejectsAnOutOfRangeTierBeforeWriting(t *testing.T) {
	s, mock := newMockStore(t)
	_, err := s.SetAgentEscalation(context.Background(), uuid.New(), models.ActionTier(5), "op")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
	assertExpectationsMet(t, mock)
}

func TestSetAgentEscalation_UnknownAgentIsNotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentEscalationForUpdateQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.SetAgentEscalation(context.Background(), id, models.ActionTierDestructive, "op")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
	assertExpectationsMet(t, mock)
}

func TestDecodeEscalateAt(t *testing.T) {
	if got, err := decodeEscalateAt(sql.NullInt16{}); got != nil || err != nil {
		t.Errorf("NULL = (%v, %v), want (nil, nil): NULL means never escalate", got, err)
	}
	if got, err := decodeEscalateAt(sql.NullInt16{Int16: 3, Valid: true}); err != nil || got == nil || *got != models.ActionTierExternalComms {
		t.Errorf("3 = (%v, %v), want EXTERNAL_COMMS", got, err)
	}
	if _, err := decodeEscalateAt(sql.NullInt16{Int16: 9, Valid: true}); err == nil {
		t.Error("an out-of-range stored value must fail loudly, never decode to some tier")
	}
}
