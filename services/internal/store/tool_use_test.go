package store

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestStore_HasAllowDecision(t *testing.T) {
	for _, want := range []bool{true, false} {
		s, mock := newMockStore(t)
		id, digest := uuid.New(), [32]byte{1, 2, 3}

		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery(regexp.QuoteMeta(hasAllowDecisionQuery)).
			WithArgs(id, "Bash", digest[:]).
			WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(want))
		mock.ExpectCommit()

		got, err := s.HasAllowDecision(context.Background(), id, "Bash", digest)
		if err != nil || got != want {
			t.Fatalf("HasAllowDecision() = %v, %v; want %v", got, err, want)
		}
		assertExpectationsMet(t, mock)
	}
}

// Only an ALLOW from Decide counts. A DENY or ESCALATE for the same call, or
// an earlier unmatched_tool_use row (which also carries the tool and digest),
// must not satisfy a later report.
func TestStore_HasAllowDecisionQuery_MatchesOnlyAllowDecisions(t *testing.T) {
	for _, want := range []string{
		"event_type = 'decision'", "decision = 'ALLOW'",
		"delegation_id = $1", "tool_name = $2", "input_digest = $3",
	} {
		if !strings.Contains(hasAllowDecisionQuery, want) {
			t.Errorf("hasAllowDecisionQuery lacks %q: %s", want, hasAllowDecisionQuery)
		}
	}
	if EventTypeDecision != "decision" || EventTypeUnmatchedToolUse != "unmatched_tool_use" {
		t.Error("the event type constants no longer match the literals in this file's queries")
	}
}

func TestStore_CountUnmatchedToolUses(t *testing.T) {
	s, mock := newMockStore(t)
	a, b := uuid.New(), uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(countUnmatchedToolUsesQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"delegation_id", "count"}).
			AddRow(a.String(), int64(2)).AddRow(b.String(), int64(1)))
	mock.ExpectCommit()

	got, err := s.CountUnmatchedToolUses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[a] != 2 || got[b] != 1 {
		t.Fatalf("CountUnmatchedToolUses() = %v", got)
	}
	assertExpectationsMet(t, mock)
}
