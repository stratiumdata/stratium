package store

import (
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// auditReadRows builds the column set listAuditQuery selects, in its order.
func auditReadRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"seq", "prev_hash", "entry_hash", "occurred_at", "event_type", "actor",
		"agent_id", "delegation_id", "tool_name", "derived_tier", "decision", "reason", "action",
	})
}

// TestStore_ListAudit_FiltersAreBoundNotAssembled is the load-bearing test
// for this query. internal/store forbids runtime-assembled SQL
// (TestNoRuntimeAssembledSQL), so optional filters cannot be appended as
// text -- they have to be one fixed statement whose parameters carry the
// optionality. This pins that: an unfiltered call and a filtered call must
// issue the SAME sql, differing only in their bound arguments.
func TestStore_ListAudit_FiltersAreBoundNotAssembled(t *testing.T) {
	agentID := uuid.New()

	for _, tc := range []struct {
		name     string
		filter   AuditFilter
		wantArgs []driverArg
	}{
		{
			name:     "no filters",
			filter:   AuditFilter{Limit: 50},
			wantArgs: []driverArg{{""}, {nil}, {int64(0)}, {int64(50)}},
		},
		{
			name:     "event type only",
			filter:   AuditFilter{EventType: "containment", Limit: 50},
			wantArgs: []driverArg{{"containment"}, {nil}, {int64(0)}, {int64(50)}},
		},
		{
			name:     "agent and cursor",
			filter:   AuditFilter{AgentID: &agentID, BeforeSeq: 900, Limit: 10},
			wantArgs: []driverArg{{""}, {agentID.String()}, {int64(900)}, {int64(10)}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectQuery(regexp.QuoteMeta(listAuditQuery)).
				WithArgs(tc.wantArgs[0].v, tc.wantArgs[1].v, tc.wantArgs[2].v, tc.wantArgs[3].v).
				WillReturnRows(auditReadRows())
			mock.ExpectCommit()

			if _, err := s.ListAudit(t.Context(), tc.filter); err != nil {
				t.Fatalf("ListAudit: %v", err)
			}
			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_ListAudit_ReturnsRowsNewestFirstWithTheirHashes pins that the
// hashes reach the caller. They are the only reason a reader can check the
// chain at all, and dropping them from the scan would be invisible to any
// test that only asserted the human-readable fields.
func TestStore_ListAudit_ReturnsRowsNewestFirstWithTheirHashes(t *testing.T) {
	s, mock := newMockStore(t)
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	agentID := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listAuditQuery)).
		WillReturnRows(auditReadRows().
			AddRow(int64(12), []byte("prev-12"), []byte("hash-12"), at, "containment", "op@example.com",
				agentID, nil, "", int16(0), "ALLOW", "agent grant widened: child tool Write not in parent approved_tools", "").
			AddRow(int64(11), []byte("prev-11"), []byte("hash-11"), at, "agent_updated", "op@example.com",
				agentID, nil, "", int16(0), "ALLOW", "", ""))
	mock.ExpectCommit()

	page, err := s.ListAudit(t.Context(), AuditFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(page.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(page.Entries))
	}
	if page.Entries[0].Seq != 12 {
		t.Errorf("first entry seq = %d, want 12 (newest first)", page.Entries[0].Seq)
	}
	if string(page.Entries[0].PrevHash) != "prev-12" || string(page.Entries[0].EntryHash) != "hash-12" {
		t.Errorf("hashes not carried through: prev=%q entry=%q",
			page.Entries[0].PrevHash, page.Entries[0].EntryHash)
	}
	if page.Entries[0].EventType != "containment" {
		t.Errorf("event_type = %q, want containment", page.Entries[0].EventType)
	}
	// The page was not full, so there is no next cursor to hand back.
	if page.NextBeforeSeq != nil {
		t.Errorf("NextBeforeSeq = %v, want nil on a short page", *page.NextBeforeSeq)
	}
}

// TestStore_ListAudit_FullPageCarriesACursor is the other half: a caller
// that got exactly Limit rows cannot tell whether more exist, so the store
// hands back the cursor to ask.
func TestStore_ListAudit_FullPageCarriesACursor(t *testing.T) {
	s, mock := newMockStore(t)
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listAuditQuery)).
		WillReturnRows(auditReadRows().
			AddRow(int64(9), []byte("p"), []byte("h"), at, "decision", "a", nil, nil, "Read", int16(1), "ALLOW", "", "read").
			AddRow(int64(8), []byte("p"), []byte("h"), at, "decision", "a", nil, nil, "Read", int16(1), "ALLOW", "", "read"))
	mock.ExpectCommit()

	page, err := s.ListAudit(t.Context(), AuditFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if page.NextBeforeSeq == nil {
		t.Fatal("a full page must carry a cursor")
	}
	if *page.NextBeforeSeq != 8 {
		t.Errorf("NextBeforeSeq = %d, want 8 (the smallest seq on the page)", *page.NextBeforeSeq)
	}
	if got := page.Entries[0].Action; got != "read" {
		t.Errorf("Entries[0].Action = %q, want the selected action column", got)
	}
}

// driverArg keeps the table above readable: sqlmock's WithArgs is variadic
// over any, and a []any literal per case reads worse than this.
type driverArg struct{ v any }
