package main

import (
	"encoding/json"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

func auditQueryRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"seq", "prev_hash", "entry_hash", "occurred_at", "event_type", "actor",
		"agent_id", "delegation_id", "tool_name", "derived_tier", "decision", "reason",
	})
}

// expectAuditList registers the begin/set-tenant/query/commit sequence
// ListAudit issues, asserting the four bound arguments -- which is where a
// mis-parsed query parameter would surface.
func expectAuditList(mock sqlmock.Sqlmock, eventType, agentID any, beforeSeq, limit int64, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM audit_chain").
		WithArgs(eventType, agentID, beforeSeq, limit).
		WillReturnRows(rows)
	mock.ExpectCommit()
}

// TestListAudit_PassesFiltersThrough is the point of the handler: a query
// string is the only thing between a caller and the store's filter, so a
// mis-parsed parameter is the whole failure mode.
func TestListAudit_PassesFiltersThrough(t *testing.T) {
	f := newTestServerFixture(t)
	agentID := uuid.New()
	expectAuditList(f.mock, "containment", agentID.String(), int64(900), int64(10), auditQueryRows())

	rec := doRequest(t, f.server, http.MethodGet,
		"/v1/audit?event_type=containment&agent_id="+agentID.String()+"&before_seq=900&limit=10",
		f.token(t, "org-viewers"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestListAudit_NoParamsIsUnfiltered pins the zero values that make
// listAuditQuery's single-statement form work -- an empty event_type, a nil
// agent, a zero cursor, and the default limit.
func TestListAudit_NoParamsIsUnfiltered(t *testing.T) {
	f := newTestServerFixture(t)
	expectAuditList(f.mock, "", nil, int64(0), int64(50), auditQueryRows())

	rec := doRequest(t, f.server, http.MethodGet, "/v1/audit", f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestListAudit_RejectsAMalformedAgentID refuses at the boundary rather than
// passing a string the database will reject: a 400 naming the parameter is
// an answer, a 500 from a failed uuid cast is not.
func TestListAudit_RejectsAMalformedAgentID(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/audit?agent_id=not-a-uuid",
		f.token(t, "org-viewers"))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	if !regexp.MustCompile(`agent_id`).MatchString(rec.Body.String()) {
		t.Errorf("body does not name the offending parameter: %s", rec.Body.String())
	}
	// Nothing may reach the store: no expectations were registered, so a
	// query here fails the call outright.
	assertExpectationsMet(t, f.mock)
}

// TestListAudit_ClampsAnOversizeLimit stops a caller asking for an unbounded
// scan of a table that only ever grows.
func TestListAudit_ClampsAnOversizeLimit(t *testing.T) {
	f := newTestServerFixture(t)
	expectAuditList(f.mock, "", nil, int64(0), int64(500), auditQueryRows())

	rec := doRequest(t, f.server, http.MethodGet, "/v1/audit?limit=100000",
		f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestListAudit_CarriesTheHashesOnTheWire is what makes the response
// verifiable at all. A reader that dropped them would still look correct in
// every other assertion here.
func TestListAudit_CarriesTheHashesOnTheWire(t *testing.T) {
	f := newTestServerFixture(t)
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	expectAuditList(f.mock, "containment", nil, int64(0), int64(50),
		auditQueryRows().AddRow(int64(12), []byte("prev"), []byte("hash"), at, "containment",
			"op@example.com", nil, nil, "", int16(0), "ALLOW",
			"agent grant widened: child tool Write not in parent approved_tools"))

	rec := doRequest(t, f.server, http.MethodGet, "/v1/audit?event_type=containment",
		f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}

	var page models.AuditPage
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v; body = %s", err, rec.Body.String())
	}
	if len(page.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(page.Entries))
	}
	if string(page.Entries[0].PrevHash) != "prev" || string(page.Entries[0].EntryHash) != "hash" {
		t.Errorf("hashes missing from the wire shape: %s", rec.Body.String())
	}
	if page.Entries[0].Reason == "" {
		t.Error("reason is empty; it is the whole point of reading a containment row")
	}
	assertExpectationsMet(t, f.mock)
}

// TestListAudit_RouteIsRegisteredAtViewer pins the role alongside the other
// route-table assertions.
func TestListAudit_RouteIsRegisteredAtViewer(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "GET /v1/audit" {
			found = true
			if rt.MinRole != RoleViewer {
				t.Errorf("MinRole = %v, want RoleViewer", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("GET /v1/audit is not in routeTable")
	}
}
