package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

func pagingApprovalRow(rows *sqlmock.Rows, id uuid.UUID, requestedAt time.Time) {
	rows.AddRow(
		id.String(), fixtureTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
		"requester@example.com", "root@example.com", "Bash", "execute", int64(models.ActionTierExternalComms),
		make([]byte, 32), "pending", requestedAt, approvalFixtureExpiresAt, nil, nil, nil,
	)
}

// A page that is not the last carries a Link header to the next one, and that
// URL is accepted as it stands. The body stays a plain array.
func TestListApprovals_PageHasALinkToTheNext_WhichTheServerAccepts(t *testing.T) {
	f := newTestServerFixture(t)
	first, second := uuid.New(), uuid.New()
	rows := sqlmock.NewRows(approvalRowColumns())
	pagingApprovalRow(rows, first, approvalFixtureRequestedAt)
	pagingApprovalRow(rows, second, approvalFixtureRequestedAt.Add(-time.Minute))
	expectApprovalList(f.mock, rows) // limit 1 asks for 2

	rec := doRequest(t, f.server, http.MethodGet, "/v1/approvals?limit=1", f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("body is not a JSON array: %v", err)
	}
	if len(got) != 1 || got[0]["id"] != first.String() {
		t.Fatalf("page = %v, want only the newest approval", got)
	}

	link := rec.Header().Get("Link")
	next, rel, _ := strings.Cut(link, ">; ")
	next = strings.TrimPrefix(next, "<")
	if rel != `rel="next"` || !strings.HasPrefix(next, "/v1/approvals?") ||
		!strings.Contains(next, "limit=1") || !strings.Contains(next, first.String()) {
		t.Fatalf("Link = %q, want a rel=next URL for this route carrying the limit and the last row's cursor", link)
	}

	last := sqlmock.NewRows(approvalRowColumns())
	pagingApprovalRow(last, second, approvalFixtureRequestedAt.Add(-time.Minute))
	expectApprovalList(f.mock, last)

	rec = doRequest(t, f.server, http.MethodGet, next, f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("following the Link: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Link") != "" {
		t.Errorf("the last page has Link = %q, want none", rec.Header().Get("Link"))
	}
	assertExpectationsMet(t, f.mock)
}

// A bad page parameter is refused before the database is asked anything.
func TestListRoutes_BadPageParameters_Refused(t *testing.T) {
	for _, path := range []string{
		"/v1/approvals?limit=0", "/v1/approvals?limit=many", "/v1/approvals?before=yesterday",
		"/v1/delegations?limit=-3", "/v1/delegations?before=2026-01-01T00:00:00Z~not-a-uuid",
	} {
		t.Run(path, func(t *testing.T) {
			f := newTestServerFixture(t)
			rec := doRequest(t, f.server, http.MethodGet, path, f.token(t, "org-viewers"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
			assertExpectationsMet(t, f.mock)
		})
	}
}
