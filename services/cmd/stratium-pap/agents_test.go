// agents_test.go proves the HTTP wiring for agents.go -- the same thin
// decode/call/respond proof policies_test.go gives its own resource.
// internal/store/agent_test.go covers CreateAgent/UpdateAgent's own field
// validation exhaustively.
package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/stratiumdata/stratium/pkg/models"
)

func TestCreateAgent_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(f.mock, "INSERT INTO agents",
		sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))

	body := models.Agent{Name: "billing-bot", Provider: "anthropic", TrustTier: models.TrustTierCertified, Enabled: true, AllowedTools: []string{"Read"}}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/agents", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got := decodeBody[models.Agent](t, rec)
	if got.ID != id {
		t.Errorf("response ID = %s, want %s", got.ID, id)
	}

	assertExpectationsMet(t, f.mock)
}

// TestCreateAgent_MissingAllowedTools_Refused proves the security-relevant
// footgun this endpoint specifically guards against (models.Agent's own
// AllowedTools doc comment, and ErrAllowedToolsRequired's) reaches an HTTP
// caller as 400, and never as a silently-created unrestricted agent.
func TestCreateAgent_MissingAllowedTools_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	body := map[string]any{"name": "billing-bot", "provider": "anthropic", "trust_tier": 1, "enabled": true}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/agents", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // never reached the database
}

func TestGetAgent_NotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM agents").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/agents/"+id.String(), f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestUpdateAgent_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	// classification_caps and resource_constraints are RETURNING columns now
	// (internal/store's updateAgentQuery no longer writes either -- PUT can't
	// touch these columns -- but still reads back their unchanged, real
	// values; see that query's own doc comment).
	// allowed_tools is read back under FOR UPDATE before the write, as the
	// baseline for the containment verdict (internal/store/containment_audit.go).
	// [] before and [] in the body is unrestricted -> unrestricted: the grant
	// does not move, so the single audit insert below is still the whole
	// sequence.
	expectGrantWriteAndAudit(f.mock, "allowed_tools", `[]`, "UPDATE agents",
		sqlmock.NewRows([]string{"created_at", "updated_at", "classification_caps", "resource_constraints", "escalate_at"}).
			AddRow(now, now, []byte(`{}`), []byte(`{}`), nil))

	body := models.Agent{Name: "renamed-bot", Provider: "anthropic", TrustTier: models.TrustTierRegistered, Suspended: true, AllowedTools: []string{}}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/agents/"+id.String(), f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.Agent](t, rec)
	if !got.Suspended {
		t.Errorf("Suspended = false, want true")
	}
}

func TestDeleteAgent_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectDeleteAndAudit(f.mock, "DELETE FROM agents", "name", "doomed-bot")

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/agents/"+id.String(), f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	assertExpectationsMet(t, f.mock)
}

// TestDeleteAgent_StillReferenced_ReturnsConflict is Issue 2's HTTP-level
// proof: an agent a live delegation or approval still names must answer 409
// Conflict, naming the blocker -- never the 500 an unrecognized error would
// have produced before store.ErrConflict existed, and never the underlying
// Postgres constraint text either.
func TestDeleteAgent_StillReferenced_ReturnsConflict(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("DELETE FROM agents").WillReturnError(&pq.Error{
		Code:    "23503",
		Message: `update or delete on table "agents" violates foreign key constraint "delegations_agent_id_fkey" on table "delegations"`,
		Detail:  `Key (id)=(deadbeef-0000-0000-0000-000000000000) is still referenced from table "delegations".`,
	})
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/agents/"+id.String(), f.token(t, "org-admins"))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "delegation") && !strings.Contains(body, "approval") {
		t.Errorf("body = %q, want it to name what blocks the delete (a delegation or approval)", body)
	}
	if strings.Contains(body, "delegations_agent_id_fkey") || strings.Contains(body, "still referenced from table") {
		t.Errorf("body = %q, must not echo the underlying Postgres constraint/detail text", body)
	}

	assertExpectationsMet(t, f.mock)
}
