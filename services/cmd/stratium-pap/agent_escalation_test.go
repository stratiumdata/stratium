// agent_escalation_test.go proves the HTTP wiring for agent_escalation.go.
// internal/store/agent_escalation_test.go covers the store's own logic,
// including which writes are recorded as widenings.
package main

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// expectEscalationWrite registers the store's write: the locked read of the
// current threshold (none), the UPDATE, and the one audit row. With no prior
// threshold, neither setting nor clearing one widens, so no containment row.
func expectEscalationWrite(mock sqlmock.Sqlmock) {
	now := time.Now().UTC().Truncate(time.Second)
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT escalate_at FROM agents WHERE id = \$1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"escalate_at"}).AddRow(nil))
	mock.ExpectQuery("UPDATE agents SET escalate_at").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

func escalationPath(id uuid.UUID) string { return "/v1/agents/" + id.String() + "/escalation" }

func TestPutAgentEscalation_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectEscalationWrite(f.mock)
	expectLiveDelegations(f.mock, 1)

	rec := doJSONRequest(t, f.server, http.MethodPut, escalationPath(id),
		f.token(t, "org-admins"), map[string]any{"escalate_at": 4})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentEscalationView](t, rec)
	if got.EscalateAt == nil || *got.EscalateAt != models.ActionTierDestructive {
		t.Errorf("escalate_at = %v, want DESTRUCTIVE", got.EscalateAt)
	}
	if got.LiveDelegations != 1 || got.Applies != "at next issuance" {
		t.Errorf("view = %+v", got)
	}
	assertExpectationsMet(t, f.mock)
}

// A missing or null field must be refused, never read as tier 0 (escalate
// on everything) or as "no threshold" (unattended). Out of range is refused
// too. None of these reach the store.
func TestPutAgentEscalation_RefusesAmbiguousOrInvalidBodies(t *testing.T) {
	for name, body := range map[string]map[string]any{
		"missing":      {},
		"null":         {"escalate_at": nil},
		"typo'd key":   {"escalateAt": 4},
		"out of range": {"escalate_at": 5},
		"negative":     {"escalate_at": -1},
	} {
		t.Run(name, func(t *testing.T) {
			f := newTestServerFixture(t)
			rec := doJSONRequest(t, f.server, http.MethodPut, escalationPath(uuid.New()),
				f.token(t, "org-admins"), body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
			}
			assertExpectationsMet(t, f.mock)
		})
	}
}

func TestGetAgentEscalation_ReturnsStoredValue(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now()
	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM agents").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "name", "provider", "model_id",
			"trust_tier", "enabled", "suspended", "allowed_tools", "classification_caps", "resource_constraints",
			"created_at", "updated_at", "escalate_at"}).
			AddRow(id.String(), "test-tenant", "bot", "anthropic", "claude-opus",
				int64(models.TrustTierPlatformTrusted), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`),
				now, now, int64(3)))
	f.mock.ExpectCommit()
	expectLiveDelegations(f.mock, 0)

	rec := doRequest(t, f.server, http.MethodGet, escalationPath(id), f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentEscalationView](t, rec)
	if got.EscalateAt == nil || *got.EscalateAt != models.ActionTierExternalComms {
		t.Errorf("escalate_at = %v, want EXTERNAL_COMMS", got.EscalateAt)
	}
	assertExpectationsMet(t, f.mock)
}

func TestDeleteAgentEscalation_Returns204(t *testing.T) {
	f := newTestServerFixture(t)
	expectEscalationWrite(f.mock)

	rec := doRequest(t, f.server, http.MethodDelete, escalationPath(uuid.New()), f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// An editor may rename an agent but must not set or remove its threshold.
func TestAgentEscalation_EditorForbidden(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			f := newTestServerFixture(t)
			rec := doJSONRequest(t, f.server, method, escalationPath(uuid.New()),
				f.token(t, "org-editors"), map[string]any{"escalate_at": 4})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			assertExpectationsMet(t, f.mock)
		})
	}
}
