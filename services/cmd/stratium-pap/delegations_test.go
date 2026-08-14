// delegations_test.go proves the HTTP wiring for delegations.go, the same
// thin-layer scope policies_test.go's own doc comment states.
// internal/store/delegation_test.go already covers RevokeDelegation's own
// audit-atomicity and idempotency exhaustively; the cascade property itself
// ("revoking a root denies every descendant on the next action") is proven
// live in internal/store/pap_task4_integration_test.go, since it needs
// DelegationLeg run against a real, persisted chain — nothing this HTTP
// layer touches.
package main

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// delegationRowColumns mirrors internal/store's own (unexported)
// delegationColumns/loadDelegationQuery order — reproduced here for the
// same reason approvalRowColumns is (approvals_test.go's own doc comment).
func delegationRowColumns() []string {
	return []string{
		"id", "tenant_id", "user_id", "agent_id", "approved_tools", "max_action_tier",
		"classification_caps", "resource_constraints", "purpose", "expires_at",
		"created_at", "revoked", "revoked_at", "parent_delegation_id",
		"root_delegation_id", "depth", "chain_agent_ids", "escalate_at",
	}
}

func TestRevokeDelegation_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id, agentID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("UPDATE delegations").
		WillReturnRows(sqlmock.NewRows(delegationRowColumns()).AddRow(
			id.String(), fixtureTenant, "user-1", agentID.String(),
			[]byte(`[]`), int64(models.ActionTierInternalModify),
			[]byte(`{}`), []byte(`{}`), nil, now.Add(time.Hour),
			now, true, now, nil,
			id.String(), int64(0), []byte(`[]`), nil,
		))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	rec := doRequest(t, f.server, http.MethodPost, "/v1/delegations/"+id.String()+"/revoke", f.token(t, "org-admins"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.Delegation](t, rec)
	if !got.Revoked {
		t.Error("Revoked = false, want true")
	}

	assertExpectationsMet(t, f.mock)
}

// TestRevokeDelegation_EditorRole_Refused proves the role floor (RoleAdmin,
// routeTable): unlike decideApproval, there is no SECOND, identity-based
// check backing this one up (N7's own contrast, §4.10.1 — "taking away
// requires only a role"), so the role gate is this route's ENTIRE
// enforcement, and it needs to hold on its own.
func TestRevokeDelegation_EditorRole_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	rec := doRequest(t, f.server, http.MethodPost, "/v1/delegations/"+id.String()+"/revoke", f.token(t, "org-editors"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertExpectationsMet(t, f.mock) // never reached the store at all
}

func TestRevokeDelegation_InvalidID(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodPost, "/v1/delegations/not-a-uuid/revoke", f.token(t, "org-admins"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock)
}

func TestRevokeDelegation_NotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("UPDATE delegations").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodPost, "/v1/delegations/"+id.String()+"/revoke", f.token(t, "org-admins"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}
