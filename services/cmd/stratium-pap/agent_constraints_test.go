// agent_constraints_test.go proves the HTTP wiring for agent_constraints.go
// -- the same thin decode/call/respond proof agent_caps_test.go gives its
// own resource. internal/store/agent_constraints_test.go covers
// SetAgentResourceConstraints/ClearAgentResourceConstraints/
// GetAgentResourceConstraints's own validation and view-assembly logic
// exhaustively; this file only proves the route decodes, calls, and
// responds correctly.
package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"database/sql"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// expectAgentForConstraints registers the sqlmock sequence for the GetAgent
// call GetAgentResourceConstraints makes to read the agent's CURRENT stored
// resource_constraints -- begin, set tenant, the row, commit. Distinct from
// agent_caps_test.go's own expectAgentForCaps, which hardcodes
// resource_constraints to {}: GetAgentResourceConstraints's first read is
// the one place this file needs to control that column's actual stored
// value.
func expectAgentForConstraints(mock sqlmock.Sqlmock, id uuid.UUID, resourceConstraints map[string]string) {
	constraintsJSON, err := json.Marshal(resourceConstraints)
	if err != nil {
		panic(err)
	}
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM agents").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "name", "provider", "model_id",
			"trust_tier", "enabled", "suspended", "allowed_tools", "classification_caps", "resource_constraints", "created_at", "updated_at", "escalate_at"}).
			AddRow(id.String(), "test-tenant", "scoped-bot", "anthropic", "claude-opus",
				int64(models.TrustTierCertified), true, false, []byte(`null`), []byte(`{}`), constraintsJSON, now, now, nil))
	mock.ExpectCommit()
}

// TestPutAgentConstraints_Success follows SetAgentResourceConstraints' real
// call order (internal/store/agent_constraints.go): writeAgentConstraints
// (expectWriteAndAudit), then agentConstraintsView's own three reads --
// GetAgent (expectAgentForCaps), the catalog, and the live-delegation
// count.
func TestPutAgentConstraints_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectGrantWriteAndAudit(f.mock, "resource_constraints", `{}`, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAgentForCaps(f.mock, id, nil, nil)
	expectCatalog(f.mock, nil)
	expectLiveDelegations(f.mock, 0)

	body := map[string]any{"resource_constraints": map[string]string{models.ResourceIDPrefixKey: "/workspace/"}}
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+id.String()+"/resource-constraints", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentConstraintsView](t, rec)
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("resource_constraints = %v", got.ResourceConstraints)
	}
	assertExpectationsMet(t, f.mock)
}

// TestPutAgentConstraints_MissingTrailingSlashRejected proves the handler
// propagates validateResourceConstraints' refusal (internal/store) rather
// than swallowing it: "/workspace" without a trailing slash never reaches
// the database at all (zero mock expectations registered).
func TestPutAgentConstraints_MissingTrailingSlashRejected(t *testing.T) {
	f := newTestServerFixture(t)

	body := map[string]any{"resource_constraints": map[string]string{models.ResourceIDPrefixKey: "/workspace"}}
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/resource-constraints", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // never reached the store's write path
}

// TestPutAgentConstraints_MissingFieldRejected proves an absent
// resource_constraints field is refused with a 400 rather than decoding to a
// nil map and sailing through validateResourceConstraints (zero iterations,
// nothing to reject) to wipe the agent's scope -- the defect this handler's
// nil check (agent_constraints.go) closes. Zero mock expectations
// registered: the request must never reach the store.
func TestPutAgentConstraints_MissingFieldRejected(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/resource-constraints", f.token(t, "org-admins"),
		map[string]any{})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // never reached the store's write path
}

// TestPutAgentConstraints_ExplicitEmptyMapAccepted proves an operator who
// deliberately sends "resource_constraints": {} -- as opposed to omitting
// the field -- still succeeds: that is a legitimate way to set the scope to
// unrestricted, distinct from the omitted-field case above, the same
// nil-vs-present-empty distinction ErrAllowedToolsRequired draws
// (internal/store/agent.go).
func TestPutAgentConstraints_ExplicitEmptyMapAccepted(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectGrantWriteAndAudit(f.mock, "resource_constraints", `{}`, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAgentForCaps(f.mock, id, nil, nil)
	expectCatalog(f.mock, nil)
	expectLiveDelegations(f.mock, 0)

	body := map[string]any{"resource_constraints": map[string]string{}}
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+id.String()+"/resource-constraints", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestGetAgentConstraints_ReturnsStoredValue follows GetAgentResourceConstraints'
// real call order: GetAgent (expectAgentForConstraints, for the stored
// scope), then agentConstraintsView's own second GetAgent (expectAgentForCaps,
// for AllowedTools), the catalog, and the live-delegation count.
func TestGetAgentConstraints_ReturnsStoredValue(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectAgentForConstraints(f.mock, id, map[string]string{models.ResourceIDPrefixKey: "/workspace/"})
	expectAgentForCaps(f.mock, id, nil, nil)
	expectCatalog(f.mock, nil)
	expectLiveDelegations(f.mock, 1)

	rec := doRequest(t, f.server, http.MethodGet,
		"/v1/agents/"+id.String()+"/resource-constraints", f.token(t, "org-viewers"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentConstraintsView](t, rec)
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("resource_constraints = %v, want the stored value", got.ResourceConstraints)
	}
	if got.LiveDelegations != 1 {
		t.Errorf("live_delegations = %d, want 1", got.LiveDelegations)
	}
	assertExpectationsMet(t, f.mock)
}

// TestGetAgentConstraints_UnknownAgentNotFound proves an unknown agent id
// maps to 404 -- indistinguishable, by design, from what another tenant's
// agent id also returns, since beginTenantTx scopes every read to the
// caller's own tenant.
func TestGetAgentConstraints_UnknownAgentNotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM agents").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet,
		"/v1/agents/"+id.String()+"/resource-constraints", f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	assertExpectationsMet(t, f.mock)
}

func TestDeleteAgentConstraints_ClearsAndReturns204(t *testing.T) {
	f := newTestServerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	expectGrantWriteAndAudit(f.mock, "resource_constraints", `{}`, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	rec := doRequest(t, f.server, http.MethodDelete,
		"/v1/agents/"+uuid.New().String()+"/resource-constraints", f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// Editor may rename an agent but must not set its resource-constraint
// ceiling -- the same reasoning TestPutAgentCaps_EditorForbidden documents
// for classification caps.
func TestPutAgentConstraints_EditorForbidden(t *testing.T) {
	f := newTestServerFixture(t)
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/resource-constraints",
		f.token(t, "org-editors"),
		map[string]any{"resource_constraints": map[string]string{models.ResourceIDPrefixKey: "/workspace/"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	assertExpectationsMet(t, f.mock) // never reached the store
}

// Editor may rename an agent but must not clear its resource-constraint
// ceiling either -- deleteAgentConstraints' own DELETE counterpart.
func TestDeleteAgentConstraints_EditorForbidden(t *testing.T) {
	f := newTestServerFixture(t)
	rec := doRequest(t, f.server, http.MethodDelete,
		"/v1/agents/"+uuid.New().String()+"/resource-constraints", f.token(t, "org-editors"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	assertExpectationsMet(t, f.mock) // never reached the store
}
