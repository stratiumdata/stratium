// agent_caps_test.go proves the HTTP wiring for agent_caps.go -- the same
// thin decode/call/respond proof agents_test.go gives its own resource.
// internal/store/agent_caps_test.go covers SetAgentClassificationCaps/
// ClearAgentClassificationCaps/GetAgentClassificationCaps's own validation
// and view-assembly logic exhaustively; this file only proves the route
// decodes, calls, and responds correctly.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// --- local sqlmock helpers ---
//
// internal/store/agent_caps_test.go already has expectLabelRules/
// expectCatalog/expectLiveDelegations/expectGetAgentRow, built against that
// package's own unexported query constants (listResourceLabelRulesQuery,
// listToolCatalogEntriesQuery, countLiveDelegationsQuery, getAgentQuery).
// This package cannot reach those -- a different package, and they are
// unexported -- so these are local, loose-regex-fragment equivalents: the
// same "fragment of the query text, not the exact literal" discipline
// crud_helpers_test.go's own expectWriteAndAudit already uses, for the
// identical reason (that comment's own explanation applies here verbatim).

// expectLabelRules registers the sqlmock sequence for the
// ListResourceLabelRules call SetAgentClassificationCaps and
// GetAgentClassificationCaps both make (via catchAllLevels) to resolve each
// hierarchy's catch-all level -- begin, set tenant, the rows, commit.
func expectLabelRules(mock sqlmock.Sqlmock, rules []models.ResourceLabelRule) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"id", "tenant_id", "prefix", "hierarchy", "level"})
	for _, r := range rules {
		rows.AddRow(uuid.New().String(), "test-tenant", r.Prefix, r.Hierarchy, r.Level)
	}
	mock.ExpectQuery("FROM resource_label_rules").WillReturnRows(rows)
	mock.ExpectCommit()
}

// expectCatalog registers the sqlmock sequence for the
// ListToolCatalogEntries call agentCapsView makes -- begin, set tenant, the
// rows, commit.
func expectCatalog(mock sqlmock.Sqlmock, entries []models.ToolCatalogEntry) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	rows := sqlmock.NewRows([]string{"id", "tenant_id", "tool_name", "action_tier", "verb", "resource_field", "command_field"})
	for _, e := range entries {
		var actionTier any
		if e.ActionTier != nil {
			actionTier = int64(*e.ActionTier)
		}
		var resourceField, commandField any
		if e.ResourceField != nil {
			resourceField = *e.ResourceField
		}
		if e.CommandField != nil {
			commandField = *e.CommandField
		}
		rows.AddRow(uuid.New().String(), "test-tenant", e.ToolName, actionTier, e.Verb, resourceField, commandField)
	}
	mock.ExpectQuery("FROM tool_catalog").WillReturnRows(rows)
	mock.ExpectCommit()
}

// expectLiveDelegations registers the sqlmock sequence for the
// countLiveDelegations call agentCapsView makes -- begin, set tenant, the
// count, commit.
func expectLiveDelegations(mock sqlmock.Sqlmock, count int) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM delegations").WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
	mock.ExpectCommit()
}

// expectAgentForCaps registers the sqlmock sequence for the GetAgent call
// agentCapsView makes to read the agent's current AllowedTools (Get's own
// direct GetAgentClassificationCaps call reuses this too) -- begin, set
// tenant, the row, commit. Columns this file's assertions never read (Name,
// Provider, ModelID, TrustTier, Enabled, Suspended) get fixed placeholders,
// mirroring internal/store/agent_caps_test.go's own expectGetAgentRow.
func expectAgentForCaps(mock sqlmock.Sqlmock, id uuid.UUID, allowedTools []string, classificationCaps map[string]string) {
	allowedToolsJSON, err := json.Marshal(allowedTools)
	if err != nil {
		panic(err)
	}
	capsJSON, err := json.Marshal(classificationCaps)
	if err != nil {
		panic(err)
	}
	now := time.Now()

	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM agents").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "name", "provider", "model_id",
			"trust_tier", "enabled", "suspended", "allowed_tools", "classification_caps", "created_at", "updated_at"}).
			AddRow(id.String(), "test-tenant", "caps-bot", "anthropic", "claude-opus",
				int64(models.TrustTierCertified), true, false, allowedToolsJSON, capsJSON, now, now))
	mock.ExpectCommit()
}

// TestPutAgentCaps_Success's mock sequence follows
// SetAgentClassificationCaps' real call order (agent_caps.go, internal/
// store): catchAllLevels (expectLabelRules), writeAgentCaps
// (expectWriteAndAudit), then agentCapsView's own three reads -- GetAgent
// (expectAgentForCaps), the catalog, and the live-delegation count.
func TestPutAgentCaps_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectLabelRules(f.mock, []models.ResourceLabelRule{{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"}})
	expectWriteAndAudit(f.mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAgentForCaps(f.mock, id, nil, nil)
	expectCatalog(f.mock, nil)
	expectLiveDelegations(f.mock, 0)

	body := map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}}
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+id.String()+"/classification-caps", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[models.AgentCapsView](t, rec)
	if got.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("caps = %v", got.ClassificationCaps)
	}
	if got.Applies != "at next issuance" {
		t.Errorf("applies = %q", got.Applies)
	}
	assertExpectationsMet(t, f.mock)
}

// Editor may rename an agent but must not set its classification ceiling.
func TestPutAgentCaps_EditorForbidden(t *testing.T) {
	f := newTestServerFixture(t)
	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/classification-caps",
		f.token(t, "org-editors"),
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	assertExpectationsMet(t, f.mock) // never reached the store
}

// The error body is a bare sentence, not JSON. Asserting this keeps clients
// honest: step 0d of the agent test plan piped curl into json.load and turned
// every failure into the same unreadable traceback.
func TestPutAgentCaps_NoCatchAllIsPlainTextConflict(t *testing.T) {
	f := newTestServerFixture(t)
	expectLabelRules(f.mock, []models.ResourceLabelRule{{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"}})

	rec := doJSONRequest(t, f.server, http.MethodPut,
		"/v1/agents/"+uuid.New().String()+"/classification-caps", f.token(t, "org-admins"),
		map[string]any{"classification_caps": map[string]string{"nato": "CONFIDENTIAL"}})

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409, body = %s", rec.Code, rec.Body.String())
	}
	if strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "{") {
		t.Errorf("body is JSON, want plain text: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "allow_uncovered") {
		t.Errorf("body does not name the override: %s", rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

func TestDeleteAgentCaps_ClearsAndReturns204(t *testing.T) {
	f := newTestServerFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(f.mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	rec := doRequest(t, f.server, http.MethodDelete,
		"/v1/agents/"+uuid.New().String()+"/classification-caps", f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204, body = %s", rec.Code, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}
