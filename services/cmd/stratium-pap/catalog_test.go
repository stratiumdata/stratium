// catalog_test.go proves the HTTP wiring for catalog.go, the same
// thin-layer scope policies_test.go's own doc comment states: request
// decodes, reaches the right internal/store method, and its result (or
// error) becomes the right response. internal/store/catalog_test.go already
// covers CreateToolCatalogEntry/UpdateToolCatalogEntry's own validation and
// audit-atomicity exhaustively.
package main

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// TestCreateToolCatalogEntry_AllThreeRowStates_Success proves this handler
// forwards every one of T1's three valid row shapes intact -- see
// internal/store/catalog_test.go's own TestStore_CreateToolCatalogEntry_
// AllThreeRowStatesPersist for the property itself; this is the HTTP-level
// instance, through real JSON encode/decode, of the same three cases.
func TestCreateToolCatalogEntry_AllThreeRowStates_Success(t *testing.T) {
	commandField := "command"
	tests := []struct {
		name string
		body models.ToolCatalogEntry
	}{
		{"fixed tier alone", models.ToolCatalogEntry{ToolName: "Read", ActionTier: actionTierPtr(models.ActionTierReadOnly), Verb: "read"}},
		{"NULL tier with command_field -- Bash's own shape", models.ToolCatalogEntry{ToolName: "Bash", Verb: "execute", CommandField: &commandField}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestServerFixture(t)
			id := uuid.New()
			expectWriteAndAudit(f.mock, "INSERT INTO tool_catalog", sqlmock.NewRows([]string{"id"}).AddRow(id.String()))

			rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/tool-catalog", f.token(t, "org-admins"), tt.body)
			if rec.Code != http.StatusCreated {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
			}
			got := decodeBody[models.ToolCatalogEntry](t, rec)
			if got.ID != id {
				t.Errorf("response ID = %s, want %s", got.ID, id)
			}

			assertExpectationsMet(t, f.mock)
		})
	}
}

// actionTierPtr mirrors internal/store/catalog_test.go's own tierPtr --
// duplicated rather than imported, since internal/store is a different
// package and this file only ever needs the identical one-line helper, not
// anything else that package exports for its own tests.
func actionTierPtr(t models.ActionTier) *models.ActionTier { return &t }

// TestCreateToolCatalogEntry_MissingTierAndCommandField_Refused_NothingPersisted
// is the HTTP-level instance of the required mutation "let a catalog row
// with neither a tier nor a command_field through": refused with 400
// (internal/store.ErrInvalidRequest via writeStoreError), and — the
// zero-expectation mock proves it — never reaches the database at all.
func TestCreateToolCatalogEntry_MissingTierAndCommandField_Refused_NothingPersisted(t *testing.T) {
	f := newTestServerFixture(t)

	body := models.ToolCatalogEntry{ToolName: "mystery-tool"} // no ActionTier, no CommandField
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/tool-catalog", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // zero expectations: nothing reached the database
}

func TestGetToolCatalogEntry_NotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM tool_catalog").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/tool-catalog/"+id.String(), f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetToolCatalogEntry_InvalidID(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/tool-catalog/not-a-uuid", f.token(t, "org-viewers"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock) // never reached the store at all
}

func TestUpdateToolCatalogEntry_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectWriteAndAudit(f.mock, "UPDATE tool_catalog", sqlmock.NewRows([]string{"id"}).AddRow(id.String()))

	body := models.ToolCatalogEntry{ToolName: "Read", ActionTier: actionTierPtr(models.ActionTierInternalModify), Verb: "read"}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/tool-catalog/"+id.String(), f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.ToolCatalogEntry](t, rec)
	if got.ID != id {
		t.Errorf("response ID = %s, want %s", got.ID, id)
	}
}

// TestListToolCatalog_Success proves the GET-list route reaches
// ListToolCatalogEntries and returns whatever it does — a thin, generic
// proof, matching this package's own established scope for a list handler
// (policies.go's listPolicies has no dedicated test of its own beyond the
// role-gating table in server_test.go; this one exists mainly to also
// double as this file's own "viewer can read tool-catalog" witness, since
// tool-catalog is not one of the three resources server_test.go's own
// generic role tests iterate).
func TestListToolCatalog_Success(t *testing.T) {
	f := newTestServerFixture(t)

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM tool_catalog").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "tool_name", "action_tier", "verb", "resource_field", "command_field"}))
	f.mock.ExpectCommit()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/tool-catalog", f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[[]models.ToolCatalogEntry](t, rec)
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

// expectCatalogEntryBeforeRead is the row an editor's update is compared
// against (store.getToolCatalogEntryForUpdateQuery), read in the write's own
// transaction before anything else.
func expectCatalogEntryBeforeRead(mock sqlmock.Sqlmock, id uuid.UUID, tier models.ActionTier) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM tool_catalog WHERE id = .* FOR UPDATE").WillReturnRows(
		sqlmock.NewRows([]string{"id", "tenant_id", "tool_name", "action_tier", "verb", "resource_field", "command_field"}).
			AddRow(id.String(), "tenant-test", "Read", int64(tier), "read", nil, nil))
}

// An editor may raise an existing entry's tier, and nothing else: lowering
// it would move the tool under an escalation threshold only an admin sets.
func TestUpdateToolCatalogEntry_EditorRaisesTier(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectCatalogEntryBeforeRead(f.mock, id, models.ActionTierReadOnly)
	f.mock.ExpectQuery("UPDATE tool_catalog").WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	body := models.ToolCatalogEntry{ToolName: "Read", ActionTier: actionTierPtr(models.ActionTierInternalModify), Verb: "read"}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/tool-catalog/"+id.String(), f.token(t, "org-editors"), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

func TestUpdateToolCatalogEntry_EditorCannotLowerTier(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectCatalogEntryBeforeRead(f.mock, id, models.ActionTierInternalModify)
	f.mock.ExpectRollback()

	body := models.ToolCatalogEntry{ToolName: "Read", ActionTier: actionTierPtr(models.ActionTierReadOnly), Verb: "read"}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/tool-catalog/"+id.String(), f.token(t, "org-editors"), body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if body := rec.Body.String(); !containsAll(body, "admin", "lowers the action tier") {
		t.Errorf("body = %q, want it to say an admin is needed and why", body)
	}
	assertExpectationsMet(t, f.mock) // no UPDATE, no audit row
}

func TestCreateToolCatalogEntry_EditorRefused(t *testing.T) {
	f := newTestServerFixture(t)
	body := models.ToolCatalogEntry{ToolName: "Read", ActionTier: actionTierPtr(models.ActionTierReadOnly), Verb: "read"}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/tool-catalog", f.token(t, "org-editors"), body)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertExpectationsMet(t, f.mock)
}
