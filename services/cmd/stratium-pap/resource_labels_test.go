// resource_labels_test.go proves the HTTP wiring for resource_labels.go --
// the same thin decode/call/respond proof policies_test.go, agents_test.go
// and tier_overrides_test.go give their own resources -- plus this resource's
// own role boundaries, exercised route by route rather than inferred from
// routeTable's MinRole values (server_test.go's
// TestRouteTable_RoleGatingMatchesSpec proves the DATA; this file proves the
// requests).
//
// internal/store/resource_label_test.go covers validateResourceLabelRule
// exhaustively, for both write paths. This file's job is only to prove that a
// level outside its hierarchy reaches an HTTP caller as 400 through the real
// route, on BOTH the create and the update, without anything here having its
// own opinion about what a legal hierarchy is.
package main

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// resourceLabelRuleColumns is listResourceLabelRulesQuery's own column list
// (internal/store/resource_label.go), duplicated here rather than imported for
// the reason policyListColumns is: it is unexported, in a different package,
// and this file only ever needs result sets shaped like it.
func resourceLabelRuleColumns() []string {
	return []string{"id", "tenant_id", "prefix", "hierarchy", "level"}
}

func expectEmptyResourceLabelRuleList(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM resource_label_rules").WillReturnRows(sqlmock.NewRows(resourceLabelRuleColumns()))
	mock.ExpectCommit()
}

// expectResourceLabelRuleWriteAndAudit is expectWriteAndAudit's counterpart for
// this table's INSERT/UPDATE, which return only id rather than a full row.
func expectResourceLabelRuleWriteAndAudit(mock sqlmock.Sqlmock, writeQueryFragment string, id uuid.UUID) {
	expectWriteAndAudit(mock, writeQueryFragment, sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
}

func TestCreateResourceLabelRule_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectResourceLabelRuleWriteAndAudit(f.mock, "INSERT INTO resource_label_rules", id)

	body := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/resource-label-rules", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got := decodeBody[models.ResourceLabelRule](t, rec)
	if got.ID != id {
		t.Errorf("response ID = %s, want %s -- the id is the handle the update and delete routes name, and a "+
			"create that withheld it would leave the rule addressable only by listing", got.ID, id)
	}
	if got.Prefix != body.Prefix || got.Hierarchy != body.Hierarchy || got.Level != body.Level {
		t.Errorf("response = %+v, want the submitted rule echoed back", got)
	}

	assertExpectationsMet(t, f.mock)
}

// R7's catch-all, through the real route: a body with no "prefix" at all
// decodes to the empty string and must be ACCEPTED, unlike every other create
// in this package where an empty required field is refused. This is the one
// test that would fail if anyone added a reflexive required-field guard to
// createResourceLabelRule -- and the rule it protects is the answer an operator
// needs when enabling a cap makes everything deny.
func TestCreateResourceLabelRule_EmptyPrefixCatchAllAccepted(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectResourceLabelRuleWriteAndAudit(f.mock, "INSERT INTO resource_label_rules", id)

	// Deliberately a map with no "prefix" key rather than a struct with an
	// empty one: an operator's catch-all request is written by omitting the
	// field, and a guard rejecting `"prefix": ""` would still let this through
	// (or vice versa) if the two were not the same path.
	body := map[string]any{"hierarchy": "commercial", "level": "PUBLIC"}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/resource-label-rules", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d (the empty prefix is R7's catch-all, not a missing field), body = %s",
			rec.Code, http.StatusCreated, rec.Body.String())
	}
	if got := decodeBody[models.ResourceLabelRule](t, rec); got.Prefix != "" {
		t.Errorf("response Prefix = %q, want the empty catch-all prefix", got.Prefix)
	}

	assertExpectationsMet(t, f.mock)
}

// A level that is not a level of its hierarchy is refused before anything is
// written, on BOTH write paths. The zero-expectation mock is what proves
// "before": a request that reached the database would fail as an unexpected
// query rather than pass this assertion.
//
// Both paths from one table on purpose. The single most important property of
// this task is that create and update share ONE validator, and a test that
// exercised only create would leave a second, drifting copy behind update
// entirely undetected -- which is exactly the failure mode migrations/000019
// rejected a duplicate CHECK constraint to avoid.
//
// "PUBLIC" under "nato" is a REAL level of a REAL hierarchy, just not that one:
// a weaker check asking only "is this string a level somewhere?" accepts it.
func TestResourceLabelRuleWrites_LevelOutsideItsHierarchyRefused_NothingPersisted(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"create", http.MethodPost, "/v1/resource-label-rules"},
		{"update", http.MethodPut, "/v1/resource-label-rules/" + uuid.New().String()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestServerFixture(t)

			body := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "PUBLIC"}
			rec := doJSONRequest(t, f.server, tt.method, tt.path, f.token(t, "org-editors"), body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			// The store's own message, surfaced rather than replaced: this
			// handler has no vocabulary of hierarchies to write a message
			// with, and an opaque "invalid rule" would strip the one thing
			// R9 says this check is worth.
			if body := rec.Body.String(); !containsAll(body, "PUBLIC", "nato", "TOP-SECRET") {
				t.Errorf("body = %q, want the store's own error naming the level, the hierarchy, and that "+
					"hierarchy's real levels", body)
			}

			assertExpectationsMet(t, f.mock) // zero expectations: nothing reached the database
		})
	}
}

func TestUpdateResourceLabelRule_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectResourceLabelRuleWriteAndAudit(f.mock, "UPDATE resource_label_rules", id)

	body := models.ResourceLabelRule{Prefix: "/data/reports/", Hierarchy: "nato", Level: "TOP-SECRET"}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/resource-label-rules/"+id.String(), f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.ResourceLabelRule](t, rec)
	if got.ID != id || got.Prefix != body.Prefix || got.Level != body.Level {
		t.Errorf("response = %+v, want the replaced rule at id %s", got, id)
	}

	assertExpectationsMet(t, f.mock)
}

func TestGetResourceLabelRule_NotFound(t *testing.T) {
	f := newTestServerFixture(t)

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM resource_label_rules").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/resource-label-rules/"+uuid.New().String(), f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

// The delete's own sequence differs from every other resource's: between the
// DELETE and the audit append sits a read of the SURVIVING rules, which is what
// the audit entry's blast-radius report is computed from (see
// DeleteResourceLabelRule's own doc comment). Queuing it here is what proves
// that read happens inside the write's transaction rather than after it.
func TestDeleteResourceLabelRule_Success(t *testing.T) {
	f := newTestServerFixture(t)

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("DELETE FROM resource_label_rules").
		WillReturnRows(sqlmock.NewRows([]string{"prefix", "hierarchy", "level"}).AddRow("/data/", "nato", "SECRET"))
	f.mock.ExpectQuery("SELECT prefix, hierarchy, level FROM resource_label_rules").
		WillReturnRows(sqlmock.NewRows([]string{"prefix", "hierarchy", "level"}))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/resource-label-rules/"+uuid.New().String(), f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusNoContent, rec.Body.String())
	}

	assertExpectationsMet(t, f.mock)
}

// --- Role boundaries, route by route ------------------------------------
//
// The mapping, stated: viewer reads (GET list, GET by id); editor reads and
// writes (POST, PUT); admin reads, writes, and deletes (DELETE). Identical to
// policies, agents and tier-overrides -- see routeTable's own comment for why
// this resource takes the blanket shape rather than an exception, and in
// particular why DELETE at admin is the floor that earns the most here: every
// other DELETE in this system removes something permissive, and this one
// removes a label, which under R2/R7 turns allows into denials.
//
// Each case below is a REQUEST, not an inspection of routeTable. Both matter
// and neither substitutes for the other: server_test.go's
// TestRouteTable_RoleGatingMatchesSpec proves the table's MinRole values are
// right, and this proves authorize actually enforces them on these five paths.

func TestResourceLabelRuleRoutes_SufficientRoleReachesHandler(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		group  string
		// needsEmptyList marks the one route shape with no body to refuse on
		// and no path id to reject: the GET list reaches the store, so it
		// needs a result set to read. Every other case below 400s inside its
		// own handler (no body for POST/PUT, a non-UUID id for the {id}
		// routes), which still proves the request got past authorize.
		needsEmptyList bool
	}{
		{"viewer lists", http.MethodGet, "/v1/resource-label-rules", "org-viewers", true},
		{"viewer reads one", http.MethodGet, "/v1/resource-label-rules/abc-123", "org-viewers", false},
		{"editor creates", http.MethodPost, "/v1/resource-label-rules", "org-editors", false},
		{"editor updates", http.MethodPut, "/v1/resource-label-rules/abc-123", "org-editors", false},
		{"admin deletes", http.MethodDelete, "/v1/resource-label-rules/abc-123", "org-admins", false},
		// Every role also meets every route with a lower minimum.
		{"editor reads too", http.MethodGet, "/v1/resource-label-rules", "org-editors", true},
		{"admin writes too", http.MethodPost, "/v1/resource-label-rules", "org-admins", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newTestServerFixture(t)
			if tt.needsEmptyList {
				expectEmptyResourceLabelRuleList(f.mock)
			}
			rec := doRequest(t, f.server, tt.method, tt.path, f.token(t, tt.group))
			if !reachedHandler(rec.Code) {
				t.Errorf("%s %s as %s: status = %d, want anything but 401/403", tt.method, tt.path, tt.group, rec.Code)
			}
		})
	}
}

// The refusals, including the one this resource cares about most: an EDITOR
// cannot delete. A label rule is the one row in this system whose removal
// turns allows into denials, so the ceiling matters as much as the floor --
// "let editor delete" is a required mutation for this task, and this is its
// designated catcher at the request layer.
func TestResourceLabelRuleRoutes_InsufficientRoleRefused(t *testing.T) {
	f := newTestServerFixture(t)

	tests := []struct {
		name   string
		method string
		path   string
		group  string
	}{
		{"viewer cannot create", http.MethodPost, "/v1/resource-label-rules", "org-viewers"},
		{"viewer cannot update", http.MethodPut, "/v1/resource-label-rules/abc-123", "org-viewers"},
		{"viewer cannot delete", http.MethodDelete, "/v1/resource-label-rules/abc-123", "org-viewers"},
		{"editor cannot delete", http.MethodDelete, "/v1/resource-label-rules/abc-123", "org-editors"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doRequest(t, f.server, tt.method, tt.path, f.token(t, tt.group))
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s: status = %d, want %d", tt.method, tt.path, tt.group, rec.Code, http.StatusForbidden)
			}
		})
	}

	// No expectations were ever registered on this fixture's mock, so every
	// refusal above also proves nothing reached the database -- a 403 that had
	// nonetheless written a row would be a quieter and worse defect than a
	// missing 403.
	assertExpectationsMet(t, f.mock)
}
