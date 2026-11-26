// policies_test.go proves the HTTP wiring for policies.go: a request
// decodes, reaches the right internal/store method, and its result (or
// error) becomes the right response. internal/store/policy_test.go already
// covers CreatePolicy/UpdatePolicy's own validation and audit-atomicity
// exhaustively; these tests do not repeat that depth, only confirm this
// package's own thin layer forwards correctly. TestIntegration_PAPCRUD_*
// (pap_crud_integration_test.go, build-tagged integration) is the real,
// live-Postgres round trip.
package main

import (
	"database/sql"
	"net/http"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/policy/cedar"
	"github.com/stratiumdata/stratium/internal/policy/jsonpolicy"
	"github.com/stratiumdata/stratium/internal/policy/rego"
	"github.com/stratiumdata/stratium/internal/policy/xacml"
	"github.com/stratiumdata/stratium/pkg/models"
)

// newPolicyTestFixture builds on newTestServerFixture (server_test.go),
// replacing its deliberately empty Registry with the four real engines:
// every other test in this package only needs role gating, which does not
// depend on which engines are wired, but these tests specifically exercise
// CreatePolicy/UpdatePolicy's own Validate call and need the genuine
// engines to validate against -- the same reason internal/store/
// policy_test.go's own testRegistry exists. Reassigning f.server.registry
// directly (both types live in this package) avoids re-deriving
// newTestServerFixture's own IdP/verifier/role-mapping/sqlmock wiring a
// second time for one field.
func newPolicyTestFixture(t *testing.T) *testServerFixture {
	t.Helper()
	f := newTestServerFixture(t)
	f.server.registry = policy.Registry{"cedar": cedar.New(), "json": jsonpolicy.New(), "rego": rego.New(), "xacml": xacml.New()}
	return f
}

func TestCreatePolicy_Success(t *testing.T) {
	f := newPolicyTestFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(f.mock, "INSERT INTO policies",
		sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))

	body := models.Policy{Name: "p1", Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: true}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got := decodeBody[models.Policy](t, rec)
	if got.ID != id {
		t.Errorf("response ID = %s, want %s", got.ID, id)
	}

	assertExpectationsMet(t, f.mock)
}

// TestCreatePolicy_InvalidPolicyRefused_NothingPersisted is the HTTP-level
// instance of Property 2, end to end through JSON: a Rego policy with a
// typo'd package -- the task brief's own named example -- must be refused
// with 400, and (the zero-expectation mock proves it) never reach the
// database at all.
func TestCreatePolicy_InvalidPolicyRefused_NothingPersisted(t *testing.T) {
	f := newPolicyTestFixture(t)

	body := models.Policy{
		Name: "dead-on-arrival", Language: "rego",
		Text:   "package stratium.polic\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}",
		Effect: "allow",
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // zero expectations: nothing reached the database
}

// TestCreatePolicy_EffectMismatch_Refused_NothingPersisted is Issue 1's
// HTTP-level instance, the same shape as InvalidPolicyRefused_
// NothingPersisted just above but for effect/text disagreement rather than
// a dead policy: a Cedar permit(...) statement declares "allow"; this
// request claims "deny". Must be refused with 400 (a request the operator
// can fix), never reach the database, and never a mismatch story an
// operator has to reverse-engineer from a generic error.
func TestCreatePolicy_EffectMismatch_Refused_NothingPersisted(t *testing.T) {
	f := newPolicyTestFixture(t)

	body := models.Policy{
		Name: "contradicts-its-own-text", Language: "cedar",
		Text: `permit(principal, action, resource);`, Effect: "deny",
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // zero expectations: nothing reached the database
}

func TestGetPolicy_NotFound(t *testing.T) {
	f := newPolicyTestFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM policies").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/policies/"+id.String(), f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestGetPolicy_InvalidID(t *testing.T) {
	f := newPolicyTestFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/policies/not-a-uuid", f.token(t, "org-viewers"))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock) // never reached the store at all
}

func TestUpdatePolicy_Success(t *testing.T) {
	f := newPolicyTestFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	expectWriteAndAudit(f.mock, "UPDATE policies",
		sqlmock.NewRows([]string{"version", "created_at", "updated_at"}).AddRow(int64(2), now, now))

	body := models.Policy{Name: "renamed", Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: false}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+id.String(), f.token(t, "org-admins"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.Policy](t, rec)
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2", got.Version)
	}
}

func TestDeletePolicy_Success(t *testing.T) {
	f := newPolicyTestFixture(t)
	id := uuid.New()
	expectDeleteAndAudit(f.mock, "DELETE FROM policies", "name", "doomed-policy")

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/policies/"+id.String(), f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	assertExpectationsMet(t, f.mock)
}

// expectPolicyProtectedRead is what an editor's policy update reads first, in
// its own transaction: whether an admin has protected the policy.
func expectPolicyProtectedRead(mock sqlmock.Sqlmock, protected bool) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT protected FROM policies WHERE id = \$1 FOR UPDATE`).
		WillReturnRows(sqlmock.NewRows([]string{"protected"}).AddRow(protected))
}

// An admin can protect a policy. An editor can then neither rewrite nor
// disable it: the rule it states stays until an admin says otherwise.
func TestUpdatePolicy_EditorCannotChangeAProtectedPolicy(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectPolicyProtectedRead(f.mock, true)
	f.mock.ExpectRollback()

	body := models.Policy{Name: "reserved", Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: false}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+uuid.NewString(), f.token(t, "org-editors"), body)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if body := rec.Body.String(); !containsAll(body, "admin", "protected") {
		t.Errorf("body = %q, want it to say the policy is protected and an admin is needed", body)
	}
	assertExpectationsMet(t, f.mock) // no UPDATE, no audit row
}

func TestUpdatePolicy_EditorChangesAnUnprotectedPolicy(t *testing.T) {
	f := newPolicyTestFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	expectPolicyProtectedRead(f.mock, false)
	f.mock.ExpectQuery("UPDATE policies").
		WillReturnRows(sqlmock.NewRows([]string{"version", "created_at", "updated_at"}).AddRow(int64(2), now, now))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	body := models.Policy{Name: "renamed", Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: true}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+uuid.NewString(), f.token(t, "org-editors"), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

func TestSetPolicyProtection(t *testing.T) {
	t.Run("an admin protects a policy", func(t *testing.T) {
		f := newPolicyTestFixture(t)
		id := uuid.New()
		expectWriteAndAudit(f.mock, "UPDATE policies SET protected",
			sqlmock.NewRows([]string{"name"}).AddRow("reserved-for-alice"))

		rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+id.String()+"/protection",
			f.token(t, "org-admins"), map[string]any{"protected": true})
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		got := decodeBody[models.PolicyProtectionView](t, rec)
		if got.PolicyID != id || !got.Protected {
			t.Errorf("response = %+v, want policy %s protected", got, id)
		}
		assertExpectationsMet(t, f.mock)
	})
	t.Run("an editor cannot", func(t *testing.T) {
		f := newPolicyTestFixture(t)
		rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+uuid.NewString()+"/protection",
			f.token(t, "org-editors"), map[string]any{"protected": false})
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		assertExpectationsMet(t, f.mock)
	})
	t.Run("the value must be stated", func(t *testing.T) {
		f := newPolicyTestFixture(t)
		rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/policies/"+uuid.NewString()+"/protection",
			f.token(t, "org-admins"), map[string]any{})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
		assertExpectationsMet(t, f.mock)
	})
}
