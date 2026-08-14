// crud_helpers_test.go holds sqlmock sequence builders shared by
// policies_test.go, agents_test.go, and tier_overrides_test.go: every
// Create/Update/Delete handler in this package ultimately calls an
// internal/store method that follows the identical begin / set-tenant /
// write / advisory-lock / tail-read / audit-insert / commit shape (that
// package's own appendAuditTx), so the MOCK sequence is identical across
// all three resources -- only the write query's own text differs, taken
// here as a loose regex fragment since this package cannot reach
// internal/store's unexported query constants (a different package, and
// there is no reason it should be able to).
package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// expectWriteAndAudit registers the ordered sqlmock sequence every
// Create/Update handler issues, ending with a full row scanned back via
// RETURNING (writeRows) -- what CreatePolicy/CreateAgent/CreateTierOverride
// and their Update counterparts all do.
func expectWriteAndAudit(mock sqlmock.Sqlmock, writeQueryFragment string, writeRows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(writeQueryFragment).WillReturnRows(writeRows)
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// expectDeleteAndAudit is expectWriteAndAudit's DELETE-shaped counterpart:
// the write step returns exactly one named column, the RETURNING value
// every Delete* method captures for its audit entry's Reason (a policy's
// name, an agent's name, a tier override's tool_or_verb).
func expectDeleteAndAudit(mock sqlmock.Sqlmock, deleteQueryFragment, returningColumn, returningValue string) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(deleteQueryFragment).
		WillReturnRows(sqlmock.NewRows([]string{returningColumn}).AddRow(returningValue))
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// doJSONRequest is doRequest's (server_test.go) body-carrying counterpart:
// every test in server_test.go only ever needed a nil body (proving role
// gating, which never inspects one), but a CRUD round-trip test needs to
// send an actual request payload.
func doJSONRequest(t *testing.T, server *Server, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	server.ServeHTTP(rec, req)
	return rec
}

// decodeBody unmarshals rec's body into a fresh v, failing the test loudly
// on a malformed response rather than letting a caller's own nil-pointer
// dereference obscure what actually went wrong.
func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return v
}

// assertExpectationsMet mirrors internal/store's own test helper of the
// same name: every registered sqlmock expectation must have been
// consumed, which is what proves a request that should never have reached
// the database (an invalid policy, a non-UUID path segment) truly did not.
func assertExpectationsMet(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}
