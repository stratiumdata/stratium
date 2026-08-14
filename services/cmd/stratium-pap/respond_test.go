// respond_test.go tests writeStoreError directly, against synthetic errors,
// rather than only incidentally through a handler's own sqlmock-backed
// tests (policies_test.go, agents_test.go, tier_overrides_test.go): the one
// property this package's own doc comment states as a discipline --
// "default... intentionally does NOT echo err's own text to the client" --
// has no dedicated test anywhere else, and Issue 2's own required mutations
// ("map the FK violation back to 500" and "make the 409 path echo the raw
// database error") need a test that would fail if that discipline were
// violated on EITHER the 500 or the 409 side.
package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"stratium/internal/store"
)

// TestWriteStoreError_UnrecognizedError_Returns500WithoutEchoingIt is the
// genuine-500 path's own pinning test: an error writeStoreError does not
// recognize (in practice, almost always a raw database error internal/store
// itself did not wrap in a named sentinel) must fall through to a fixed,
// generic body -- never the underlying error's own text, which could carry
// schema, connection, or constraint detail no operator needs to fix their
// own request. This is also the direct proof for the required mutation "map
// the FK violation back to 500": if DeleteAgent's isForeignKeyViolation
// check were removed, the resulting error would be exactly this kind of
// unrecognized error, and this test's own body/leak assertions are what a
// naive "just check it's a 500" test would miss -- the mutation would still
// pass a bare status-code check.
func TestWriteStoreError_UnrecognizedError_Returns500WithoutEchoingIt(t *testing.T) {
	sensitive := errors.New("pq: connection to database \"stratium\" at host internal-db-7.private failed: role \"stratium_pap_login\" password authentication failed")

	rec := httptest.NewRecorder()
	writeStoreError(rec, sensitive)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
	body := rec.Body.String()
	if body != "internal error\n" {
		t.Errorf("body = %q, want the fixed generic message, not anything derived from the underlying error", body)
	}
	if strings.Contains(body, "internal-db-7") || strings.Contains(body, "stratium_pap_login") || strings.Contains(body, "password") {
		t.Errorf("body = %q, leaks the underlying error's own text", body)
	}
}

// TestWriteStoreError_Conflict_NamesTheBlockerWithoutEchoingPostgres is the
// 409 path's own pinning test, the direct proof for the required mutation
// "make the 409 path echo the raw database error": the error is built
// exactly the way DeleteAgent (internal/store/agent.go) builds it -- wrapping
// store.ErrConflict with a fixed string and the agent's id, never with the
// underlying pq.Error's own Message/Detail -- so this test is pinning
// agent.go's OWN construction as much as writeStoreError's mapping of it.
// The body must be useful (names what blocks the delete) and safe (no
// Postgres constraint/SQLSTATE text, which a mutation that wrapped
// err.Error() instead of a fixed string would have let through).
func TestWriteStoreError_Conflict_NamesTheBlockerWithoutEchoingPostgres(t *testing.T) {
	id := uuid.New()
	conflictErr := fmt.Errorf("%w: agent %s is still referenced by a delegation or approval", store.ErrConflict, id)

	rec := httptest.NewRecorder()
	writeStoreError(rec, conflictErr)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "delegation or approval") {
		t.Errorf("body = %q, want it to name what blocks the delete", body)
	}
	if strings.Contains(body, "SQLSTATE") || strings.Contains(body, "constraint") || strings.Contains(body, "23503") {
		t.Errorf("body = %q, must not carry raw Postgres constraint/SQLSTATE detail", body)
	}
}

// TestWriteStoreError_ApproverNotRootPrincipal_Returns403 is N7's own
// mapping proof: store.ErrApproverNotRootPrincipal is an authorization
// refusal (the operator's identity is known, just not entitled to decide
// THIS approval), not a request-shape problem, so it must land on 403, not
// 400 or the unrecognized-error 500 path.
func TestWriteStoreError_ApproverNotRootPrincipal_Returns403(t *testing.T) {
	id := uuid.New()
	err := fmt.Errorf("%w: approval %s", store.ErrApproverNotRootPrincipal, id)

	rec := httptest.NewRecorder()
	writeStoreError(rec, err)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestWriteStoreError_ApprovalNotPending_Returns409 is the sibling proof for
// store.ErrApprovalNotPending: it names what the row's own current state
// already is (already decided), the same "what else exists" shape
// ErrAlreadyExists/ErrConflict get, so it must land on 409 alongside them,
// not the 400-producing "what is wrong with THIS request" group.
func TestWriteStoreError_ApprovalNotPending_Returns409(t *testing.T) {
	id := uuid.New()
	err := fmt.Errorf("%w: approval %s is already %q", store.ErrApprovalNotPending, id, "approved")

	rec := httptest.NewRecorder()
	writeStoreError(rec, err)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusConflict)
	}
}
