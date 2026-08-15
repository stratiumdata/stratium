// tier_overrides_test.go proves the HTTP wiring for tier_overrides.go --
// the same thin decode/call/respond proof policies_test.go and
// agents_test.go give their own resources.
// internal/store/tier_override_test.go covers CreateTierOverride/
// UpdateTierOverride's own raise-only enforcement exhaustively; this file's
// job is only to prove a lowering override reaches an HTTP caller as 400
// through the real route, not to re-derive the property itself.
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

// expectTierOverrideBaselineRead queues the two SELECTs
// store.CreateTierOverride/UpdateTierOverride perform inside the write's own
// transaction. The raise-only rule compares against the resolution BENEATH the
// override, and two tables make up that resolution: the tenant's own
// tool_catalog, and its other tier_overrides rows — deriveTierByName probes
// overrides at every slot before any catalog lookup, so a sibling row at a
// less specific key really does sit beneath this one. Empty results are the
// "tenant has configured nothing" case, under which the baselines below are
// DefaultCatalog()'s.
func expectTierOverrideBaselineRead(mock sqlmock.Sqlmock) {
	mock.ExpectQuery("FROM tool_catalog").WillReturnRows(
		sqlmock.NewRows([]string{"tool_name", "action_tier", "verb", "resource_field", "command_field"}))
	mock.ExpectQuery("FROM tier_overrides").WillReturnRows(
		sqlmock.NewRows([]string{"tool_or_verb", "action_tier"}))
}

// expectTierOverrideRefusedAfterBaselineRead is the shape a refused write now
// takes: the transaction opens and the baseline is read, then nothing else
// happens. Before Task 7 a refusal reached the database not at all, because
// the baseline was a pure function; the property that matters is unchanged
// and still asserted — no write query is ever queued, so a write reaching one
// fails as an unexpected query.
func expectTierOverrideRefusedAfterBaselineRead(mock sqlmock.Sqlmock) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	expectTierOverrideBaselineRead(mock)
	mock.ExpectRollback()
}

func TestCreateTierOverride_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	expectTierOverrideBaselineRead(f.mock)
	f.mock.ExpectQuery("INSERT INTO tier_overrides").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(id.String(), now))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	// "Read"'s built-in is READ_ONLY (1); raising to INTERNAL_MODIFY (2)
	// is legitimate.
	body := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierInternalModify}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/tier-overrides", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	got := decodeBody[models.TierOverride](t, rec)
	if got.ID != id {
		t.Errorf("response ID = %s, want %s", got.ID, id)
	}
	if got.BuiltinTier != models.ActionTierReadOnly {
		t.Errorf("BuiltinTier = %s, want %s (server-computed)", got.BuiltinTier, models.ActionTierReadOnly)
	}

	assertExpectationsMet(t, f.mock)
}

// TestCreateTierOverride_LoweringRefused_NothingPersisted is Property 3's
// own HTTP-level proof, end to end through the real route: "Write" has a
// built-in of INTERNAL_MODIFY (2); declaring it READ_ONLY (1) is exactly
// the "declare a destructive action harmless" attempt server-side
// derivation exists to prevent (task brief's own wording). The expectations
// stop at the baseline read, so nothing was ever written.
func TestCreateTierOverride_LoweringRefused_NothingPersisted(t *testing.T) {
	f := newTestServerFixture(t)
	expectTierOverrideRefusedAfterBaselineRead(f.mock)

	body := models.TierOverride{ToolOrVerb: "Write", ActionTier: models.ActionTierReadOnly}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/tier-overrides", f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

func TestGetTierOverride_NotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM tier_overrides").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	rec := doRequest(t, f.server, http.MethodGet, "/v1/tier-overrides/"+id.String(), f.token(t, "org-viewers"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestUpdateTierOverride_LoweringRefused(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectTierOverrideRefusedAfterBaselineRead(f.mock)

	body := models.TierOverride{ToolOrVerb: "Write", ActionTier: models.ActionTierReadOnly}
	rec := doJSONRequest(t, f.server, http.MethodPut, "/v1/tier-overrides/"+id.String(), f.token(t, "org-admins"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

func TestDeleteTierOverride_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	expectDeleteAndAudit(f.mock, "DELETE FROM tier_overrides", "tool_or_verb", "Bash")

	rec := doRequest(t, f.server, http.MethodDelete, "/v1/tier-overrides/"+id.String(), f.token(t, "org-admins"))
	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}

	assertExpectationsMet(t, f.mock)
}
