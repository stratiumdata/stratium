// approvals_test.go proves the HTTP wiring for approvals.go, and — because
// this is the security-critical half of Task 4 (spec §4.10.1, N7/N8) — goes
// well past policies_test.go's own "thin layer" scope to prove the identity
// checks themselves hold at the HTTP boundary, not merely that a request
// reaches internal/store.DecideApproval. internal/store/approval_test.go
// already proves N7's comparison and the store's own error taxonomy
// exhaustively; these tests prove the SAME property survives real OIDC
// token minting, claim resolution, and role gating end to end.
package main

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// approvalFixtureRequestedAt/approvalFixtureExpiresAt are real time.Time
// values, not RFC3339 strings: database/sql's generic Scan only accepts a
// driver.Value that already IS a time.Time for a *time.Time destination
// (models.Approval.RequestedAt/ExpiresAt/ApprovedAt), the same requirement
// every other timestamp fixture in this codebase's sqlmock-backed tests
// already follows (e.g. internal/store/approval_test.go's own requestedAt
// local).
var (
	approvalFixtureRequestedAt = time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	approvalFixtureExpiresAt   = approvalFixtureRequestedAt.Add(time.Hour)
)

// approvalRowColumns is internal/store's own (unexported) approvalColumns
// reproduced here, in query-column order: id, tenant_id, agent_id,
// delegation_id, root_delegation_id, subject, root_principal, tool_name,
// action, derived_tier, input_digest, status, requested_at, expires_at,
// approved_by, approved_at. Duplicated rather than imported for the same
// reason server_test.go's own policyListColumns is: it is unexported, in a
// different package, and this file only ever needs a result set shaped
// like it.
func approvalRowColumns() []string {
	return []string{
		"id", "tenant_id", "agent_id", "delegation_id", "root_delegation_id",
		"subject", "root_principal", "tool_name", "action", "derived_tier",
		"input_digest", "status", "requested_at", "expires_at", "approved_by", "approved_at",
	}
}

// expectPendingApprovalLoad registers the ordered sqlmock sequence
// DecideApproval issues to load-and-lock one pending approval naming
// rootPrincipal: begin, set tenant, the FOR UPDATE load. A loose regex
// fragment ("FROM approvals"), not internal/store's exact unexported query
// text, matching crud_helpers_test.go's own established discipline for
// reaching across a package boundary.
func expectPendingApprovalLoad(mock sqlmock.Sqlmock, id uuid.UUID, rootPrincipal string) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM approvals").
		WillReturnRows(sqlmock.NewRows(approvalRowColumns()).AddRow(
			id.String(), fixtureTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
			"requesting-subject", rootPrincipal, "Bash", "execute", int64(models.ActionTierExternalComms),
			make([]byte, 32), "pending", approvalFixtureRequestedAt, approvalFixtureExpiresAt, nil, nil,
		))
}

// expectDecisionWriteAndAudit registers the ordered sqlmock sequence for the
// UPDATE half of a successful decision plus its audit entry -- the same
// shape expectWriteAndAudit (crud_helpers_test.go) gives every other write
// in this package, reused here rather than re-derived because the
// begin/set-tenant step already happened in expectPendingApprovalLoad above
// (DecideApproval issues both inside one transaction, not two).
func expectDecisionWriteAndAudit(mock sqlmock.Sqlmock) {
	mock.ExpectExec("UPDATE approvals").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// TestApproveApproval_IdentityMatchesRootPrincipal_Success is N7's positive
// case, live: an operator whose resolved ApproverIdentity (the "email"
// claim, this fixture's configured approverClaim) equals the loaded
// approval's own root_principal may approve, with a sufficient (admin) role.
func TestApproveApproval_IdentityMatchesRootPrincipal_Success(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	const rootPrincipal = "root@example.com"
	expectPendingApprovalLoad(f.mock, id, rootPrincipal)
	expectDecisionWriteAndAudit(f.mock)

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": rootPrincipal, "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestApproveApproval_WrongIdentity_RefusedEvenWithAdminRole is N7's own
// required, dedicated test (spec §4.10.1: "a role is necessary and never
// sufficient"; task brief: "one whose identity does not [match] is refused
// even with the admin role -- that is N7 and it needs its own test").
// The token below carries org-admins -- routeTable's own MinRole for this
// route, the highest role this system has -- and STILL must be refused,
// because ApproverIdentity ("impostor@example.com") does not equal the
// loaded approval's root_principal ("root@example.com"). Proven with no
// UPDATE or audit expectation registered at all: if N7's comparison were
// ever weakened to "any admin may decide," this test's mock would receive a
// call it was never told to expect and fail for that reason, not merely
// because this assertion checked a status code.
func TestApproveApproval_WrongIdentity_RefusedEvenWithAdminRole(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	const rootPrincipal = "root@example.com"
	expectPendingApprovalLoad(f.mock, id, rootPrincipal)
	f.mock.ExpectRollback() // load-and-lock only: N7 refuses before any UPDATE is attempted

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "impostor@example.com", "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (N7: known identity, not entitled to decide THIS approval), body = %s",
			rec.Code, http.StatusForbidden, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestApproveApproval_RequestBodyApproverFieldIsIgnored is the task brief's
// own instruction turned into a behavioral test: "load the approval and
// compare against its stored root_principal. Do not trust anything in the
// request to tell you who the approver should be." The operator's real
// identity ("impostor@example.com") does not match root_principal, so this
// must be refused -- but the request body ALSO carries a field naming the
// real root_principal outright, the shape a careless implementation might
// have read as an override ({"approved_by": ...} or {"root_principal": ...}
// taken from the body instead of the verified token). If decideApproval
// (approvals.go) ever grew a decodeJSON call and used any such field instead
// of op.ApproverIdentity, this is the test that would catch it: today,
// approveApproval/denyApproval read no request body at all, so a body is
// sent here specifically to prove one being present and attacker-favorable
// changes nothing.
func TestApproveApproval_RequestBodyApproverFieldIsIgnored(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	const rootPrincipal = "root@example.com"
	expectPendingApprovalLoad(f.mock, id, rootPrincipal)
	f.mock.ExpectRollback() // load-and-lock only: N7 refuses before any UPDATE is attempted

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "impostor@example.com", "email_verified": true})
	body := map[string]string{"approved_by": rootPrincipal, "root_principal": rootPrincipal}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok, body)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d -- a request body naming the correct root_principal must not override "+
			"the verified token's own identity, body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestApproveApproval_UnverifiedEmailClaim_Refused is N8's own required
// test: some IdPs let a caller self-assert "email" with no verification
// step behind it, which would otherwise let an operator claim to BE the
// root principal without an IdP actually vouching for it. email_verified is
// explicitly false here (not merely absent -- TestApproveApproval_
// NoEmailVerifiedClaim_Refused below covers that case too), yet the claimed
// email value is otherwise a byte-for-byte match for root_principal --
// proving the refusal is really about verification, not a values mismatch.
// Refused with 401 (an identity problem: N8's own claim resolution could not
// establish who this operator reliably is) BEFORE internal/store is ever
// reached -- no approvals-table expectation is registered at all, only the
// role check inherent to reaching authorize's own gate.
func TestApproveApproval_UnverifiedEmailClaim_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "root@example.com", "email_verified": false})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (N8: email_verified must be true when the configured claim is \"email\"), body = %s",
			rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // zero expectations: never reached internal/store at all
}

// TestApproveApproval_NoEmailVerifiedClaim_Refused is UnverifiedEmailClaim_
// Refused's own sibling for the claim being entirely ABSENT rather than
// explicitly false -- N8's own fail-closed requirement ("not verified by
// default"), and a real, plausible IdP response shape (many providers omit
// email_verified entirely for accounts where it does not apply, rather than
// sending it as false).
func TestApproveApproval_NoEmailVerifiedClaim_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "root@example.com"}) // no email_verified key at all
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestDenyApproval_RecordsDenied is the task brief's own required test: "an
// explicit deny records denied." Same identity-match precondition as
// approve (N7 draws no distinction between the two dispositions -- see
// internal/store.DecideApproval's own doc comment) but exercised through
// the /deny route and asserted against the response body's own Status.
func TestDenyApproval_RecordsDenied(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	const rootPrincipal = "root@example.com"
	expectPendingApprovalLoad(f.mock, id, rootPrincipal)
	f.mock.ExpectExec("UPDATE approvals").
		WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM audit_chain").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectExec("INSERT INTO audit_chain").WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectCommit()

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": rootPrincipal, "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/deny", tok)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[models.Approval](t, rec)
	if got.Status != "denied" {
		t.Errorf("Status = %q, want %q", got.Status, "denied")
	}
	assertExpectationsMet(t, f.mock)
}

// TestDecideApproval_EditorRole_Refused proves the role FLOOR itself: an
// editor -- sufficient for every other write route this package registers
// -- is refused 403 by authorize before ever reaching decideApproval, since
// routeTable gates this route at RoleAdmin (N7: "a role is necessary").
// TestApproveApproval_WrongIdentity_RefusedEvenWithAdminRole above is this
// test's own complement: together they prove the role check and the
// identity check are both required, and neither stands in for the other.
func TestDecideApproval_EditorRole_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	tok := f.tokenWithClaims(t, "org-editors", map[string]any{"email": "root@example.com", "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	assertExpectationsMet(t, f.mock) // never reached authorize's next() at all
}

func TestApproveApproval_InvalidID(t *testing.T) {
	f := newTestServerFixture(t)

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "root@example.com", "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/not-a-uuid/approve", tok)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock) // never reached the store at all
}

// TestApproveApproval_NotFound proves an id naming no row (or another
// tenant's, indistinguishable under RLS) surfaces as 404, matching every
// other Get/decide-shaped handler's own not-found treatment in this
// package.
func TestApproveApproval_NotFound(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM approvals").WillReturnError(sql.ErrNoRows)
	f.mock.ExpectRollback()

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "root@example.com", "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d, body = %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestApproveApproval_AlreadyDecided_Conflict proves internal/store.
// ErrApprovalNotPending maps to 409, matching writeStoreError's own doc
// comment on why it joins ErrAlreadyExists/ErrConflict rather than the
// 400-producing group: it names what the row's own current state already
// is, not anything wrong with the request as submitted.
func TestApproveApproval_AlreadyDecided_Conflict(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	const rootPrincipal = "root@example.com"

	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM approvals").
		WillReturnRows(sqlmock.NewRows(approvalRowColumns()).AddRow(
			id.String(), fixtureTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
			"requesting-subject", rootPrincipal, "Bash", "execute", int64(models.ActionTierExternalComms),
			make([]byte, 32), "denied", approvalFixtureRequestedAt, approvalFixtureExpiresAt,
			rootPrincipal, approvalFixtureRequestedAt.Add(5*time.Minute),
		))
	f.mock.ExpectRollback()

	tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": rootPrincipal, "email_verified": true})
	rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/approve", tok)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestDecideApproval_ApproveAndDeny_BothRequireTheSameIdentityCheck pins
// that approve and deny both consult the SAME resolved ApproverIdentity --
// a regression guard against the two handlers (approveApproval/
// denyApproval) ever drifting to read different fields, or one forgetting
// the check entirely, since they are otherwise near-identical bodies
// (approvals.go's own doc comment on why they share decideApproval instead
// of duplicating it).
func TestDecideApproval_ApproveAndDeny_BothRequireTheSameIdentityCheck(t *testing.T) {
	for _, route := range []string{"approve", "deny"} {
		t.Run(route, func(t *testing.T) {
			f := newTestServerFixture(t)
			id := uuid.New()
			expectPendingApprovalLoad(f.mock, id, "root@example.com")
			f.mock.ExpectRollback()

			tok := f.tokenWithClaims(t, "org-admins", map[string]any{"email": "not-the-root-principal@example.com", "email_verified": true})
			rec := doRequest(t, f.server, http.MethodPost, "/v1/approvals/"+id.String()+"/"+route, tok)

			if rec.Code != http.StatusForbidden {
				t.Errorf("%s: status = %d, want %d", route, rec.Code, http.StatusForbidden)
			}
			assertExpectationsMet(t, f.mock)
		})
	}
}

// --- GET /v1/approvals (Task 6) -----------------------------------------

// expectApprovalList registers the ordered sqlmock sequence ListApprovals
// issues: begin, set the tenant, the list query, commit. A loose regex
// fragment ("FROM approvals"), matching this file's own established
// discipline for reaching across a package boundary.
func expectApprovalList(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM approvals").WillReturnRows(rows)
	mock.ExpectCommit()
}

// TestListApprovals_ViewerRole_ReturnsRows is the route's own reason for
// existing: Task 4's approve/deny actions are keyed by an id that, until this
// route, nothing returned. RoleViewer, matching every other list route.
//
// It also pins the two wire properties Task 6's brief names, at the HTTP
// boundary rather than only at the model: input_digest arrives as a hex
// string (never the array of 32 numbers a bare [32]byte marshals to), and
// status is present so a "pending approvals" screen can filter client-side —
// which is the whole basis for this endpoint returning every status. See
// internal/store.listApprovalsQuery's doc comment for that ruling.
func TestListApprovals_ViewerRole_ReturnsRows(t *testing.T) {
	f := newTestServerFixture(t)
	pendingID, deniedID := uuid.New(), uuid.New()
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	rows := sqlmock.NewRows(approvalRowColumns()).
		AddRow(
			pendingID.String(), fixtureTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
			"requester@example.com", "root@example.com", "Bash", "execute", int64(models.ActionTierExternalComms),
			digest, "pending", approvalFixtureRequestedAt, approvalFixtureExpiresAt, nil, nil,
		).
		AddRow(
			deniedID.String(), fixtureTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
			"requester@example.com", "root@example.com", "Read", "read", int64(models.ActionTierReadOnly),
			make([]byte, 32), "denied", approvalFixtureRequestedAt, approvalFixtureExpiresAt,
			"root@example.com", approvalFixtureRequestedAt,
		)
	expectApprovalList(f.mock, rows)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/approvals", f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var got []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GET /v1/approvals returned %d approvals, want 2 (a pending one AND a decided one)", len(got))
	}
	if got[0]["input_digest"] != hex.EncodeToString(digest) {
		t.Errorf("input_digest = %v, want the hex string %q", got[0]["input_digest"], hex.EncodeToString(digest))
	}
	statuses := map[string]bool{}
	for _, a := range got {
		status, _ := a["status"].(string)
		statuses[status] = true
	}
	if !statuses["pending"] || !statuses["denied"] {
		t.Errorf("statuses on the wire = %v, want both pending and denied: this route answers /v1/approvals, not /v1/approvals/pending", statuses)
	}

	assertExpectationsMet(t, f.mock)
}

// TestListApprovals_Empty_IsEmptyArrayNotNull: a nil slice marshals as JSON
// null, and a UI must not have to tell "no approvals" apart from "the field
// is missing." Asserted on the raw body, not on a decoded []T — both null and
// [] decode into a Go slice, and only one of them is the required answer.
func TestListApprovals_Empty_IsEmptyArrayNotNull(t *testing.T) {
	f := newTestServerFixture(t)
	expectApprovalList(f.mock, sqlmock.NewRows(approvalRowColumns()))

	rec := doRequest(t, f.server, http.MethodGet, "/v1/approvals", f.token(t, "org-viewers"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := strings.TrimSpace(rec.Body.String()); got != "[]" {
		t.Errorf("body = %q, want %q", got, "[]")
	}

	assertExpectationsMet(t, f.mock)
}

// TestListApprovals_NoToken_Refused: the new route is registered through
// authorize like every other, not beside it. A read route is exactly the
// shape a mutation dropping MinRole would leave looking harmless.
func TestListApprovals_NoToken_Refused(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/v1/approvals", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	assertExpectationsMet(t, f.mock) // never reached the store
}

// TestViewer_CanListButCannotDecide is the direct proof that adding a
// RoleViewer read beside two RoleAdmin write actions did not relax them — the
// mutation "drop MinRole on either new route" would not catch this, because
// it is the SIBLING routes' floor being asserted. It is also N14 stated at
// the API rather than the UI: the client is bypassed entirely here, and the
// server refuses the write on its own.
//
// The viewer's token carries the matching "email" claim (N7's own identity),
// so the only thing refusing these two requests is the role floor. A 403 with
// no store expectation registered proves the refusal happened before any
// database access.
func TestViewer_CanListButCannotDecide(t *testing.T) {
	f := newTestServerFixture(t)
	id := uuid.New()
	tok := f.tokenWithClaims(t, "org-viewers", map[string]any{"email": "root@example.com", "email_verified": true})

	for _, path := range []string{
		"/v1/approvals/" + id.String() + "/approve",
		"/v1/approvals/" + id.String() + "/deny",
	} {
		rec := doRequest(t, f.server, http.MethodPost, path, tok)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST %s as a viewer: status = %d, want %d", path, rec.Code, http.StatusForbidden)
		}
	}

	// The same viewer, on the same resource's read route, succeeds — so the
	// refusals above are the role floor on the WRITE, not a broken token.
	expectApprovalList(f.mock, sqlmock.NewRows(approvalRowColumns()))
	rec := doRequest(t, f.server, http.MethodGet, "/v1/approvals", tok)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /v1/approvals as a viewer: status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	assertExpectationsMet(t, f.mock)
}
