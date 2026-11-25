package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

// approvalColumns is the loadApprovalQuery column order, factored out since
// every LoadApproval test below builds a row against it.
func approvalColumns() []string {
	return []string{
		"id", "tenant_id", "agent_id", "delegation_id", "root_delegation_id",
		"subject", "root_principal", "tool_name", "action", "derived_tier",
		"input_digest", "status", "requested_at", "expires_at", "approved_by", "approved_at", "used_at",
	}
}

// --- CreateApproval ---

// A freshly created approval inserts exactly the twelve columns
// insertApprovalQuery names, in that order, and nothing else — proven with
// deliberately wrong values on every field CreateApproval must NOT read
// (Status, RequestedAt, ApprovedBy, ApprovedAt): a real caller could never
// legitimately populate these before creation (see CreateApproval's own
// doc comment for why), but if CreateApproval ever started trusting them,
// these garbage values are what would silently reach the database. Every
// other field is a distinct value so a positional mixup in the INSERT's
// arg list — e.g. Subject and RootPrincipal swapped — would fail the
// WithArgs match rather than pass by coincidence.
func TestStore_CreateApproval_InsertsRowIgnoringCallerSuppliedLifecycleFields(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	expiresAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	digest := sha256.Sum256([]byte("create-approval fixture"))

	a := &models.Approval{
		ID:               id,
		TenantID:         "wrong-tenant-must-be-ignored", // Store.tenantID is what's used; see below
		AgentID:          agentID,
		DelegationID:     delegationID,
		RootDelegationID: rootDelegationID,
		Subject:          "requesting-subject",
		RootPrincipal:    "root-principal",
		ToolName:         "Bash",
		Action:           "execute",
		DerivedTier:      models.ActionTierExternalComms,
		InputDigest:      digest,
		ExpiresAt:        expiresAt,

		// Deliberately wrong: CreateApproval must never write any of these.
		// A real caller has no legitimate value for them at creation time.
		Status:      "approved",
		RequestedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC),
		ApprovedBy:  strPtr("someone-who-never-approved-this"),
		ApprovedAt:  timePtr(time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)),
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertApprovalQuery)).
		WithArgs(
			id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
			"requesting-subject", "root-principal", "Bash", "execute", int64(models.ActionTierExternalComms),
			digest[:], expiresAt,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.CreateApproval(context.Background(), a); err != nil {
		t.Fatalf("CreateApproval() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// A failure on the INSERT itself must propagate and must still roll back —
// the same discipline TestStore_CreateDelegation_InsertErrorRollsBack
// exercises for delegations.
func TestStore_CreateApproval_InsertErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)
	a := minimalApproval()
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertApprovalQuery)).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	err := s.CreateApproval(context.Background(), a)
	if err == nil {
		t.Fatal("CreateApproval() error = nil, want error")
	}

	assertExpectationsMet(t, mock)
}

// minimalApproval is a syntactically valid Approval for tests that do not
// care about its field values, only that CreateApproval reaches (or does
// not reach) the INSERT.
func minimalApproval() *models.Approval {
	return &models.Approval{
		ID: uuid.New(), AgentID: uuid.New(), DelegationID: uuid.New(), RootDelegationID: uuid.New(),
		Subject: "s", RootPrincipal: "r", ToolName: "Bash", Action: "read",
		DerivedTier: models.ActionTierReadOnly,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func strPtr(s string) *string        { return &s }
func timePtr(t time.Time) *time.Time { return &t }

// --- LoadApproval ---

// A row round-trips field for field. Every value below is distinct from
// every other — including the two nullable timestamp/string columns this
// fixture exercises (ApprovedBy/ApprovedAt, both non-NULL here; the NULL
// case is TestStore_LoadApproval_PendingRowHasNilApprovedFields) — so a
// scan-target transposition anywhere in scanApproval's Scan(...) call
// (this project has twice shipped a fixture whose fields were
// indistinguishable enough to mask exactly that) shows up as a wrong
// assertion rather than passing by coincidence.
func TestStore_LoadApproval_RoundTripsFieldForField(t *testing.T) {
	s, mock := newMockStore(t)

	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte("load-approval round-trip fixture"))
	requestedAt := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	expiresAt := requestedAt.Add(time.Hour)
	approvedAt := requestedAt.Add(30 * time.Minute)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(approvalColumns()).AddRow(
			id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
			"requesting-subject", "root-principal", "Bash", "execute", int64(models.ActionTierExternalComms),
			digest[:], "approved", requestedAt, expiresAt,
			"approver-principal", approvedAt, approvedAt.Add(time.Minute),
		))
	mock.ExpectCommit()

	got, err := s.LoadApproval(context.Background(), id)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}

	if got.ID != id {
		t.Errorf("ID = %s, want %s", got.ID, id)
	}
	if got.TenantID != testTenant {
		t.Errorf("TenantID = %q, want %q", got.TenantID, testTenant)
	}
	if got.AgentID != agentID {
		t.Errorf("AgentID = %s, want %s", got.AgentID, agentID)
	}
	if got.DelegationID != delegationID {
		t.Errorf("DelegationID = %s, want %s", got.DelegationID, delegationID)
	}
	if got.RootDelegationID != rootDelegationID {
		t.Errorf("RootDelegationID = %s, want %s", got.RootDelegationID, rootDelegationID)
	}
	if got.Subject != "requesting-subject" {
		t.Errorf("Subject = %q, want %q", got.Subject, "requesting-subject")
	}
	if got.RootPrincipal != "root-principal" {
		t.Errorf("RootPrincipal = %q, want %q", got.RootPrincipal, "root-principal")
	}
	if got.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want %q", got.ToolName, "Bash")
	}
	if got.Action != "execute" {
		t.Errorf("Action = %q, want %q", got.Action, "execute")
	}
	if got.DerivedTier != models.ActionTierExternalComms {
		t.Errorf("DerivedTier = %v, want %v", got.DerivedTier, models.ActionTierExternalComms)
	}
	if got.InputDigest != digest {
		t.Errorf("InputDigest = %x, want %x", got.InputDigest, digest)
	}
	if got.Status != "approved" {
		t.Errorf("Status = %q, want %q", got.Status, "approved")
	}
	if !got.RequestedAt.Equal(requestedAt) {
		t.Errorf("RequestedAt = %v, want %v", got.RequestedAt, requestedAt)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expiresAt)
	}
	if got.ApprovedBy == nil || *got.ApprovedBy != "approver-principal" {
		t.Errorf("ApprovedBy = %v, want %q", got.ApprovedBy, "approver-principal")
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(approvedAt) {
		t.Errorf("ApprovedAt = %v, want %v", got.ApprovedAt, approvedAt)
	}
	if want := approvedAt.Add(time.Minute); got.UsedAt == nil || !got.UsedAt.Equal(want) {
		t.Errorf("UsedAt = %v, want %v", got.UsedAt, want)
	}

	assertExpectationsMet(t, mock)
}

// A pending approval — the only shape CreateApproval itself ever produces —
// has no approver yet: both nullable columns must decode to nil, not a
// dereferenced zero value (empty string / the zero time.Time), the same
// property TestStore_LoadChain_RootFirstThreeHops pins for the leaf
// delegation's NULL purpose.
func TestStore_LoadApproval_PendingRowHasNilApprovedFields(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte("pending fixture"))
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(approvalColumns()).AddRow(
			id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
			"subject", "root-principal", "Bash", "read", int64(models.ActionTierReadOnly),
			digest[:], "pending", now, now.Add(time.Hour),
			nil, nil, nil,
		))
	mock.ExpectCommit()

	got, err := s.LoadApproval(context.Background(), id)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	if got.ApprovedBy != nil {
		t.Errorf("ApprovedBy = %v, want nil (NULL column)", got.ApprovedBy)
	}
	if got.ApprovedAt != nil {
		t.Errorf("ApprovedAt = %v, want nil (NULL column)", got.ApprovedAt)
	}
	if got.Status != "pending" {
		t.Errorf("Status = %q, want %q", got.Status, "pending")
	}

	assertExpectationsMet(t, mock)
}

// An unknown id is a clean not-found, never an error that could be confused
// with a real failure, and — the fail-closed requirement this package's doc
// comment states for every Load method — never a zero-valued *Approval a
// caller might mistake for a real, pending row (a mutation that returned
// (&models.Approval{}, nil) here would leave got nil-checked below but err nil,
// which this assertion catches: errors.Is(nil, ErrNotFound) is false).
func TestStore_LoadApproval_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	got, err := s.LoadApproval(context.Background(), id)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadApproval() error = %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Errorf("LoadApproval() = %+v, want nil on ErrNotFound", got)
	}

	assertExpectationsMet(t, mock)
}

// UseApproval reports whether its one statement changed a row: true for the
// call that spends the approval, false once it is spent or when no such
// approval is visible.
func TestStore_UseApproval_ReportsWhetherItSpentTheApproval(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows int64
		want bool
	}{{"first use", 1, true}, {"already used or not found", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			id := uuid.New()
			now := time.Now()

			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectExec(regexp.QuoteMeta(useApprovalQuery)).
				WithArgs(now, id.String()).
				WillReturnResult(sqlmock.NewResult(0, tc.rows))
			mock.ExpectCommit()

			got, err := s.UseApproval(context.Background(), id, now)
			if err != nil || got != tc.want {
				t.Fatalf("UseApproval() = %v, %v; want %v, nil", got, err, tc.want)
			}
			assertExpectationsMet(t, mock)
		})
	}
}

// A missing row and a real query failure must be distinguishable: only the
// former is ErrNotFound.
func TestStore_LoadApproval_QueryError(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	_, err := s.LoadApproval(context.Background(), id)
	if err == nil {
		t.Fatal("LoadApproval() error = nil, want error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadApproval() error = %v, must not be ErrNotFound for a query failure", err)
	}

	assertExpectationsMet(t, mock)
}

// A derived_tier outside the valid ActionTier range must fail loudly rather
// than silently decode to ActionTierReasoning (its Go zero value) — the
// same fail-closed requirement scanDelegation applies to max_action_tier.
// A corrupt tier passing as REASONING would be the single most dangerous
// misread this table could produce.
func TestStore_LoadApproval_DerivedTierOutOfRangeFails(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	digest := sha256.Sum256([]byte("bad tier fixture"))
	now := time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(approvalColumns()).AddRow(
			id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
			"subject", "root-principal", "Bash", "read", int64(99), // out of range
			digest[:], "pending", now, now.Add(time.Hour),
			nil, nil, nil,
		))
	mock.ExpectRollback()

	got, err := s.LoadApproval(context.Background(), id)
	if err == nil {
		t.Fatal("LoadApproval() error = nil, want a decode error for an out-of-range derived_tier")
	}
	if got != nil {
		t.Errorf("LoadApproval() = %+v, want nil on decode failure", got)
	}

	assertExpectationsMet(t, mock)
}

// --- DecideApproval (Task 4: E7, the approve action itself) ---

// pendingApprovalRow returns one loadApprovalForUpdateQuery-shaped row for a
// still-pending approval naming rootPrincipal — the fixture every
// DecideApproval test below starts from, since each test exercises a
// DIFFERENT check DecideApproval makes against this same row shape.
func pendingApprovalRow(id, agentID, delegationID, rootDelegationID uuid.UUID, rootPrincipal string) (*sqlmock.Rows, [32]byte, time.Time) {
	digest := sha256.Sum256([]byte("decide-approval fixture"))
	requestedAt := time.Now().UTC().Truncate(time.Second)
	rows := sqlmock.NewRows(approvalColumns()).AddRow(
		id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
		"requesting-subject", rootPrincipal, "Bash", "execute", int64(models.ActionTierExternalComms),
		digest[:], "pending", requestedAt, requestedAt.Add(time.Hour), nil, nil, nil,
	)
	return rows, digest, requestedAt
}

// TestLoadApprovalForUpdateQuery_LocksTheRow pins loadApprovalForUpdateQuery's
// own shape directly, independent of the mock plumbing below: it must lock
// the row (FOR UPDATE — see that query's own doc comment for the race it
// closes) and must be loadApprovalQuery's own text extended, not a second,
// independently maintained copy of that column list that could drift out
// of sync with it.
func TestLoadApprovalForUpdateQuery_LocksTheRow(t *testing.T) {
	if !strings.Contains(loadApprovalForUpdateQuery, "FOR UPDATE") {
		t.Errorf("loadApprovalForUpdateQuery = %q, want it to lock the row with FOR UPDATE", loadApprovalForUpdateQuery)
	}
	if !strings.HasPrefix(loadApprovalForUpdateQuery, loadApprovalQuery) {
		t.Errorf("loadApprovalForUpdateQuery must extend loadApprovalQuery verbatim so both stay in sync with the same column list")
	}
}

// TestStore_DecideApproval_ApproveSuccess is N7's positive case: an operator
// whose identity equals the loaded approval's own root_principal may
// approve. approved_by is asserted to be written as the row's OWN
// root_principal (not a second copy of operatorIdentity), matching
// DecideApproval's own doc comment on why that specific value is chosen.
func TestStore_DecideApproval_ApproveSuccess(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const rootPrincipal = "root-principal@example.com"
	now := time.Now().UTC().Truncate(time.Second)
	rows, digest, _ := pendingApprovalRow(id, agentID, delegationID, rootDelegationID, rootPrincipal)

	// The exact audit.Entry DecideApproval must build for an approval --
	// pinned via insertArgsFor (audit_test.go's own helper, also used by
	// TestStore_DeletePolicy_Success) rather than only checking that SOME
	// audit insert happened. This catches a field dropped, reordered, or
	// swapped with a neighbor (e.g. AgentID/DelegationID transposed) --
	// exactly what a bare "an insert happened" check would miss.
	//
	// What it does NOT catch, and cannot: a typo inside eventTypeApprovalApproved's
	// own string literal. wantEntry.EventType reads that same symbol, so a
	// mutation to its definition moves both sides together -- the identical
	// blind spot TestIntegration_PAPCRUD_DeniedAtDepthMatchesTheEstablishedSentinel's
	// own doc comment already documents for noDenial, and already accepts as
	// this codebase's standing trade-off: the unit layer proves argument
	// shape and order; TestIntegration_DecideApproval_RoundTrip (pap_task4_
	// integration_test.go), which compares against the HARDCODED literal
	// "approval_approved" via assertAuditTrailMatches, is what actually
	// holds the line on the constant's own value -- confirmed live, the
	// same way, during this task's own bonus mutation pass: retyping the
	// constant to "approval_aproved" left every test in this file green
	// and was caught only by that integration test.
	wantEntry := audit.Entry{
		TenantID: testTenant, OccurredAt: now, EventType: eventTypeApprovalApproved, Actor: "operator-actor",
		AgentID: &agentID, DelegationID: &delegationID, RootDelegationID: &rootDelegationID,
		ToolName: "Bash", Action: "execute", DerivedTier: int16(models.ActionTierExternalComms),
		Decision: "ALLOW", DeniedAtDepth: noDenial, Reason: "escalation approved", InputDigest: digest,
	}
	wantLinked := audit.Link(nil, wantEntry)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(updateApprovalDecisionQuery)).
		WithArgs("approved", rootPrincipal, now, id.String()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.DecideApproval(context.Background(), id, true, rootPrincipal, "operator-actor", now)
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if got.Status != "approved" {
		t.Errorf("Status = %q, want %q", got.Status, "approved")
	}
	if got.ApprovedBy == nil || *got.ApprovedBy != rootPrincipal {
		t.Errorf("ApprovedBy = %v, want %q", got.ApprovedBy, rootPrincipal)
	}
	if got.ApprovedAt == nil || !got.ApprovedAt.Equal(now) {
		t.Errorf("ApprovedAt = %v, want %v", got.ApprovedAt, now)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_DecideApproval_DenySuccess is ApproveSuccess's own counterpart
// for an explicit deny: the schema allows 'denied' and an approver
// rejecting immediately beats making an agent wait for a timeout (task
// brief). approved_by/approved_at are still set on a deny — see
// DecideApproval's own doc comment on why both columns mean "who decided,
// and when," not strictly "who approved."
func TestStore_DecideApproval_DenySuccess(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const rootPrincipal = "root-principal@example.com"
	now := time.Now().UTC().Truncate(time.Second)
	rows, digest, _ := pendingApprovalRow(id, agentID, delegationID, rootDelegationID, rootPrincipal)

	// Pinned via insertArgsFor -- see ApproveSuccess's own comment on what
	// this does and does not protect against (the identical limitation
	// applies here to eventTypeApprovalDenied and Decision="DENY").
	wantEntry := audit.Entry{
		TenantID: testTenant, OccurredAt: now, EventType: eventTypeApprovalDenied, Actor: "operator-actor",
		AgentID: &agentID, DelegationID: &delegationID, RootDelegationID: &rootDelegationID,
		ToolName: "Bash", Action: "execute", DerivedTier: int16(models.ActionTierExternalComms),
		Decision: "DENY", DeniedAtDepth: noDenial, Reason: "escalation denied", InputDigest: digest,
	}
	wantLinked := audit.Link(nil, wantEntry)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(updateApprovalDecisionQuery)).
		WithArgs("denied", rootPrincipal, now, id.String()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.DecideApproval(context.Background(), id, false, rootPrincipal, "operator-actor", now)
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if got.Status != "denied" {
		t.Errorf("Status = %q, want %q", got.Status, "denied")
	}
	if got.ApprovedBy == nil || *got.ApprovedBy != rootPrincipal {
		t.Errorf("ApprovedBy = %v, want %q (who decided, not merely who approved)", got.ApprovedBy, rootPrincipal)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_DecideApproval_WrongApproverRefused is N7's own required test
// (task brief: "one whose identity does not [match] is refused... that is
// N7 and it needs its own test"): an operator whose identity does not equal
// the loaded row's root_principal is refused with ErrApproverNotRootPrincipal
// — proven with NO updateApprovalDecisionQuery or audit expectation
// registered at all, so a mutant that dropped or weakened this comparison
// would instead reach the (absent) UPDATE expectation and fail with
// sqlmock's own "was not expected" error, not this specific errors.Is
// check. This is the store-layer twin of
// cmd/stratium-pap/approvals_test.go's own HTTP-level proof that this holds
// even when the operator's ROLE is admin — role and identity are two
// different gates, and this test is about the second one alone.
func TestStore_DecideApproval_WrongApproverRefused(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	rows, _, _ := pendingApprovalRow(id, agentID, delegationID, rootDelegationID, "the-real-root-principal@example.com")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectRollback()

	_, err := s.DecideApproval(context.Background(), id, true, "an-impostor@example.com", "operator-actor", time.Now())
	if !errors.Is(err, ErrApproverNotRootPrincipal) {
		t.Errorf("DecideApproval() error = %v, want errors.Is(_, ErrApproverNotRootPrincipal)", err)
	}

	assertExpectationsMet(t, mock) // no UPDATE, no audit insert: nothing was decided
}

// TestStore_DecideApproval_AlreadyDecidedRefused proves a second decision on
// an already-resolved approval is refused, not a silent overwrite of the
// first disposition — checked AFTER the N7 comparison above (see
// DecideApproval's own doc comment for why that order is deliberate: an
// operator N7 has already ruled out must not learn anything about the row's
// current status from which error comes back).
func TestStore_DecideApproval_AlreadyDecidedRefused(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const rootPrincipal = "root-principal@example.com"
	digest := sha256.Sum256([]byte("already decided fixture"))
	requestedAt := time.Now().UTC().Truncate(time.Second)
	approvedAt := requestedAt.Add(time.Minute)
	rows := sqlmock.NewRows(approvalColumns()).AddRow(
		id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
		"requesting-subject", rootPrincipal, "Bash", "execute", int64(models.ActionTierExternalComms),
		digest[:], "approved", requestedAt, requestedAt.Add(time.Hour), rootPrincipal, approvedAt, nil,
	)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectRollback()

	_, err := s.DecideApproval(context.Background(), id, false, rootPrincipal, "operator-actor", time.Now())
	if !errors.Is(err, ErrApprovalNotPending) {
		t.Errorf("DecideApproval() error = %v, want errors.Is(_, ErrApprovalNotPending)", err)
	}

	assertExpectationsMet(t, mock) // no UPDATE, no audit insert: the first disposition survives untouched
}

func TestStore_DecideApproval_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.DecideApproval(context.Background(), id, true, "someone@example.com", "operator-actor", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("DecideApproval() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_DecideApproval_AuditFailureRollsBackWrite is N4's own proof for
// this method — see policy_test.go's
// TestStore_CreatePolicy_AuditFailureRollsBackWrite for the full reasoning:
// the UPDATE succeeds, but the audit append's own advisory-lock step fails,
// and because both share one transaction, only ExpectRollback remains
// registered.
func TestStore_DecideApproval_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const rootPrincipal = "root-principal@example.com"
	now := time.Now().UTC().Truncate(time.Second)
	rows, _, _ := pendingApprovalRow(id, agentID, delegationID, rootDelegationID, rootPrincipal)
	lockErr := errors.New("connection reset mid-audit")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(updateApprovalDecisionQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).WillReturnError(lockErr)
	mock.ExpectRollback()

	if _, err := s.DecideApproval(context.Background(), id, true, rootPrincipal, "operator-actor", now); err == nil {
		t.Fatal("DecideApproval() error = nil, want the audit failure to propagate")
	}

	// No live-Postgres counterpart: pap_crud_integration_test.go's own
	// package doc explains why Task 3 already made this call for the
	// identical property on CreatePolicy/CreateAgent/CreateTierOverride, and
	// this method inherits the same reasoning rather than a fresh one --
	// reproducing an audit-insert failure deterministically against a live
	// connection would be far more fragile than what it would prove beyond
	// this sqlmock-level proof, which injects the failure at the exact
	// instant the property needs it.
	assertExpectationsMet(t, mock)
}

// idAbsentArg is a sqlmock.Argument matcher: it fails the match if v is a
// string containing forbidden, and accepts any other value (including a
// non-string driver.Value such as a []byte hash, a time.Time, or an int16
// tier, none of which could carry a UUID's canonical string form) — see
// TestStore_DecideApproval_AuditEntryNeverNamesTheApprovalID, its only
// caller, for why every argument is checked this way rather than just the
// one (Reason) most likely to carry it.
type idAbsentArg struct{ forbidden string }

func (m idAbsentArg) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return true
	}
	return !strings.Contains(s, m.forbidden)
}

// TestStore_DecideApproval_AuditEntryNeverNamesTheApprovalID guards this
// phase's own logging rule ("never log... an approval id") at the one place
// DecideApproval builds an audit.Entry. Every one of insertAuditQuery's 22
// positional arguments is matched against idAbsentArg{id.String()} — not
// merely Reason, the field most likely to carry a stray id — so if a future
// edit added the approval's own id ANYWHERE on this entry, sqlmock would
// refuse the match and fail this test for an unexpected argument, rather
// than this test only ever checking the one field its author remembered to
// suspect. WHICH escalation was decided is already fully identifiable from
// AgentID/DelegationID/RootDelegationID/ToolName/Action/DerivedTier/
// InputDigest (all copied from the approval, per DecideApproval's own doc
// comment), so there is no reason this row's own primary key would ever
// legitimately need to appear here, and audit_chain has no column for it
// regardless.
func TestStore_DecideApproval_AuditEntryNeverNamesTheApprovalID(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	const rootPrincipal = "root-principal@example.com"
	now := time.Now().UTC().Truncate(time.Second)
	rows, _, _ := pendingApprovalRow(id, agentID, delegationID, rootDelegationID, rootPrincipal)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalForUpdateQuery)).WithArgs(id.String()).WillReturnRows(rows)
	mock.ExpectExec(regexp.QuoteMeta(updateApprovalDecisionQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)

	const insertAuditQueryArgCount = 22 // tenant_id..input_digest — see insertAuditQuery's own doc comment (audit.go)
	forbid := idAbsentArg{forbidden: id.String()}
	args := make([]driver.Value, insertAuditQueryArgCount)
	for i := range args {
		args[i] = forbid
	}
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, err := s.DecideApproval(context.Background(), id, true, rootPrincipal, "operator-actor", now); err != nil {
		t.Fatalf("DecideApproval() error = %v, want nil -- and, per idAbsentArg above, want no argument to have carried the approval's own id", err)
	}
	assertExpectationsMet(t, mock)
}

// input_digest is NOT NULL in the schema, so any row read back must carry
// exactly 32 bytes; a different length is a truncated or corrupt digest and
// must fail loudly rather than silently copy a partial value into the
// fixed-size array — the same discipline scanAuditTail applies to
// audit_chain's prev_hash/input_digest.
func TestStore_LoadApproval_InputDigestWrongLengthFails(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID, delegationID, rootDelegationID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadApprovalQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(approvalColumns()).AddRow(
			id.String(), testTenant, agentID.String(), delegationID.String(), rootDelegationID.String(),
			"subject", "root-principal", "Bash", "read", int64(models.ActionTierReadOnly),
			[]byte{0x01, 0x02, 0x03}, "pending", now, now.Add(time.Hour), // 3 bytes, not 32
			nil, nil, nil,
		))
	mock.ExpectRollback()

	got, err := s.LoadApproval(context.Background(), id)
	if err == nil {
		t.Fatal("LoadApproval() error = nil, want a decode error for a wrong-length input_digest")
	}
	if got != nil {
		t.Errorf("LoadApproval() = %+v, want nil on decode failure", got)
	}

	assertExpectationsMet(t, mock)
}

// --- ListApprovals (Task 6) ---

// listApprovalRow builds one approvals row in approvalColumns order.
func listApprovalRow(rows *sqlmock.Rows, id uuid.UUID, status string, requestedAt time.Time) *sqlmock.Rows {
	var approvedBy, approvedAt interface{}
	if status != "pending" {
		approvedBy, approvedAt = "root@example.com", requestedAt.Add(time.Minute)
	}
	return rows.AddRow(
		id.String(), testTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
		"requester@example.com", "root@example.com", "Bash", "execute", int64(models.ActionTierExternalComms),
		make([]byte, 32), status, requestedAt, requestedAt.Add(time.Hour), approvedBy, approvedAt, nil,
	)
}

// TestStore_ListApprovals_ReturnsEveryStatus is the ruling this method's own
// doc comment argues for, asserted rather than merely described: the query
// carries no status predicate, so a decided approval comes back alongside a
// pending one. Without this, filtering to 'pending' would make every decided
// row unreachable — there is no GET /v1/approvals/{id} anywhere in this
// phase — and no existing test would have noticed.
func TestStore_ListApprovals_ReturnsEveryStatus(t *testing.T) {
	s, mock := newMockStore(t)
	requestedAt := time.Now().UTC().Truncate(time.Second)

	rows := sqlmock.NewRows(approvalColumns())
	listApprovalRow(rows, uuid.New(), "pending", requestedAt)
	listApprovalRow(rows, uuid.New(), "approved", requestedAt.Add(-time.Hour))
	listApprovalRow(rows, uuid.New(), "denied", requestedAt.Add(-2*time.Hour))

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listApprovalsQuery)).WillReturnRows(rows)
	mock.ExpectCommit()

	got, err := s.ListApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListApprovals() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("ListApprovals() returned %d approvals, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, a := range got {
		seen[a.Status] = true
	}
	for _, status := range []string{"pending", "approved", "denied"} {
		if !seen[status] {
			t.Errorf("ListApprovals() dropped every %q approval; this endpoint answers /v1/approvals, not /v1/approvals/pending", status)
		}
	}

	assertExpectationsMet(t, mock)
}

// TestStore_ListApprovals_QueryHasNoTenantPredicate: RLS via beginTenantTx is
// this codebase's only tenant boundary. A WHERE tenant_id here would still
// pass every behavioural test in this file — sqlmock replays whatever rows the
// test hands it, and against a real database the predicate is simply
// redundant with the RLS policy that already applies — which is exactly why
// the check has to be on the query text. See internal/store's own package
// doc: a second, divergent tenant check is worse than none.
//
// Asserted as "no WHERE clause at all," not "no tenant_id substring":
// tenant_id is a SELECTED COLUMN in this query (models.Approval.TenantID is
// populated from it), so a substring check would fail on the correct query.
// This list is unconditional by design — every approval this tenant has —
// so any WHERE appearing here is a filter someone added, tenant-shaped or
// otherwise, and worth failing on.
func TestStore_ListApprovals_QueryHasNoTenantPredicate(t *testing.T) {
	if strings.Contains(strings.ToLower(listApprovalsQuery), "where") {
		t.Errorf("listApprovalsQuery = %q, want no WHERE clause: RLS is the only tenant boundary and this list is unfiltered",
			listApprovalsQuery)
	}
}

// TestStore_ListApprovals_EmptyIsNotAnError pins the make([]T, 0) accumulator:
// a nil slice marshals as JSON null, and the admin UI must not have to tell
// "this tenant has no approvals" apart from "the field is missing."
func TestStore_ListApprovals_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listApprovalsQuery)).WillReturnRows(sqlmock.NewRows(approvalColumns()))
	mock.ExpectCommit()

	got, err := s.ListApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListApprovals() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("ListApprovals() = %v, want a non-nil empty slice", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(empty list) error = %v", err)
	}
	if string(raw) != "[]" {
		t.Errorf("an empty ListApprovals() marshals as %s, want []", raw)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_ListApprovals_ScanErrorAborts: a corrupt row must fail the whole
// call, never be skipped so the caller silently sees a short list. Reuses the
// short-digest case scanApproval already rejects for a single row.
func TestStore_ListApprovals_ScanErrorAborts(t *testing.T) {
	s, mock := newMockStore(t)
	requestedAt := time.Now().UTC().Truncate(time.Second)

	rows := sqlmock.NewRows(approvalColumns()).AddRow(
		uuid.New().String(), testTenant, uuid.New().String(), uuid.New().String(), uuid.New().String(),
		"requester@example.com", "root@example.com", "Bash", "execute", int64(models.ActionTierExternalComms),
		make([]byte, 8), "pending", requestedAt, requestedAt.Add(time.Hour), nil, nil, nil,
	)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listApprovalsQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	if _, err := s.ListApprovals(context.Background()); err == nil {
		t.Fatal("ListApprovals() error = nil for a row with a truncated input_digest, want an error")
	}
}
