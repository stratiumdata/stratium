package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// approvalColumns is the loadApprovalQuery column order, factored out since
// every LoadApproval test below builds a row against it.
func approvalColumns() []string {
	return []string{
		"id", "tenant_id", "agent_id", "delegation_id", "root_delegation_id",
		"subject", "root_principal", "tool_name", "action", "derived_tier",
		"input_digest", "status", "requested_at", "expires_at", "approved_by", "approved_at",
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

	a := &Approval{
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
func minimalApproval() *Approval {
	return &Approval{
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
			"approver-principal", approvedAt,
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
			nil, nil,
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
// (&Approval{}, nil) here would leave got nil-checked below but err nil,
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
			nil, nil,
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
			nil, nil,
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
