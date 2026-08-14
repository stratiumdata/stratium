package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/internal/authz"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

func tierOverrideRowColumns() []string {
	return []string{"id", "tenant_id", "tool_or_verb", "action_tier", "builtin_tier", "created_at", "created_by"}
}

// --- builtinTier ---

// TestBuiltinTier is the pure-function proof behind CreateTierOverride/
// UpdateTierOverride's own raise-only checks: it pins the exact floor
// ValidateOverride compares a proposed override against, for the three
// shapes tool_or_verb actually takes in practice.
func TestBuiltinTier(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want models.ActionTier
	}{
		{"catalogued tool name", "Read", models.ActionTierReadOnly},
		{"another catalogued tool name", "Write", models.ActionTierInternalModify},
		{"known verb, lowercase", "delete", models.ActionTierDestructive},
		{"known verb, case-insensitive per BuiltinTier's own verbTiers lookup", "READ", models.ActionTierReadOnly},
		{
			// Bash is deliberately absent from authz.DefaultCatalog (that
			// function's own doc comment: a fixed tier here would defeat
			// per-command classification) and is not a verb either, so it
			// floors at the lattice's own minimum -- see builtinTier's own
			// doc comment on why that is safe rather than a loophole.
			"Bash has no static builtin, floors at Reasoning", "Bash", models.ActionTierReasoning,
		},
		{"unrecognised name floors at Reasoning", "totally-unknown-tool", models.ActionTierReasoning},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := builtinTier(tt.key); got != tt.want {
				t.Errorf("builtinTier(%q) = %s, want %s", tt.key, got, tt.want)
			}
		})
	}
}

// --- CreateTierOverride ---

func TestStore_CreateTierOverride_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	// "Read"'s builtin is ReadOnly (1); raising to InternalModify (2) is a
	// legitimate raise, so builtin_tier = 1 is what must be persisted.
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WithArgs(testTenant, "Read", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), "operator-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(id.String(), now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierInternalModify}
	got, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if err != nil {
		t.Fatalf("CreateTierOverride() error = %v", err)
	}
	if got.BuiltinTier != models.ActionTierReadOnly {
		t.Errorf("BuiltinTier = %s, want %s (server-computed, never client-supplied)", got.BuiltinTier, models.ActionTierReadOnly)
	}
	if got.CreatedBy != "operator-1" {
		t.Errorf("CreatedBy = %q, want %q", got.CreatedBy, "operator-1")
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateTierOverride_RaisingBuiltinTierIsIgnoredFromInput is the
// direct proof that a client-supplied BuiltinTier changes nothing: even a
// caller that tries to hand in BuiltinTier=Destructive (falsely claiming
// "Read" is already maximally dangerous, which would make almost any
// ActionTier pass the raise-only check trivially) gets the real,
// server-computed floor instead.
func TestStore_CreateTierOverride_ClientSuppliedBuiltinTierIsIgnored(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	// The real builtin for "Read" (ReadOnly=1) is what must reach the
	// query, not the attacker-supplied BuiltinTier=Destructive(4) below.
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WithArgs(testTenant, "Read", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), "operator-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(id.String(), now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierInternalModify, BuiltinTier: models.ActionTierDestructive}
	got, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if err != nil {
		t.Fatalf("CreateTierOverride() error = %v", err)
	}
	if got.BuiltinTier != models.ActionTierReadOnly {
		t.Errorf("BuiltinTier = %s, want %s (the real computed floor, not the client-supplied value)",
			got.BuiltinTier, models.ActionTierReadOnly)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateTierOverride_LoweringRefusedBeforePersisting is Property
// 3's own proof and the direct target of the required mutation "accept a
// lowering override": "Read" (builtin ReadOnly=1) down to Reasoning=0 is a
// lowering, must be refused by authz.ValidateOverride, and must never reach
// beginTenantTx -- the zero-expectation mock below is what proves the
// second half; if a mutant swapped ValidateOverride's comparison (or
// skipped the call), the request would instead reach the empty mock and
// fail with sqlmock's own "was not expected" error, not this specific
// errors.Is check.
func TestStore_CreateTierOverride_LoweringRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	// Write's builtin is InternalModify (2); ReadOnly (1) is strictly lower.
	in := models.TierOverride{ToolOrVerb: "Write", ActionTier: models.ActionTierReadOnly}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, authz.ErrOverrideLowersTier) {
		t.Errorf("CreateTierOverride() error = %v, want authz.ErrOverrideLowersTier", err)
	}

	assertExpectationsMet(t, mock) // zero expectations: nothing may reach the database
}

// TestStore_CreateTierOverride_EqualTierIsAccepted is the raise-only rule's
// own boundary case: ValidateOverride's condition is "override < builtin"
// refuses, so override == builtin (no-op, declaring a tool exactly as
// sensitive as it already is) must be ACCEPTED, not refused by an
// off-by-one mutation of < into <=.
func TestStore_CreateTierOverride_EqualTierIsAccepted(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WithArgs(testTenant, "Read", int64(models.ActionTierReadOnly), int64(models.ActionTierReadOnly), "operator-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(id.String(), now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierReadOnly}
	if _, err := s.CreateTierOverride(context.Background(), in, "operator-1"); err != nil {
		t.Fatalf("CreateTierOverride() error = %v, want nil for override == builtin", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreateTierOverride_EmptyToolOrVerbRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	in := models.TierOverride{ToolOrVerb: "", ActionTier: models.ActionTierReadOnly}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreateTierOverride() error = %v, want ErrInvalidRequest", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreateTierOverride_DuplicateIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WillReturnError(&pq.Error{Code: sqlStateUniqueViolation, Message: `duplicate key value violates unique constraint "tier_overrides_tenant_id_tool_or_verb_key"`})
	mock.ExpectRollback()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierReadOnly}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("CreateTierOverride() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateTierOverride_AuditFailureRollsBackWrite is
// tier_override.go's own instance of N4's atomicity proof -- see
// policy_test.go's TestStore_CreatePolicy_AuditFailureRollsBackWrite for
// the full reasoning.
func TestStore_CreateTierOverride_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	insertErr := errors.New("connection reset writing the audit entry")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(uuid.New().String(), time.Now()))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnError(insertErr)
	mock.ExpectRollback()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierReadOnly}
	if _, err := s.CreateTierOverride(context.Background(), in, "operator-1"); err == nil {
		t.Fatal("CreateTierOverride() error = nil, want the audit insert failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// --- GetTierOverride ---

func TestStore_GetTierOverride_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(tierOverrideRowColumns()).
			AddRow(id.String(), testTenant, "Read", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), now, "operator-1"))
	mock.ExpectCommit()

	got, err := s.GetTierOverride(context.Background(), id)
	if err != nil {
		t.Fatalf("GetTierOverride() error = %v", err)
	}
	if got.ActionTier != models.ActionTierInternalModify || got.BuiltinTier != models.ActionTierReadOnly {
		t.Errorf("GetTierOverride() = %+v, want ActionTier=INTERNAL_MODIFY BuiltinTier=READ_ONLY", got)
	}
}

// An out-of-range stored tier must fail loudly, never silently decode as
// ActionTierReasoning -- the same discipline scanDelegation applies to
// max_action_tier (store.go).
func TestStore_GetTierOverride_OutOfRangeActionTierFailsLoudly(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(tierOverrideRowColumns()).
			AddRow(id.String(), testTenant, "Read", int64(99), int64(models.ActionTierReadOnly), now, "operator-1"))
	mock.ExpectRollback()

	if _, err := s.GetTierOverride(context.Background(), id); err == nil {
		t.Fatal("GetTierOverride() error = nil, want a range error for an out-of-range action_tier")
	}
}

func TestStore_GetTierOverride_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.GetTierOverride(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetTierOverride() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- ListTierOverrides ---

func TestStore_ListTierOverrides_Success(t *testing.T) {
	s, mock := newMockStore(t)
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listTierOverridesQuery)).
		WillReturnRows(sqlmock.NewRows(tierOverrideRowColumns()).
			AddRow(uuid.New().String(), testTenant, "Bash", int64(models.ActionTierDestructive), int64(models.ActionTierReasoning), now, "operator-1").
			AddRow(uuid.New().String(), testTenant, "Read", int64(models.ActionTierInternalModify), int64(models.ActionTierReadOnly), now, "operator-2"))
	mock.ExpectCommit()

	got, err := s.ListTierOverrides(context.Background())
	if err != nil {
		t.Fatalf("ListTierOverrides() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListTierOverrides() returned %d overrides, want 2", len(got))
	}

	assertExpectationsMet(t, mock)
}

func TestStore_ListTierOverrides_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listTierOverridesQuery)).WillReturnRows(sqlmock.NewRows(tierOverrideRowColumns()))
	mock.ExpectCommit()

	got, err := s.ListTierOverrides(context.Background())
	if err != nil {
		t.Fatalf("ListTierOverrides() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListTierOverrides() = %v, want a non-nil empty slice", got)
	}

	assertExpectationsMet(t, mock)
}

// --- UpdateTierOverride ---

func TestStore_UpdateTierOverride_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	created := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateTierOverrideQuery)).
		WithArgs("Read", int64(models.ActionTierExternalComms), int64(models.ActionTierReadOnly), id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "created_by"}).AddRow(created, "original-author"))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierExternalComms}
	got, err := s.UpdateTierOverride(context.Background(), id, in, "operator-editor", now)
	if err != nil {
		t.Fatalf("UpdateTierOverride() error = %v", err)
	}
	// CreatedBy must survive an edit unchanged -- an update is not a
	// re-authorship (updateTierOverrideQuery's own doc comment).
	if got.CreatedBy != "original-author" {
		t.Errorf("CreatedBy = %q, want %q (unchanged by an edit)", got.CreatedBy, "original-author")
	}

	assertExpectationsMet(t, mock)
}

// TestStore_UpdateTierOverride_LoweringRefusedBeforePersisting is
// UpdateTierOverride's own instance of the required "accept a lowering
// override" mutation target -- re-validated fresh on every update, not
// trusted from the row's own stored builtin_tier (that method's own doc
// comment).
func TestStore_UpdateTierOverride_LoweringRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	in := models.TierOverride{ToolOrVerb: "Write", ActionTier: models.ActionTierReasoning}
	_, err := s.UpdateTierOverride(context.Background(), uuid.New(), in, "operator-1", time.Now())
	if !errors.Is(err, authz.ErrOverrideLowersTier) {
		t.Errorf("UpdateTierOverride() error = %v, want authz.ErrOverrideLowersTier", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_UpdateTierOverride_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateTierOverrideQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierReadOnly}
	if _, err := s.UpdateTierOverride(context.Background(), id, in, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateTierOverride() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- DeleteTierOverride ---

// TestStore_DeleteTierOverride_Success pins the full audit argument list
// via insertArgsFor -- see TestStore_DeletePolicy_Success's own doc comment
// for why.
func TestStore_DeleteTierOverride_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	wantEntry := audit.Entry{
		TenantID:      testTenant,
		OccurredAt:    now,
		EventType:     eventTypeTierOverrideDeleted,
		Actor:         "operator-3",
		ToolName:      "Read",
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        "Read",
	}
	wantLinked := audit.Link(nil, wantEntry)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"tool_or_verb"}).AddRow("Read"))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.DeleteTierOverride(context.Background(), id, "operator-3", now); err != nil {
		t.Fatalf("DeleteTierOverride() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_DeleteTierOverride_NoRaiseOnlyCheck is the deliberate negative
// space: deleting an override that itself raised a tier (removing it drops
// the tool back to a LOWER, built-in tier) must still succeed -- there is
// no ValidateOverride call on this path at all (DeleteTierOverride's own
// doc comment explains why a delete can never be "a lowering"). If a
// well-meaning but wrong future change added a raise-only check here, this
// test would catch it refusing a delete that must always be allowed.
func TestStore_DeleteTierOverride_NoRaiseOnlyCheck(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"tool_or_verb"}).AddRow("Bash"))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.DeleteTierOverride(context.Background(), id, "operator-1", now); err != nil {
		t.Fatalf("DeleteTierOverride() error = %v, want nil -- removing an override is never a lowering", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_DeleteTierOverride_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteTierOverrideQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if err := s.DeleteTierOverride(context.Background(), id, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteTierOverride() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}
