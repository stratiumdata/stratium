package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"maps"
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

// --- overrideBaseline ---
//
// The pure "what is the baseline for this key" table lives with the rule
// itself, in internal/authz (TestOverrideBaseline, tier_test.go). What is
// proven HERE is the half that is this package's own: that the tenant's live
// tool_catalog is what reaches it, read inside the write's own transaction.
// The proof is through CreateTierOverride/UpdateTierOverride rather than
// through overrideBaseline directly -- catalog rows that change which
// overrides are accepted are what the tests below turn on, which is a
// stronger statement than a mocked helper returning a tier.

// toolCatalogRows builds a sqlmock result in loadToolCatalogQuery's own
// column order. A test passes the tenant's catalog rows as
// {tool_name, action_tier, verb, resource_field, command_field} tuples; a
// nil action_tier is the NULL-tier (Bash-shaped) row.
func toolCatalogRows(rows ...[]driver.Value) *sqlmock.Rows {
	out := sqlmock.NewRows([]string{"tool_name", "action_tier", "verb", "resource_field", "command_field"})
	for _, r := range rows {
		out.AddRow(r...)
	}
	return out
}

// expectBaselineReads queues the two SELECTs overrideBaseline performs inside
// the same transaction as the write it is validating: the tenant's
// tool_catalog and its other tier_overrides rows. Every CreateTierOverride/
// UpdateTierOverride expectation below carries both, immediately after
// expectSetTenant -- the raise-only baseline is the resolution BENEATH the
// override, and both tables are part of that (deriveTierByName probes
// overrides at every slot before any catalog lookup, so a sibling row sits
// beneath this one).
//
// catalog is the tenant's rows; siblings is its existing overrides, most
// often none.
func expectBaselineReads(mock sqlmock.Sqlmock, catalog *sqlmock.Rows, siblings ...[]driver.Value) {
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).WillReturnRows(catalog)
	overrideRows := sqlmock.NewRows(tierOverrideLoadColumns())
	for _, r := range siblings {
		overrideRows.AddRow(r...)
	}
	mock.ExpectQuery(regexp.QuoteMeta(loadTierOverridesQuery)).WillReturnRows(overrideRows)
}

// --- CreateTierOverride ---

func TestStore_CreateTierOverride_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock, toolCatalogRows())
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
	expectBaselineReads(mock, toolCatalogRows())
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

// TestStore_CreateTierOverride_LoweringRefusedBeforePersisting is the
// raise-only rule's own proof and the direct target of the required mutation
// "accept a lowering override": "Write" (baseline InternalModify=2) down to
// ReadOnly=1 is a lowering, must be refused by authz.ValidateOverride, and
// must never reach the INSERT.
//
// The expectations stop at the catalog read and a rollback. Before Phase 14
// Task 7 this test's mock had ZERO expectations, because the baseline was a
// pure function and a refusal never opened a transaction at all; the
// baseline is now the resolution beneath the override, which requires the
// tenant's catalog, which requires the transaction. The property being
// asserted is unchanged and is still the one that matters -- no
// insertTierOverrideQuery is queued, so a mutant that swapped
// ValidateOverride's comparison, or skipped the call, reaches an
// unexpected-query failure from sqlmock rather than this errors.Is check.
func TestStore_CreateTierOverride_LoweringRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock, toolCatalogRows())
	mock.ExpectRollback()

	// Write's baseline is InternalModify (2); ReadOnly (1) is strictly lower.
	in := models.TierOverride{ToolOrVerb: "Write", ActionTier: models.ActionTierReadOnly}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, authz.ErrOverrideLowersTier) {
		t.Errorf("CreateTierOverride() error = %v, want authz.ErrOverrideLowersTier", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateTierOverride_CatalogEntryIsTheBaseline is Task 7's own
// correction, proven at the write end: the tenant catalogs "Read" as
// DESTRUCTIVE, and an override to INTERNAL_MODIFY must be refused even
// though INTERNAL_MODIFY sits comfortably above the BUILT-IN tier for Read
// (READ_ONLY). This is the exact sequence the task brief names -- built-in
// READ_ONLY + catalog DESTRUCTIVE + override WRITE passed the old check and
// then lowered the effective tier from DESTRUCTIVE to WRITE, a lowering that
// satisfied the raise-only rule by measuring against the wrong baseline.
//
// A mutation that reverts overrideBaseline to consulting DefaultCatalog()
// alone passes every other test in this file and fails only here and at its
// read-time counterpart (TestDecide_OverrideBelowCatalogBaselineIsDropped,
// pdpgrpc/server_test.go).
func TestStore_CreateTierOverride_CatalogEntryIsTheBaseline(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock, toolCatalogRows(
		[]driver.Value{"Read", int64(models.ActionTierDestructive), "", nil, nil},
	))
	mock.ExpectRollback()

	in := models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierInternalModify}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, authz.ErrOverrideLowersTier) {
		t.Errorf("CreateTierOverride() error = %v, want authz.ErrOverrideLowersTier -- "+
			"the tenant's own catalog entry (DESTRUCTIVE) is the baseline, not the built-in (READ_ONLY)", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateTierOverride_NullTierCatalogRowFallsBackToBuiltin is the
// ruling on the one obstacle the old builtinTier doc comment named and did
// not resolve: a catalog row with a NULL tier (Bash-shaped -- "no fixed
// tier, classify per command") has no static tier to compare an override
// against.
//
// It is not refused. Refusing would block the single most legitimate use
// this table has -- an operator raising Bash to DESTRUCTIVE tenant-wide --
// so such a key falls back to the built-in resolution, which for "Bash"
// (absent from DefaultCatalog and not a verb) is ActionTier's own floor.
// The override is accepted and builtin_tier records that floor.
func TestStore_CreateTierOverride_NullTierCatalogRowFallsBackToBuiltin(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock, toolCatalogRows(
		[]driver.Value{"Bash", nil, "", nil, "command"},
	))
	mock.ExpectQuery(regexp.QuoteMeta(insertTierOverrideQuery)).
		WithArgs(testTenant, "Bash", int64(models.ActionTierDestructive), int64(models.ActionTierReasoning), "operator-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at"}).AddRow(id.String(), now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	in := models.TierOverride{ToolOrVerb: "Bash", ActionTier: models.ActionTierDestructive}
	got, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if err != nil {
		t.Fatalf("CreateTierOverride() error = %v, want nil -- raising a NULL-tier catalog entry must be allowed", err)
	}
	if got.BuiltinTier != models.ActionTierReasoning {
		t.Errorf("BuiltinTier = %s, want %s (a NULL-tier row contributes no entry, so the baseline is the built-in resolution)",
			got.BuiltinTier, models.ActionTierReasoning)
	}

	assertExpectationsMet(t, mock)
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
	expectBaselineReads(mock, toolCatalogRows())
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
	expectBaselineReads(mock, toolCatalogRows())
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
	expectBaselineReads(mock, toolCatalogRows())
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

// --- LoadTierOverrides (the decision path's own read) ---

func tierOverrideLoadColumns() []string { return []string{"tool_or_verb", "action_tier"} }

// TestStore_LoadTierOverrides_Success pins the two things that distinguish
// this read from ListTierOverrides above: the shape (a map keyed by
// tool_or_verb, which is what authz.TierTable.Overrides is) and the column
// list (two columns -- no id, no created_by, and deliberately no
// builtin_tier, which the PDP must recompute live rather than trust).
func TestStore_LoadTierOverrides_Success(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTierOverridesQuery)).
		WillReturnRows(sqlmock.NewRows(tierOverrideLoadColumns()).
			AddRow("Bash", int64(models.ActionTierDestructive)).
			AddRow("Read", int64(models.ActionTierInternalModify)))
	mock.ExpectCommit()

	got, err := s.LoadTierOverrides(context.Background())
	if err != nil {
		t.Fatalf("LoadTierOverrides() error = %v", err)
	}
	want := map[string]models.ActionTier{
		"Bash": models.ActionTierDestructive,
		"Read": models.ActionTierInternalModify,
	}
	if !maps.Equal(got, want) {
		t.Errorf("LoadTierOverrides() = %v, want %v", got, want)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_LoadTierOverrides_EmptyIsNotAnError is the regression guard that
// makes turning this read on safe for every tenant that has no overrides --
// which was every tenant in production until this task, since nothing read
// the table at all. An empty result must be an ordinary empty map, never an
// error that would deny-and-audit a decision for a tenant that simply never
// wrote an override.
func TestStore_LoadTierOverrides_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTierOverridesQuery)).
		WillReturnRows(sqlmock.NewRows(tierOverrideLoadColumns()))
	mock.ExpectCommit()

	got, err := s.LoadTierOverrides(context.Background())
	if err != nil {
		t.Fatalf("LoadTierOverrides() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("LoadTierOverrides() = %v, want a non-nil empty map", got)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_LoadTierOverrides_OutOfRangeActionTierFailsLoudly is the same
// fail-loudly discipline scanFullTierOverride already holds, on the path
// where it matters most: a tier outside 0-4 must error, never decode as
// ActionTierReasoning (tier 0) and be honored as an override declaring the
// tool maximally harmless.
func TestStore_LoadTierOverrides_OutOfRangeActionTierFailsLoudly(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadTierOverridesQuery)).
		WillReturnRows(sqlmock.NewRows(tierOverrideLoadColumns()).AddRow("Read", int64(99)))
	mock.ExpectRollback()

	if _, err := s.LoadTierOverrides(context.Background()); err == nil {
		t.Fatal("LoadTierOverrides() error = nil, wanted an out-of-range action_tier to fail loudly")
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
	expectBaselineReads(mock, toolCatalogRows())
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

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock, toolCatalogRows())
	mock.ExpectRollback()

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
	expectBaselineReads(mock, toolCatalogRows())
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

// TestStore_CreateTierOverride_SiblingOverrideIsPartOfTheBaseline is the
// write-time end of TestDecide_SiblingOverrideIsBeneathAMoreSpecificRow
// (internal/pdpgrpc): the tenant already has "Bash" raised to DESTRUCTIVE, and
// a new "Bash:read" row at READ_ONLY is a lowering because deriveTierByName
// probes the composite key first. Refused here, so the PAP never writes a row
// the PDP would only drop on every decision.
//
// The catalog row is what makes the composite key reachable at all:
// Action.Verb is copied from tool_catalog.verb (extract.go), never
// caller-supplied, so without a Bash row carrying verb "read" no request could
// ever produce the key "Bash:read".
func TestStore_CreateTierOverride_SiblingOverrideIsPartOfTheBaseline(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectBaselineReads(mock,
		toolCatalogRows([]driver.Value{"Bash", nil, "read", nil, "command"}),
		[]driver.Value{"Bash", int64(models.ActionTierDestructive)},
	)
	mock.ExpectRollback()

	in := models.TierOverride{ToolOrVerb: "Bash:read", ActionTier: models.ActionTierReadOnly}
	_, err := s.CreateTierOverride(context.Background(), in, "operator-1")
	if !errors.Is(err, authz.ErrOverrideLowersTier) {
		t.Errorf("CreateTierOverride() error = %v, want authz.ErrOverrideLowersTier -- the tenant's existing "+
			"tenant-wide Bash override (DESTRUCTIVE) is beneath this more specific key", err)
	}

	assertExpectationsMet(t, mock)
}
