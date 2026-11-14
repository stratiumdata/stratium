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

	"github.com/stratiumdata/stratium/pkg/models"
)

// tierPtr builds a fixed, non-NULL *models.ActionTier for a
// models.ToolCatalogEntry fixture -- spelled out explicitly rather than via
// a bare &value composite literal, matching this package's own precedent
// (delegation_test.go's escalate_at fixtures) for a pointer field whose nil-
// ness is itself meaningful (ToolCatalogEntry.ActionTier's own doc comment).
func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

// toolCatalogRowColumns is the seven-column order every PAP CRUD query in
// this file selects (getToolCatalogEntryQuery, listToolCatalogEntriesQuery)
// -- id and tenant_id first, unlike toolCatalogColumns above, which is
// loadToolCatalogQuery's OWN five-column, PDP-facing order with neither.
func toolCatalogRowColumns() []string {
	return []string{"id", "tenant_id", "tool_name", "action_tier", "verb", "resource_field", "command_field"}
}

// toolCatalogColumns is loadToolCatalogQuery's column order, factored out
// since every LoadToolCatalog test below builds rows against it.
func toolCatalogColumns() []string {
	return []string{"tool_name", "action_tier", "verb", "resource_field", "command_field"}
}

// TestStore_LoadToolCatalog_RoundTripsFieldForField proves a full catalog
// loads intact, in the exact order the brief requires — begin, THEN set the
// tenant, THEN the data query, THEN commit, the same property
// TestStore_LoadAgent_Success documents for its own query — and that
// resource_field and command_field, adjacent in both the SELECT list and
// the Scan call, land in the right struct field even though each row here
// sets only one of the two. Two rows, five scanned fields each, and no
// value shared across any of them (case included: "search" here is never
// "Search" elsewhere): a transposition anywhere in scanToolCatalogRows'
// Scan(...) call — resource_field/command_field swapped, or tool_name/verb
// swapped — shows up as a wrong assertion on a specific field, never as a
// coincidental pass. This project has shipped a fixture that couldn't tell
// a mixup from correct behavior before, most recently in Phase 7 Task 1;
// this fixture is built specifically so that can't happen here.
func TestStore_LoadToolCatalog_RoundTripsFieldForField(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).
		WillReturnRows(sqlmock.NewRows(toolCatalogColumns()).
			// A resource field, no command field — the ordinary case the
			// migration's own comment describes.
			AddRow("mcp__github__search_issues", int64(models.ActionTierReadOnly), "search", "repository", nil).
			// A command field, no resource field — the shell-shaped case.
			AddRow("mcp__infra__run_shell", int64(models.ActionTierDestructive), "execute", nil, "cmd"))
	mock.ExpectCommit()

	got, err := s.LoadToolCatalog(context.Background())
	if err != nil {
		t.Fatalf("LoadToolCatalog() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("LoadToolCatalog() returned %d entries, want 2", len(got))
	}

	first, second := got[0], got[1]

	if first.ToolName != "mcp__github__search_issues" {
		t.Errorf("got[0].ToolName = %q, want %q", first.ToolName, "mcp__github__search_issues")
	}
	if first.ActionTier == nil || *first.ActionTier != models.ActionTierReadOnly {
		t.Errorf("got[0].ActionTier = %v, want %v", first.ActionTier, models.ActionTierReadOnly)
	}
	if first.Verb != "search" {
		t.Errorf("got[0].Verb = %q, want %q", first.Verb, "search")
	}
	if first.ResourceField == nil || *first.ResourceField != "repository" {
		t.Errorf("got[0].ResourceField = %v, want %q", first.ResourceField, "repository")
	}
	if first.CommandField != nil {
		t.Errorf("got[0].CommandField = %v, want nil (NULL column)", first.CommandField)
	}

	if second.ToolName != "mcp__infra__run_shell" {
		t.Errorf("got[1].ToolName = %q, want %q", second.ToolName, "mcp__infra__run_shell")
	}
	if second.ActionTier == nil || *second.ActionTier != models.ActionTierDestructive {
		t.Errorf("got[1].ActionTier = %v, want %v", second.ActionTier, models.ActionTierDestructive)
	}
	if second.Verb != "execute" {
		t.Errorf("got[1].Verb = %q, want %q", second.Verb, "execute")
	}
	if second.ResourceField != nil {
		t.Errorf("got[1].ResourceField = %v, want nil (NULL column)", second.ResourceField)
	}
	if second.CommandField == nil || *second.CommandField != "cmd" {
		t.Errorf("got[1].CommandField = %v, want %q", second.CommandField, "cmd")
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no catalog rows — every tenant until the control plane
// populates one — is an ordinary, empty result, never an error a caller
// might mistake for "the catalog could not be loaded."
func TestStore_LoadToolCatalog_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).
		WillReturnRows(sqlmock.NewRows(toolCatalogColumns()))
	mock.ExpectCommit()

	got, err := s.LoadToolCatalog(context.Background())
	if err != nil {
		t.Fatalf("LoadToolCatalog() error = %v, want nil for a tenant with no catalog rows", err)
	}
	if got == nil {
		t.Error("LoadToolCatalog() = nil, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("LoadToolCatalog() = %+v, want empty", got)
	}

	assertExpectationsMet(t, mock)
}

// The tenant-set statement failing must abort before the data query ever
// runs, and must roll back — the same property TestStore_LoadAgent_SetTenantFails
// pins for beginTenantTx's other callers. This is also the test a mutation
// dropping LoadToolCatalog's beginTenantTx call would fail: without it,
// nothing ever issues the SET-tenant exec this test expects first, so
// sqlmock reports an unexpected call the moment the (unscoped) SELECT
// arrives instead.
func TestStore_LoadToolCatalog_SetTenantFailsRollsBack(t *testing.T) {
	s, mock := newMockStore(t)
	setErr := errors.New("invalid_parameter_value")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(setTenantQuery)).
		WithArgs(testTenant).
		WillReturnError(setErr)
	mock.ExpectRollback()

	_, err := s.LoadToolCatalog(context.Background())
	if err == nil {
		t.Fatal("LoadToolCatalog() error = nil, want error when SET LOCAL fails")
	}

	assertExpectationsMet(t, mock)
}

// A query failure must propagate and must still roll back.
func TestStore_LoadToolCatalog_QueryErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	_, err := s.LoadToolCatalog(context.Background())
	if err == nil {
		t.Fatal("LoadToolCatalog() error = nil, want error")
	}

	assertExpectationsMet(t, mock)
}

// An action_tier outside the valid ActionTier range must fail loudly rather
// than silently decode to ActionTierReasoning (its Go zero value) and read
// back as though the tenant declared this tool harmless — the same
// fail-closed requirement scanDelegation and scanApproval apply to their
// own tier columns. Must roll back, not commit a partially-scanned catalog.
func TestStore_LoadToolCatalog_ActionTierOutOfRangeFailsAndRollsBack(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).
		WillReturnRows(sqlmock.NewRows(toolCatalogColumns()).
			AddRow("BadTool", int64(99), "verb", nil, nil)) // 99 is out of the 0-4 range
	mock.ExpectRollback()

	got, err := s.LoadToolCatalog(context.Background())
	if err == nil {
		t.Fatal("LoadToolCatalog() error = nil, want a decode error for an out-of-range action_tier")
	}
	if got != nil {
		t.Errorf("LoadToolCatalog() = %+v, want nil on decode failure", got)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_LoadToolCatalog_NullActionTierScansAsNilNotZero is the
// scan-layer half of the nullable action_tier fix
// (migrations/000014_tool_catalog_nullable_tier): a NULL action_tier column
// must decode to a nil *models.ActionTier, never a pointer to
// ActionTierReasoning (its underlying zero value). The distinction is not
// cosmetic — internal/authz.BuildTierCatalog reads a nil ActionTier as "no
// fixed tier, defer to the command classifier" and any non-nil one
// (including a pointer to REASONING) as "fix this tool at this exact
// tier," so a scan that silently defaulted NULL to a zero-valued pointer
// would fix every such tool at ActionTierReasoning instead of deferring to
// per-command classification — the same "corrupt row must error or decode
// honestly, never as though the tenant declared this tool harmless"
// discipline TestStore_LoadToolCatalog_ActionTierOutOfRangeFailsAndRollsBack
// already holds this column to for an out-of-range value.
func TestStore_LoadToolCatalog_NullActionTierScansAsNilNotZero(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadToolCatalogQuery)).
		WillReturnRows(sqlmock.NewRows(toolCatalogColumns()).
			AddRow("Bash", nil, "execute", nil, "command"))
	mock.ExpectCommit()

	got, err := s.LoadToolCatalog(context.Background())
	if err != nil {
		t.Fatalf("LoadToolCatalog() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("LoadToolCatalog() returned %d entries, want 1", len(got))
	}
	if got[0].ActionTier != nil {
		t.Fatalf("got[0].ActionTier = %v, want nil (NULL column) — not a pointer to its zero value", got[0].ActionTier)
	}
	if got[0].CommandField == nil || *got[0].CommandField != "command" {
		t.Errorf("got[0].CommandField = %v, want %q", got[0].CommandField, "command")
	}

	assertExpectationsMet(t, mock)
}

// --- declaredTierForAudit ---

// TestDeclaredTierForAudit pins the one property that matters for this
// table's audit entries: a NULL/nil tier and a REAL tier of REASONING (0)
// must never collide on the wire, the same "nil is not the same fact as the
// zero value" discipline this table's own migration comment
// (000014_tool_catalog_nullable_tier) states for the column itself.
func TestDeclaredTierForAudit(t *testing.T) {
	tests := []struct {
		name string
		tier *models.ActionTier
		want int16
	}{
		{"nil tier (Bash-shaped, classify by command_field) is the -1 sentinel, not 0", nil, -1},
		{"REASONING itself still round-trips as its real value 0, not confused with nil", tierPtr(models.ActionTierReasoning), 0},
		{"a non-zero tier round-trips unchanged", tierPtr(models.ActionTierDestructive), 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := declaredTierForAudit(tt.tier); got != tt.want {
				t.Errorf("declaredTierForAudit(%v) = %d, want %d", tt.tier, got, tt.want)
			}
		})
	}
}

// --- CreateToolCatalogEntry ---

// TestStore_CreateToolCatalogEntry_AllThreeRowStatesPersist is T1's own
// positive proof: every shape the schema's tool_catalog_tier_or_command_field
// CHECK allows (migrations/000014_tool_catalog_nullable_tier) — a fixed
// tier alone, a NULL tier with a command_field (Bash's own shape: "extract
// that field and classify it with the command classifier"), and both
// together — is accepted and persisted through the identical code path,
// proven with a consumed write expectation (not merely err == nil) for
// each. Getting the NULL-tier-plus-command_field shape wrong is Phase 8's
// own regression (migrations/000014's leading comment), so that case gets
// its own explicit assertion, not just a shared loop body.
func TestStore_CreateToolCatalogEntry_AllThreeRowStatesPersist(t *testing.T) {
	resourceField := "file_path"
	commandField := "command"
	tests := []struct {
		name string
		e    models.ToolCatalogEntry
	}{
		{"fixed tier alone", models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), Verb: "read", ResourceField: &resourceField}},
		{"NULL tier with command_field -- Bash's own shape", models.ToolCatalogEntry{ToolName: "Bash", ActionTier: nil, Verb: "execute", CommandField: &commandField}},
		{"both a fixed tier and a command_field", models.ToolCatalogEntry{ToolName: "mcp__infra__run", ActionTier: tierPtr(models.ActionTierDestructive), Verb: "execute", CommandField: &commandField}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			id := uuid.New()
			now := time.Now().UTC().Truncate(time.Second)

			var wantTier any
			if tt.e.ActionTier != nil {
				wantTier = int64(*tt.e.ActionTier)
			}
			var wantResourceField, wantCommandField any
			if tt.e.ResourceField != nil {
				wantResourceField = *tt.e.ResourceField
			}
			if tt.e.CommandField != nil {
				wantCommandField = *tt.e.CommandField
			}

			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectQuery(regexp.QuoteMeta(insertToolCatalogQuery)).
				WithArgs(testTenant, tt.e.ToolName, wantTier, tt.e.Verb, wantResourceField, wantCommandField).
				WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
			expectAdvisoryLock(mock)
			mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
			mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()

			got, err := s.CreateToolCatalogEntry(context.Background(), tt.e, "operator-1", now)
			if err != nil {
				t.Fatalf("CreateToolCatalogEntry() error = %v, want nil", err)
			}
			if got.ID != id {
				t.Errorf("ID = %s, want %s (the RETURNING value)", got.ID, id)
			}
			if got.TenantID != testTenant {
				t.Errorf("TenantID = %q, want %q", got.TenantID, testTenant)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_CreateToolCatalogEntry_EmptyToolNameRefusedBeforePersisting is
// the required-field half of validateToolCatalogFields's own proof.
func TestStore_CreateToolCatalogEntry_EmptyToolNameRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	e := models.ToolCatalogEntry{ToolName: "", ActionTier: tierPtr(models.ActionTierReadOnly)}
	_, err := s.CreateToolCatalogEntry(context.Background(), e, "operator-1", time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreateToolCatalogEntry() error = %v, want ErrInvalidRequest", err)
	}

	assertExpectationsMet(t, mock) // zero expectations: nothing reached the database
}

// TestStore_CreateToolCatalogEntry_MissingTierAndCommandFieldRefusedBeforePersisting
// is the direct proof for the required mutation "let a catalog row with
// neither a tier nor a command_field through," at the Go-side proactive
// layer: validateToolCatalogFields refuses before beginTenantTx is ever
// called, proven by the zero-expectation mock — if a mutant deleted this
// check, the request would instead reach the (empty) mock and fail with
// sqlmock's own "was not expected" error, not this specific errors.Is
// assertion. TestIntegration_ToolCatalog_CreateWithNeitherTierNorCommandField
// (catalog_integration_test.go, build-tagged integration) is this same
// mutation's OTHER, independent survivor: the database's own CHECK
// constraint, proven live with this Go-side check still in place, so
// removing this test's own layer alone cannot silently leave the row
// writable.
func TestStore_CreateToolCatalogEntry_MissingTierAndCommandFieldRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	e := models.ToolCatalogEntry{ToolName: "mystery-tool", ActionTier: nil, CommandField: nil}
	_, err := s.CreateToolCatalogEntry(context.Background(), e, "operator-1", time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreateToolCatalogEntry() error = %v, want ErrInvalidRequest", err)
	}

	assertExpectationsMet(t, mock) // zero expectations: nothing reached the database
}

// TestStore_CreateToolCatalogEntry_CheckViolationSurfacesAsInvalidRequest is
// isCheckViolation's own proof, independent of validateToolCatalogFields
// above: even past the Go-side check (this fixture sets ActionTier, so it
// would sail through validateToolCatalogFields untouched), a check_violation
// Postgres actually returns on the INSERT must still map to ErrInvalidRequest
// (400 via cmd/stratium-pap/respond.go's writeStoreError), never fall
// through to the unrecognized-error, 500-producing default case — the task
// brief's own words, "confirm the API surfaces that rather than crashing."
func TestStore_CreateToolCatalogEntry_CheckViolationSurfacesAsInvalidRequest(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertToolCatalogQuery)).
		WillReturnError(&pq.Error{Code: sqlStateCheckViolation, Message: `new row for relation "tool_catalog" violates check constraint "tool_catalog_tier_or_command_field"`})
	mock.ExpectRollback()

	e := models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly)}
	_, err := s.CreateToolCatalogEntry(context.Background(), e, "operator-1", time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreateToolCatalogEntry() error = %v, want errors.Is(_, ErrInvalidRequest), not an unrecognised 500-producing error", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreateToolCatalogEntry_DuplicateToolNameIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertToolCatalogQuery)).
		WillReturnError(&pq.Error{Code: sqlStateUniqueViolation, Message: `duplicate key value violates unique constraint "tool_catalog_tenant_id_tool_name_key"`})
	mock.ExpectRollback()

	e := models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly)}
	_, err := s.CreateToolCatalogEntry(context.Background(), e, "operator-1", time.Now())
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("CreateToolCatalogEntry() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateToolCatalogEntry_AuditFailureRollsBackWrite is N4's own
// proof for this file — see policy_test.go's
// TestStore_CreatePolicy_AuditFailureRollsBackWrite for the full reasoning
// this test reproduces for tool_catalog: the INSERT succeeds, but the audit
// append's own advisory-lock step fails, and because both share one
// transaction, ExpectRollback (never ExpectCommit) is the only remaining
// registered expectation.
func TestStore_CreateToolCatalogEntry_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	lockErr := errors.New("connection reset mid-audit")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertToolCatalogQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New().String()))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).WillReturnError(lockErr)
	mock.ExpectRollback()

	e := models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly)}
	if _, err := s.CreateToolCatalogEntry(context.Background(), e, "operator-1", time.Now()); err == nil {
		t.Fatal("CreateToolCatalogEntry() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// --- GetToolCatalogEntry ---

func TestStore_GetToolCatalogEntry_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	resourceField := "file_path"

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getToolCatalogEntryQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(toolCatalogRowColumns()).
			AddRow(id.String(), testTenant, "Read", int64(models.ActionTierReadOnly), "read", resourceField, nil))
	mock.ExpectCommit()

	got, err := s.GetToolCatalogEntry(context.Background(), id)
	if err != nil {
		t.Fatalf("GetToolCatalogEntry() error = %v", err)
	}
	if got.ToolName != "Read" || got.ActionTier == nil || *got.ActionTier != models.ActionTierReadOnly {
		t.Errorf("GetToolCatalogEntry() = %+v, want ToolName=Read ActionTier=READ_ONLY", got)
	}
	if got.ResourceField == nil || *got.ResourceField != resourceField {
		t.Errorf("ResourceField = %v, want %q", got.ResourceField, resourceField)
	}
	if got.CommandField != nil {
		t.Errorf("CommandField = %v, want nil (NULL column)", got.CommandField)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_GetToolCatalogEntry_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getToolCatalogEntryQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.GetToolCatalogEntry(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetToolCatalogEntry() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- ListToolCatalogEntries ---

func TestStore_ListToolCatalogEntries_Success(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listToolCatalogEntriesQuery)).
		WillReturnRows(sqlmock.NewRows(toolCatalogRowColumns()).
			AddRow(uuid.New().String(), testTenant, "Bash", nil, "execute", nil, "command").
			AddRow(uuid.New().String(), testTenant, "Read", int64(models.ActionTierReadOnly), "read", "file_path", nil))
	mock.ExpectCommit()

	got, err := s.ListToolCatalogEntries(context.Background())
	if err != nil {
		t.Fatalf("ListToolCatalogEntries() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListToolCatalogEntries() returned %d entries, want 2", len(got))
	}
	if got[0].ActionTier != nil {
		t.Errorf("got[0] (Bash) ActionTier = %v, want nil", got[0].ActionTier)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_ListToolCatalogEntries_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listToolCatalogEntriesQuery)).WillReturnRows(sqlmock.NewRows(toolCatalogRowColumns()))
	mock.ExpectCommit()

	got, err := s.ListToolCatalogEntries(context.Background())
	if err != nil {
		t.Fatalf("ListToolCatalogEntries() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListToolCatalogEntries() = %v, want a non-nil empty slice", got)
	}

	assertExpectationsMet(t, mock)
}

// --- UpdateToolCatalogEntry ---

func TestStore_UpdateToolCatalogEntry_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	commandField := "command"

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateToolCatalogEntryQuery)).
		WithArgs("Bash", nil, "execute", nil, commandField, id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(id.String()))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	// Moves the row from a fixed tier to the NULL-tier/command_field shape
	// -- an update is a full replace, so this must be as legal as any other
	// transition between this table's three valid states.
	e := models.ToolCatalogEntry{ToolName: "Bash", ActionTier: nil, Verb: "execute", CommandField: &commandField}
	got, err := s.UpdateToolCatalogEntry(context.Background(), id, e, "operator-2", time.Now())
	if err != nil {
		t.Fatalf("UpdateToolCatalogEntry() error = %v", err)
	}
	if got.ID != id || got.TenantID != testTenant {
		t.Errorf("UpdateToolCatalogEntry() = %+v, want ID=%s TenantID=%s", got, id, testTenant)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_UpdateToolCatalogEntry_MissingTierAndCommandFieldRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)

	e := models.ToolCatalogEntry{ToolName: "Bash", ActionTier: nil, CommandField: nil}
	_, err := s.UpdateToolCatalogEntry(context.Background(), uuid.New(), e, "operator-1", time.Now())
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("UpdateToolCatalogEntry() error = %v, want ErrInvalidRequest", err)
	}

	assertExpectationsMet(t, mock) // zero expectations: nothing reached the database
}

func TestStore_UpdateToolCatalogEntry_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updateToolCatalogEntryQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	e := models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly)}
	if _, err := s.UpdateToolCatalogEntry(context.Background(), id, e, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateToolCatalogEntry() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}
