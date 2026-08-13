package store

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"stratium/pkg/models"
)

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
