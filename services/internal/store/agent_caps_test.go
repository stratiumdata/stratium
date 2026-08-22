package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// --- shared fixtures ---
//
// newMockStore, expectSetTenant, assertExpectationsMet (store_test.go),
// expectAdvisoryLock (audit_test.go), agentRowColumns/getAgentQuery
// (agent.go/agent_test.go), resourceLabelRuleCRUDColumns/
// listResourceLabelRulesQuery (resource_label.go/resource_label_test.go),
// toolCatalogRowColumns/listToolCatalogEntriesQuery (catalog.go/
// catalog_test.go), and strPtr (approval_test.go) already exist in this
// package and are reused here rather than duplicated under a second name.

// expectGetAgentRow registers the ordered expectation for one GetAgent call
// -- begin, set tenant, the row, commit. Used both for a direct
// GetAgentClassificationCaps read and for agentCapsView's own read (to learn
// AllowedTools). Columns this file's code never reads (Name, Provider,
// ModelID, TrustTier, Enabled, Suspended) get fixed placeholders, the same
// shape TestStore_GetAgent_Success (agent_test.go) already uses.
func expectGetAgentRow(mock sqlmock.Sqlmock, id uuid.UUID, allowedTools []string, classificationCaps map[string]string) {
	allowedToolsJSON, err := json.Marshal(allowedTools)
	if err != nil {
		panic(err)
	}
	capsJSON, err := json.Marshal(classificationCaps)
	if err != nil {
		panic(err)
	}
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getAgentQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(agentRowColumns()).
			AddRow(id.String(), testTenant, "caps-bot", "anthropic", "claude-opus",
				int64(models.TrustTierCertified), true, false, allowedToolsJSON, capsJSON, now, now))
	mock.ExpectCommit()
}

// expectLabelRules registers the ordered expectation for the
// ListResourceLabelRules call catchAllLevels makes -- begin, set tenant, the
// rows, commit.
func expectLabelRules(mock sqlmock.Sqlmock, rules []models.ResourceLabelRule) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	rows := sqlmock.NewRows(resourceLabelRuleCRUDColumns())
	for _, r := range rules {
		rows.AddRow(r.ID.String(), testTenant, r.Prefix, r.Hierarchy, r.Level)
	}
	mock.ExpectQuery(regexp.QuoteMeta(listResourceLabelRulesQuery)).WillReturnRows(rows)
	mock.ExpectCommit()
}

// expectCatalog registers the ordered expectation for the
// ListToolCatalogEntries call agentCapsView makes -- begin, set tenant, the
// rows, commit.
func expectCatalog(mock sqlmock.Sqlmock, entries []models.ToolCatalogEntry) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	rows := sqlmock.NewRows(toolCatalogRowColumns())
	for _, e := range entries {
		var actionTier any
		if e.ActionTier != nil {
			actionTier = int64(*e.ActionTier)
		}
		var resourceField, commandField any
		if e.ResourceField != nil {
			resourceField = *e.ResourceField
		}
		if e.CommandField != nil {
			commandField = *e.CommandField
		}
		rows.AddRow(e.ID.String(), testTenant, e.ToolName, actionTier, e.Verb, resourceField, commandField)
	}
	mock.ExpectQuery(regexp.QuoteMeta(listToolCatalogEntriesQuery)).WillReturnRows(rows)
	mock.ExpectCommit()
}

// expectLiveDelegations registers the ordered expectation for the
// countLiveDelegations call agentCapsView makes -- begin, set tenant, the
// count, commit.
func expectLiveDelegations(mock sqlmock.Sqlmock, count int) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(countLiveDelegationsQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
	mock.ExpectCommit()
}

// expectWriteAndAudit registers the ordered expectations common to
// writeAgentCaps -- begin, set tenant, the write itself (matched against
// queryPattern, a regexp fragment rather than the exact literal so one
// helper covers both SetAgentClassificationCaps' and
// ClearAgentClassificationCaps' calls, which differ only in the caps
// argument bound to $2), the advisory lock, an empty audit tail, the audit
// insert, and commit -- the same seven-step shape
// TestStore_CreateAgent_Success (agent_test.go) already pins for
// CreateAgent's own write+audit transaction.
func expectWriteAndAudit(mock sqlmock.Sqlmock, queryPattern string, writeRows *sqlmock.Rows) {
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(queryPattern).WillReturnRows(writeRows)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
}

// --- validateClassificationCaps ---

func TestValidateClassificationCaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		caps    map[string]string
		wantErr bool
	}{
		{"empty is valid and means off", map[string]string{}, false},
		{"nil is valid and means off", nil, false},
		{"known hierarchy and level", map[string]string{"nato": "CONFIDENTIAL"}, false},
		{"commercial hierarchy", map[string]string{"commercial": "INTERNAL"}, false},
		{"unknown hierarchy", map[string]string{"klingon": "SECRET"}, true},
		{"level from the wrong hierarchy", map[string]string{"nato": "INTERNAL"}, true},
		{"empty level", map[string]string{"nato": ""}, true},
		{"empty hierarchy key", map[string]string{"": "SECRET"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClassificationCaps(tc.caps)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err = %v, want it to wrap ErrInvalidRequest", err)
			}
		})
	}
}

// --- SetAgentClassificationCaps ---

// TestSetAgentClassificationCaps_RefusesWithoutCatchAll pins R7/R9's
// consequence for this call: a cap on "nato" with no prefix:"" rule for that
// hierarchy denies every resource classification.CheckCap cannot resolve, so
// the call refuses before writing anything. Only catchAllLevels' own
// ListResourceLabelRules read is expected -- the refusal happens before
// writeAgentCaps or agentCapsView are ever reached.
func TestSetAgentClassificationCaps_RefusesWithoutCatchAll(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	})

	_, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, false, "operator@example.com", now)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want it to wrap ErrConflict", err)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentClassificationCaps_AllowUncoveredOverrides proves
// allowUncovered bypasses the catch-all guard and the call runs to
// completion: catchAllLevels, the write+audit, then agentCapsView's own
// three reads (GetAgent for AllowedTools, the catalog, the live-delegation
// count) -- in that order, matching SetAgentClassificationCaps' real call
// sequence (catchAllLevels -> writeAgentCaps -> agentCapsView).
func TestSetAgentClassificationCaps_AllowUncoveredOverrides(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	})
	expectWriteAndAudit(mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	if _, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, true, "operator@example.com", now); err != nil {
		t.Fatalf("with allowUncovered: %v", err)
	}
	assertExpectationsMet(t, mock)
}

// --- ClearAgentClassificationCaps ---

func TestStore_ClearAgentClassificationCaps_WritesEmptyCapsAndAudits(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectWriteAndAudit(mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))

	if err := s.ClearAgentClassificationCaps(context.Background(), id, "operator@example.com", now); err != nil {
		t.Fatalf("ClearAgentClassificationCaps() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}

// TestStore_ClearAgentClassificationCaps_UnknownAgent pins writeAgentCaps'
// stated no-rows behavior: an UPDATE that matches no row means ErrNotFound,
// not a silent no-op success.
func TestStore_ClearAgentClassificationCaps_UnknownAgent(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}))
	mock.ExpectRollback()

	err := s.ClearAgentClassificationCaps(context.Background(), id, "operator@example.com", now)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	assertExpectationsMet(t, mock)
}

// --- GetAgentClassificationCaps ---

// TestStore_GetAgentClassificationCaps_Success covers the read-only sibling
// of Set: it changes nothing (no write+audit expectation is registered), and
// assembles the same advisory view from the agent's CURRENT stored caps.
func TestStore_GetAgentClassificationCaps_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	expectGetAgentRow(mock, id, []string{"Read", "Grep"}, map[string]string{"nato": "SECRET"})
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "nato", Level: "CONFIDENTIAL"},
	})
	expectGetAgentRow(mock, id, []string{"Read", "Grep"}, map[string]string{"nato": "SECRET"})
	expectCatalog(mock, []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
	})
	expectLiveDelegations(mock, 2)

	view, err := s.GetAgentClassificationCaps(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAgentClassificationCaps() error = %v", err)
	}
	if view.LiveDelegations != 2 {
		t.Errorf("LiveDelegations = %d, want 2", view.LiveDelegations)
	}
	if got := view.CatchAll["nato"]; got == nil || *got != "CONFIDENTIAL" {
		t.Errorf("CatchAll[nato] = %v, want *CONFIDENTIAL", got)
	}
	if !reflect.DeepEqual(view.UnsatisfiableTools, []string{"Grep"}) {
		t.Errorf("UnsatisfiableTools = %v, want [Grep]", view.UnsatisfiableTools)
	}
	assertExpectationsMet(t, mock)
}

// --- unsatisfiableTools ---

// An agent with allowed_tools == [] holds EVERY tool, so the warning must be
// computed against the whole catalog. Computing it against the empty slice
// returns no warnings for exactly the agents with the widest reach.
func TestUnsatisfiableTools_EmptyAllowedToolsMeansEveryTool(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
		{ToolName: "WebSearch", ResourceField: nil},
	}
	got := unsatisfiableTools([]string{}, catalog)
	want := []string{"Grep", "WebSearch"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsatisfiableTools([], catalog) = %v, want %v", got, want)
	}
}

func TestUnsatisfiableTools_RestrictedAgentIntersects(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
		{ToolName: "WebSearch", ResourceField: nil},
	}
	got := unsatisfiableTools([]string{"Read", "Grep"}, catalog)
	want := []string{"Grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
