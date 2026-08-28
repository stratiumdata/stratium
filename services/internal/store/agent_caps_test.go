package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// eventTypeArgIndex is insertAuditQuery's zero-based position for event_type
// ($5 of 22 -- see that query's own column list, audit.go). Named for the
// same reason auditReasonArgIndex (resource_label_test.go) is: so a test
// that pins it says what it's pinning.
const eventTypeArgIndex = 4

// auditArgsWithEventType builds insertAuditQuery's 22 arguments, all
// unconstrained (sqlmock.AnyArg()) except event_type, pinned to want -- the
// identical AnyArg-except-one-index shape auditArgsWithReason
// (resource_label_test.go) already uses for the reason column.
func auditArgsWithEventType(want string) []driver.Value {
	args := make([]driver.Value, 22)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[eventTypeArgIndex] = want
	return args
}

// reasonArgIndex is insertAuditQuery's own zero-based position for `reason`
// -- the same index resource_label_test.go's own auditReasonArgIndex names,
// duplicated here (rather than reused across files in the same package)
// only because that constant is unexported and this file already keeps its
// own eventTypeArgIndex sibling the same way.
const reasonArgIndex = 17

// captureReasonArg is a sqlmock.Argument that always matches and copies the
// string it was compared against into *dst -- used where a test needs to
// read back what Reason writeAgentCaps actually sent, not merely assert a
// substring, e.g. to prove two writes audited two DIFFERENT reasons (ITEM 3).
type captureReasonArg struct{ dst *string }

func (c captureReasonArg) Match(v driver.Value) bool {
	if s, ok := v.(string); ok {
		*c.dst = s
	}
	return true
}

// auditArgsCapturingReason builds insertAuditQuery's 22 arguments, all
// unconstrained except reason, which is captured into *dst rather than
// asserted against here.
func auditArgsCapturingReason(dst *string) []driver.Value {
	args := make([]driver.Value, 22)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[reasonArgIndex] = captureReasonArg{dst: dst}
	return args
}

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
				int64(models.TrustTierCertified), true, false, allowedToolsJSON, capsJSON, []byte(`{}`), now, now))
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
		// classification.lookupCap folds case and treats two differently-cased
		// keys for one hierarchy as ambiguous, which CheckCap denies
		// unconditionally -- this function's own doc comment claims to reject
		// anything CheckCap could not act on, so this must be rejected here too.
		{"case-duplicate keys are ambiguous", map[string]string{"nato": "SECRET", "NATO": "CONFIDENTIAL"}, true},
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
// sequence (catchAllLevels -> writeAgentCaps -> agentCapsView). It also pins
// ITEM 7: CatchAll["nato"] is nil here (there is no catch-all rule for
// "nato" -- that is the whole reason this write needed the override), the
// exact field that flags the dangerous state, and this test must actually
// look at it, not just check err == nil. And ITEM 3: the audited Reason
// must say the override was used.
func TestSetAgentClassificationCaps_AllowUncoveredOverrides(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	})
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithReason("allow_uncovered=true")...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	view, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, true, "operator@example.com", now)
	if err != nil {
		t.Fatalf("with allowUncovered: %v", err)
	}
	if got := view.CatchAll["nato"]; got != nil {
		t.Errorf("CatchAll[nato] = %v, want nil -- no catch-all rule exists for nato, "+
			"this write only succeeded because of the override", got)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentClassificationCaps_AllowUncoveredIsAuditedVisibly pins ITEM 3
// from the whole-branch review directly: the spec's Risks section requires
// ?allow_uncovered=true to "appear in the audit entry" because it is this
// call's single most dangerous path, and an audit Reason indistinguishable
// from a normal guarded write would defeat that. Runs the identical cap
// write twice -- once guarded (a catch-all rule exists, allowUncovered is
// not even load-bearing) and once overridden (no catch-all rule,
// allowUncovered=true is the only reason the write succeeds) -- and asserts
// the two audited Reason strings actually differ, not merely that one of
// them happens to contain a substring.
func TestSetAgentClassificationCaps_AllowUncoveredIsAuditedVisibly(t *testing.T) {
	write := func(t *testing.T, rules []models.ResourceLabelRule, allowUncovered bool) string {
		t.Helper()
		s, mock := newMockStore(t)
		id, now := uuid.New(), time.Now().UTC()
		var reason string

		expectLabelRules(mock, rules)
		mock.ExpectBegin()
		expectSetTenant(mock)
		mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
		expectAdvisoryLock(mock)
		mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
		mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
			WithArgs(auditArgsCapturingReason(&reason)...).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		expectGetAgentRow(mock, id, nil, nil)
		expectCatalog(mock, nil)
		expectLiveDelegations(mock, 0)

		if _, err := s.SetAgentClassificationCaps(context.Background(), id,
			map[string]string{"nato": "CONFIDENTIAL"}, allowUncovered, "operator@example.com", now); err != nil {
			t.Fatalf("SetAgentClassificationCaps() error = %v", err)
		}
		assertExpectationsMet(t, mock)
		return reason
	}

	guardedReason := write(t, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	}, false)
	overriddenReason := write(t, []models.ResourceLabelRule{
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
	}, true)

	if strings.Contains(guardedReason, "allow_uncovered") {
		t.Errorf("guarded reason = %q, must not mention allow_uncovered", guardedReason)
	}
	if !strings.Contains(overriddenReason, "allow_uncovered=true") {
		t.Errorf("overridden reason = %q, want it to contain allow_uncovered=true", overriddenReason)
	}
	if guardedReason == overriddenReason {
		t.Errorf("both writes audited the identical reason %q -- the override is invisible in the chain", guardedReason)
	}
}

// TestSetAgentClassificationCaps_RefusesWhenOnlyOneOfTwoHierarchiesHasCatchAll
// pins the guard loop's direction: "commercial" (covered) sorts before
// "nato" (uncovered), so a guard that stopped after the first, satisfied
// hierarchy would wrongly let this request through. Both label-rule reads
// happen inside catchAllLevels' one ListResourceLabelRules call, before the
// guard loop runs at all.
//
// ITEM 4 (whole-branch review, spec defect): resource_label_rules is UNIQUE
// (tenant_id, prefix), not (tenant_id, prefix, hierarchy) -- migrations/
// 000019's own comment records this was deliberate, and that at most one
// prefix:"" rule can exist per tenant, in ONE hierarchy. That means a cap
// naming two hierarchies -- exactly this test's shape -- can NEVER have a
// catch-all satisfied for both at once: this ErrConflict is the ONLY
// reachable outcome for a multi-hierarchy cap without ?allow_uncovered=true,
// not merely one case among several this function can produce. The 409
// message says so (see the multiHierarchyNote branch in
// SetAgentClassificationCaps).
func TestSetAgentClassificationCaps_RefusesWhenOnlyOneOfTwoHierarchiesHasCatchAll(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "commercial", Level: "PUBLIC"},
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"}, // no prefix:"" rule for nato
	})

	_, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"commercial": "INTERNAL", "nato": "CONFIDENTIAL"}, false, "operator@example.com", now)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want it to wrap ErrConflict (nato has no catch-all, even though commercial does)", err)
	}
	if !strings.Contains(err.Error(), "only ONE catch-all") {
		t.Errorf("err = %v, want the message to explain that only one catch-all rule can exist per tenant", err)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentClassificationCaps_NormalizesCaseAndMatchesCatchAllCaseInsensitively
// pins IMPORTANT 1 and 2 together: a cap supplied as "NATO" against a rule
// stored as "nato" must both (a) find its catch-all -- no spurious 409 -- and
// (b) persist and report under the normalized lowercase key, not the
// caller's original casing.
func TestSetAgentClassificationCaps_NormalizesCaseAndMatchesCatchAllCaseInsensitively(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	expectWriteAndAudit(mock, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	view, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"NATO": "CONFIDENTIAL"}, false, "operator@example.com", now)
	if err != nil {
		t.Fatalf("SetAgentClassificationCaps() error = %v, want success -- \"NATO\" should match the \"nato\" catch-all rule", err)
	}
	if _, keptOriginalCasing := view.ClassificationCaps["NATO"]; keptOriginalCasing {
		t.Errorf("ClassificationCaps = %v, kept the caller's casing, want normalized to lowercase", view.ClassificationCaps)
	}
	if view.ClassificationCaps["nato"] != "CONFIDENTIAL" {
		t.Errorf("ClassificationCaps[nato] = %q, want CONFIDENTIAL", view.ClassificationCaps["nato"])
	}
	if got := view.CatchAll["nato"]; got == nil || *got != "UNCLASSIFIED" {
		t.Errorf("CatchAll[nato] = %v, want *UNCLASSIFIED (case-insensitive match to the stored rule)", got)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentClassificationCaps_RequiresNonEmptyCaps pins ITEM 1 from the
// whole-branch review: PUT must not be able to clear enforcement by
// omission, because the entire justification for classification-caps being
// a sub-resource rather than a field on PUT /v1/agents/{id} is that clearing
// is an explicit DELETE. A nil map (what an absent or misspelled
// classification_caps key also decodes to, at this layer -- putAgentCaps'
// decodeJSON never distinguishes them) and an explicit empty map must both
// be refused, with allowUncovered=true proving the override cannot
// substitute for a non-empty cap either -- it only ever widens what a
// non-empty cap is allowed to do. The refusal must happen before any query
// runs (no mock expectations registered here at all), so the store is safe
// for any caller, not only cmd/stratium-pap's handler.
func TestSetAgentClassificationCaps_RequiresNonEmptyCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps map[string]string
	}{
		{"nil map (also what an absent or misspelled key decodes to)", nil},
		{"explicit empty map", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			id, now := uuid.New(), time.Now().UTC()

			_, err := s.SetAgentClassificationCaps(context.Background(), id, tc.caps, true, "operator@example.com", now)
			if !errors.Is(err, ErrClassificationCapsRequired) {
				t.Fatalf("err = %v, want ErrClassificationCapsRequired", err)
			}
			if !errors.Is(err, ErrInvalidRequest) {
				t.Errorf("err = %v, want it to wrap ErrInvalidRequest (so writeStoreError maps it to 400)", err)
			}
			if !strings.Contains(err.Error(), "DELETE") {
				t.Errorf("err = %v, want it to name DELETE as the way to turn enforcement off", err)
			}
			assertExpectationsMet(t, mock) // refused before catchAllLevels' own query, even with the override set
		})
	}
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

// TestStore_GetAgentClassificationCaps_FoldsCaseLikeSet pins ITEM 5: Set
// folds a cap's hierarchy key to lowercase before persisting
// (normalizeClassificationCaps), so every row this API itself ever wrote is
// already lowercase -- but a row written some other way (direct SQL, a row
// predating this normalization) can carry any casing. catchAllLevels' own
// keys are always lowercase (its own doc comment), so without folding on
// the read path too, a stored "NATO" would look up CatchAll under the wrong
// case and report CatchAll["NATO"] = nil -- a false "everything under nato
// denies" reading of a cap that in fact resolves fine. GET must fold the
// same way PUT does.
func TestStore_GetAgentClassificationCaps_FoldsCaseLikeSet(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	rawCaps := map[string]string{"NATO": "SECRET"} // as if written directly by SQL, uppercase

	expectGetAgentRow(mock, id, nil, rawCaps)
	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "nato", Level: "CONFIDENTIAL"},
	})
	expectGetAgentRow(mock, id, nil, rawCaps)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	view, err := s.GetAgentClassificationCaps(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAgentClassificationCaps() error = %v", err)
	}
	if got := view.CatchAll["nato"]; got == nil || *got != "CONFIDENTIAL" {
		t.Errorf("CatchAll[nato] = %v, want *CONFIDENTIAL -- GET must fold case the same way PUT does", got)
	}
	if _, keptOriginalCasing := view.ClassificationCaps["NATO"]; keptOriginalCasing {
		t.Errorf("ClassificationCaps = %v, kept the row's original casing, want normalized to lowercase", view.ClassificationCaps)
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

// A command_field tool CAN satisfy a cap: its command's paths become resource
// identities (internal/authz.ShellResourceIDs) and the strictest resulting
// label decides. Before 2026-08-28 it could not, and this function tested
// ResourceField alone -- so it reported Bash as unsatisfiable, which an
// operator reads as guidance (docs/default-posture.md §4 sends them here).
//
// No existing case carried a command_field row, which is why that went
// unnoticed. This one exists so it cannot again.
func TestUnsatisfiableTools_ACommandFieldToolIsSatisfiable(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Bash", CommandField: strPtr("command")},
		{ToolName: "Grep"},
	}
	got := unsatisfiableTools([]string{}, catalog)
	want := []string{"Grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unsatisfiableTools([], catalog) = %v, want %v — a command_field tool derives "+
			"identities from the paths its command names, so it is not unsatisfiable", got, want)
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

// TestUnsatisfiableTools_RestrictedAgentIncludesUncataloguedTools pins ITEM
// 2 from the whole-branch review: a tool named in allowed_tools with NO
// catalog row at all produces no resource id at decision time either --
// exactly like a catalogued tool with a nil resource_field -- and for a
// RESTRICTED agent that tool is enumerable (allowed_tools is a finite,
// known list), so it belongs in this warning too. Before this fix, a
// tenant with a partial catalog got unsatisfiable_tools: [] for every
// uncatalogued tool it had actually granted.
func TestUnsatisfiableTools_RestrictedAgentIncludesUncataloguedTools(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
		// "Frobnicate" has no catalog row at all.
	}
	got := unsatisfiableTools([]string{"Read", "Grep", "Frobnicate"}, catalog)
	want := []string{"Frobnicate", "Grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestUnsatisfiableTools_UnrestrictedAgentCannotEnumerateUncataloguedTools
// pins the other half of ITEM 2's ruling: an UNRESTRICTED agent's
// allowed_tools is empty, so there is no finite list of uncatalogued tool
// names to scan -- the warning can only ever cover what the catalog itself
// contains for such an agent, a real and permanent gap this function's own
// doc comment must state, not silently fill in.
func TestUnsatisfiableTools_UnrestrictedAgentCannotEnumerateUncataloguedTools(t *testing.T) {
	catalog := []models.ToolCatalogEntry{
		{ToolName: "Read", ResourceField: strPtr("file_path")},
		{ToolName: "Grep", ResourceField: nil},
	}
	got := unsatisfiableTools([]string{}, catalog)
	want := []string{"Grep"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v -- an unrestricted agent's uncatalogued tools cannot be enumerated", got, want)
	}
}
