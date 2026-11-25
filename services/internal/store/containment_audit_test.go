package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

// TestContainmentReason_NamesAWideningAndStaysSilentOnANarrowing is the whole
// contract: the verdict is recorded only when a write WIDENS. A narrowing
// write that logged a verdict would train operators to ignore the event type.
func TestContainmentReason_NamesAWideningAndStaysSilentOnANarrowing(t *testing.T) {
	before := permset.Set{ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"}}
	wider := permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}}
	narrower := permset.Set{ClassificationCaps: map[string]string{"nato": "UNCLASSIFIED"}}

	if reason := containmentReason(before, wider); reason == "" {
		t.Error("raising a cap widens the grant and must produce a reason")
	}
	if reason := containmentReason(before, narrower); reason != "" {
		t.Errorf("lowering a cap narrows; want no reason, got %q", reason)
	}
	if reason := containmentReason(before, before); reason != "" {
		t.Errorf("an unchanged grant must produce no reason, got %q", reason)
	}
}

// Clearing a constraint is the widening most likely to be made by accident,
// because the API for it is a DELETE that looks like tidying up.
func TestContainmentReason_ClearingAConstraintIsAWidening(t *testing.T) {
	before := permset.Set{
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
	}
	after := permset.Set{ResourceConstraints: map[string]string{}}

	if reason := containmentReason(before, after); reason == "" {
		t.Error("clearing id_prefix widens the grant and must produce a reason")
	}
}

// TestContainmentReason_IntroducingARestrictionIsNotAWidening is the case
// permset.Contains gets deliberately BACKWARDS for this caller, and the
// reason containmentReason is more than a one-line wrapper around it.
//
// Contains refuses a child that introduces a cap or a constraint key its
// parent does not hold (contains.go's own doc comment: stricter than the
// lattice, on purpose, for delegation attenuation). Asked as a before/after
// question that rule inverts: an agent with no caps enforces NOTHING, so the
// first PUT that sets one -- the single most common write on this path --
// would be reported as a widening, and the same for the first resource
// constraint. Both of those are the narrowest write an operator ever makes.
func TestContainmentReason_IntroducingARestrictionIsNotAWidening(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after permset.Set
	}{
		{
			"the first cap an agent ever gets",
			permset.Set{ClassificationCaps: map[string]string{}},
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}},
		},
		{
			"the first resource constraint an agent ever gets",
			permset.Set{ResourceConstraints: map[string]string{}},
			permset.Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}},
		},
		{
			"a second hierarchy capped alongside an unchanged first",
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}},
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET", "commercial": "INTERNAL"}},
		},
		{
			"a prefix narrowed to a subtree",
			permset.Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}},
			permset.Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/sub/"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := containmentReason(tc.before, tc.after); reason != "" {
				t.Errorf("want no reason -- this write narrows; got %q", reason)
			}
		})
	}
}

// TestContainmentReason_ToolsNeedNoPreFill pins the claim containmentReason's
// own comment makes about the third dimension: Contains' tools clause is
// already a pure lattice rule, so the pre-fill neither helps nor harms it.
//
// The empty list is UNRESTRICTED here (permset.Set.Tools' own doc comment,
// models.Agent.HasTool), which is what makes the two middle cases the
// interesting ones -- they are the pair a reader's first guess gets
// backwards.
func TestContainmentReason_ToolsNeedNoPreFill(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after []string
		wantReason    bool
	}{
		{"a tool added to a restricted allowlist", []string{"Read"}, []string{"Read", "Bash"}, true},
		{"a tool removed from a restricted allowlist", []string{"Read", "Bash"}, []string{"Read"}, false},
		{"a restricted allowlist emptied, which means UNRESTRICTED", []string{"Read"}, []string{}, true},
		{"an unrestricted agent given a restricted allowlist", []string{}, []string{"Read"}, false},
		{"unchanged", []string{"Read"}, []string{"Read"}, false},
		{"unrestricted both sides", []string{}, []string{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason := containmentReason(
				permset.Set{Tools: tc.before}, permset.Set{Tools: tc.after})
			if got := reason != ""; got != tc.wantReason {
				t.Errorf("containmentReason(%v, %v) = %q; widening = %v, want %v",
					tc.before, tc.after, reason, got, tc.wantReason)
			}
		})
	}
}

// TestContainmentReason_WideningsAreStillNamed is the other half of the test
// above: suppressing the introduce-a-key case must not suppress the real
// widenings that live on the same two dimensions.
func TestContainmentReason_WideningsAreStillNamed(t *testing.T) {
	for _, tc := range []struct {
		name          string
		before, after permset.Set
	}{
		{
			"a hierarchy dropped from the caps",
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET", "commercial": "INTERNAL"}},
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}},
		},
		{
			"caps cleared entirely, which turns enforcement off",
			permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}},
			permset.Set{ClassificationCaps: map[string]string{}},
		},
		{
			"a prefix widened to a parent directory",
			permset.Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/sub/"}},
			permset.Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if containmentReason(tc.before, tc.after) == "" {
				t.Error("want a reason -- this write widens the grant")
			}
		})
	}
}

// TestContainmentReason_DoesNotMutateItsArguments pins the property the
// pre-fill makes easy to get wrong: containmentReason builds new maps rather
// than writing the after value's keys into the caller's before map, which
// would corrupt the very row the audit entry is about to describe.
func TestContainmentReason_DoesNotMutateItsArguments(t *testing.T) {
	before := permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET"}}
	after := permset.Set{ClassificationCaps: map[string]string{"nato": "SECRET", "commercial": "INTERNAL"}}

	containmentReason(before, after)

	if len(before.ClassificationCaps) != 1 {
		t.Errorf("before.ClassificationCaps = %v, want it untouched with one key", before.ClassificationCaps)
	}
}

// --- the store wiring ---

// These reuse agent_caps_test.go's expectCapsLoadAndWrite (writeAgentCaps'
// sequence up to its first audit entry's chain-tail read) rather than
// restating it, and pick up where it stops -- which is exactly where a
// widening write stops looking like every other one.

// TestClearAgentClassificationCaps_AuditsTheWidening is the deliverable:
// turning enforcement off is a widening, and it now leaves a second,
// hash-chained row saying so, in the SAME transaction as the write it
// describes.
//
// The second appendAuditTx call re-reads the chain tail. Against real
// Postgres that read sees the first entry this transaction just inserted
// (a transaction sees its own uncommitted writes), so the two rows chain
// onto each other correctly; sqlmock replays whatever rows a test hands it
// and cannot model that, so the tail is empty both times here.
func TestClearAgentClassificationCaps_AuditsTheWidening(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	var reason string

	expectCapsLoadAndWrite(mock, `{"nato":"SECRET"}`, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentCapsCleared)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsCapturingReason(&reason)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.ClearAgentClassificationCaps(context.Background(), id, "operator@example.com", now); err != nil {
		t.Fatalf("ClearAgentClassificationCaps() error = %v", err)
	}
	if !strings.HasPrefix(reason, "agent grant widened: ") {
		t.Errorf("containment Reason = %q, want it to start with %q", reason, "agent grant widened: ")
	}
	// The dimension, not just the prefix: a reason produced for some other
	// dimension would satisfy the prefix check alone and hide a verdict
	// computed against the wrong column.
	if !strings.Contains(reason, "nato") {
		t.Errorf("containment Reason = %q, want it to name the hierarchy whose cap was dropped", reason)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentClassificationCaps_NarrowingAuditsOneRow is the negative half.
// A write that lowers a cap appends exactly ONE audit row: any second
// expectation registered here would go unmet, and one unregistered append
// would fail the call outright.
func TestSetAgentClassificationCaps_NarrowingAuditsOneRow(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	expectLabelRules(mock, []models.ResourceLabelRule{
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
	})
	expectCapsLoadAndWrite(mock, `{"nato":"SECRET"}`, "UPDATE agents", sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentCapsSet)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	if _, err := s.SetAgentClassificationCaps(context.Background(), id,
		map[string]string{"nato": "CONFIDENTIAL"}, false, "operator@example.com", now); err != nil {
		t.Fatalf("SetAgentClassificationCaps() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentResourceConstraints_AuditsTheWidening proves the identical
// shape on the other write path, through its own before-read: a prefix
// replaced by a shallower one widens the agent's reach over the filesystem.
func TestSetAgentResourceConstraints_AuditsTheWidening(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	var reason string

	beforeJSON, err := json.Marshal(map[string]string{models.ResourceIDPrefixKey: "/workspace/sub/"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentConstraintsForUpdateQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"resource_constraints"}).AddRow(beforeJSON))
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentConstraintsSet)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsCapturingReason(&reason)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	if _, err := s.SetAgentResourceConstraints(context.Background(), id,
		map[string]string{models.ResourceIDPrefixKey: "/workspace/"}, "operator@example.com", now); err != nil {
		t.Fatalf("SetAgentResourceConstraints() error = %v", err)
	}
	if reason == "" {
		t.Fatal("no containment Reason captured -- the widening row was not appended")
	}
	if !strings.HasPrefix(reason, "agent grant widened: ") {
		t.Errorf("containment Reason = %q, want it to start with %q", reason, "agent grant widened: ")
	}
	// The dimension, not just the prefix: this write moves the resource
	// scope, and a non-empty reason naming some other dimension would pass a
	// bare emptiness check while proving the verdict was computed against
	// the wrong column.
	if !strings.Contains(reason, models.ResourceIDPrefixKey) {
		t.Errorf("containment Reason = %q, want it to name %s, the constraint this write widened",
			reason, models.ResourceIDPrefixKey)
	}
	assertExpectationsMet(t, mock)
}

// TestStore_UpdateAgent_AuditsAToolWidening is the third endpoint's proof,
// and the one with the widest blast radius: PUT /v1/agents/{id} is gated at
// RoleEditor, not RoleAdmin like the two sub-resources, and replacing a
// restricted allowlist with [] means EVERY tool
// (store.ErrAllowedToolsRequired says so verbatim). That write now leaves a
// second, hash-chained row naming what it widened.
func TestStore_UpdateAgent_AuditsAToolWidening(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC().Truncate(time.Second)
	var reason string

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentToolsForUpdateQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"allowed_tools"}).AddRow([]byte(`["Read"]`)))
	mock.ExpectQuery(regexp.QuoteMeta(updateAgentQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "updated_at", "classification_caps", "resource_constraints", "escalate_at"}).
			AddRow(now, now, []byte(`{}`), []byte(`{}`), nil))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentUpdated)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsCapturingReason(&reason)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	a := validAgent()
	a.AllowedTools = []string{} // "every tool" -- the widening
	if _, err := s.UpdateAgent(context.Background(), id, a, "operator-2", true); err != nil {
		t.Fatalf("UpdateAgent() error = %v", err)
	}
	if !strings.HasPrefix(reason, "agent grant widened: ") {
		t.Errorf("containment Reason = %q, want it to start with %q", reason, "agent grant widened: ")
	}
	if !strings.Contains(reason, "tool restriction") {
		t.Errorf("containment Reason = %q, want it to name the dropped tool restriction", reason)
	}
	assertExpectationsMet(t, mock)
}

// TestStore_UpdateAgent_NarrowingToolsAuditsOneRow is the negative half:
// removing a tool narrows, so the transaction appends exactly ONE audit row.
// A second, unregistered append would fail the call outright.
func TestStore_UpdateAgent_NarrowingToolsAuditsOneRow(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAgentToolsBeforeRead(mock, `["Read","Bash","Write"]`)
	mock.ExpectQuery(regexp.QuoteMeta(updateAgentQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "updated_at", "classification_caps", "resource_constraints", "escalate_at"}).
			AddRow(now, now, []byte(`{}`), []byte(`{}`), nil))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentUpdated)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, err := s.UpdateAgent(context.Background(), id, validAgent(), "operator-2", true); err != nil {
		t.Fatalf("UpdateAgent() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}
