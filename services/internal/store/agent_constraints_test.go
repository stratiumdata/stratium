package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// Write-time validation is what lets the decision path use a bare
// strings.HasPrefix with no boundary logic. If these rules move or weaken,
// internal/authz.satisfiesIDPrefix becomes unsafe.
func TestValidateResourceConstraints(t *testing.T) {
	cases := []struct {
		name        string
		constraints map[string]string
		wantErr     string
	}{
		{"a well-formed prefix", map[string]string{models.ResourceIDPrefixKey: "/workspace/"}, ""},
		{"no constraints at all", map[string]string{}, ""},
		{"an opaque exact key is accepted", map[string]string{"tenant": "acme"}, ""},

		{
			"a prefix without a trailing slash",
			map[string]string{models.ResourceIDPrefixKey: "/workspace"},
			"must end with",
		},
		{
			"an empty prefix",
			map[string]string{models.ResourceIDPrefixKey: ""},
			"must not be empty",
		},
		{
			"a prefix containing a traversal segment",
			map[string]string{models.ResourceIDPrefixKey: "/workspace/../"},
			"..",
		},
		{"an empty key", map[string]string{"": "x"}, "must not be empty"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateResourceConstraints(tc.constraints)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateResourceConstraints(%v) = %v, want nil", tc.constraints, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateResourceConstraints(%v) = nil, want an error naming %q",
					tc.constraints, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// A trailing-slash rejection must be actionable: the operator's next move is
// to add the slash, and the message should say so.
func TestValidateResourceConstraints_TrailingSlashErrorExplainsWhy(t *testing.T) {
	err := validateResourceConstraints(map[string]string{models.ResourceIDPrefixKey: "/workspace"})
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "/workspace/") {
		t.Errorf("error = %q, want it to show the corrected form", err)
	}
}

// --- SetAgentResourceConstraints / ClearAgentResourceConstraints / GetAgentResourceConstraints ---
//
// These reuse newMockStore, expectSetTenant, assertExpectationsMet
// (store_test.go), expectAdvisoryLock (audit_test.go), auditArgsWithEventType/
// auditArgsCapturingReason (agent_caps_test.go), and expectGetAgentRow/
// expectCatalog/expectLiveDelegations (agent_caps_test.go) rather than
// duplicating any of them -- the same package, the same fixtures.

// expectConstraintsBeforeRead registers writeAgentConstraints' locking read
// of the scope this write is about to replace -- the first statement in that
// transaction since Task 7, which needs a baseline inside the transaction to
// judge the write against (containment_audit.go). beforeJSON is the column's
// stored bytes; `{}` (an agent with no scope yet) is what every test here
// wants, because setting a scope where there was none NARROWS, so no
// containment entry follows and these sequences keep their single audit row.
func expectConstraintsBeforeRead(mock sqlmock.Sqlmock, beforeJSON string) {
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentConstraintsForUpdateQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"resource_constraints"}).AddRow([]byte(beforeJSON)))
}

// TestSetAgentResourceConstraints_Success proves the real call sequence
// (writeAgentConstraints's write+audit, then agentConstraintsView's own three
// reads -- GetAgent for AllowedTools, the catalog, the live-delegation count)
// and that the audited Reason is renderConstraints' deterministic rendering,
// not some other text.
func TestSetAgentResourceConstraints_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()
	var reason string

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectConstraintsBeforeRead(mock, `{}`)
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsCapturingReason(&reason)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectGetAgentRow(mock, id, []string{"Read", "Grep"}, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 2)

	view, err := s.SetAgentResourceConstraints(context.Background(), id,
		map[string]string{models.ResourceIDPrefixKey: "/workspace/"}, "operator@example.com", now)
	if err != nil {
		t.Fatalf("SetAgentResourceConstraints() error = %v", err)
	}
	if view.AgentID != id {
		t.Errorf("AgentID = %s, want %s", view.AgentID, id)
	}
	if view.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("ResourceConstraints = %v, want id_prefix=/workspace/", view.ResourceConstraints)
	}
	if view.LiveDelegations != 2 {
		t.Errorf("LiveDelegations = %d, want 2", view.LiveDelegations)
	}
	if reason != "resource_constraints={id_prefix=/workspace/}" {
		t.Errorf("audited Reason = %q, want the deterministic renderConstraints rendering", reason)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentResourceConstraints_RejectsInvalidPrefix proves the refusal
// happens before anything reaches the database -- the whole point of
// validateResourceConstraints running first (SetAgentResourceConstraints'
// own doc comment).
func TestSetAgentResourceConstraints_RejectsInvalidPrefix(t *testing.T) {
	s, mock := newMockStore(t)

	_, err := s.SetAgentResourceConstraints(context.Background(), uuid.New(),
		map[string]string{models.ResourceIDPrefixKey: "/workspace"}, "operator@example.com", time.Now())
	if !errors.Is(err, ErrInvalidResourceConstraint) {
		t.Fatalf("err = %v, want ErrInvalidResourceConstraint", err)
	}
	assertExpectationsMet(t, mock) // zero expectations: nothing may reach the database
}

// TestSetAgentResourceConstraints_EmptyMapIsAccepted pins the deliberate
// difference from SetAgentClassificationCaps: there is no
// ErrClassificationCapsRequired analogue here (the brief's own Interfaces
// section names only ErrInvalidResourceConstraint), so an explicit {} is a
// legitimate "unrestricted" value a caller may SET directly, not only reach
// via DELETE. writeAgentConstraints still derives
// eventTypeAgentConstraintsCleared from the empty map itself, regardless of
// which exported method got here -- the same derivation-not-parameter
// discipline writeAgentCaps follows.
func TestSetAgentResourceConstraints_EmptyMapIsAccepted(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectConstraintsBeforeRead(mock, `{}`)
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentConstraintsCleared)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	expectGetAgentRow(mock, id, nil, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 0)

	view, err := s.SetAgentResourceConstraints(context.Background(), id, map[string]string{}, "operator@example.com", now)
	if err != nil {
		t.Fatalf("SetAgentResourceConstraints() error = %v, want nil for an explicit empty map", err)
	}
	if len(view.ResourceConstraints) != 0 {
		t.Errorf("ResourceConstraints = %v, want empty", view.ResourceConstraints)
	}
	assertExpectationsMet(t, mock)
}

// TestSetAgentResourceConstraints_NotFound proves an id matching no row
// becomes ErrNotFound, the identical treatment writeAgentCaps gives
// sql.ErrNoRows.
//
// The refusal now comes from the LOAD rather than the UPDATE (Task 7: the
// scope this write replaces is read first, under FOR UPDATE, so the
// containment verdict has a baseline). Same sentinel, same rollback, one
// statement earlier.
func TestSetAgentResourceConstraints_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentConstraintsForUpdateQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.SetAgentResourceConstraints(context.Background(), id,
		map[string]string{models.ResourceIDPrefixKey: "/workspace/"}, "operator@example.com", time.Now())
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	assertExpectationsMet(t, mock)
}

// TestClearAgentResourceConstraints_Success proves Clear writes {} and
// audits eventTypeAgentConstraintsCleared explicitly, via its own exported
// entry point rather than only through Set's empty-map path (the sibling
// test above).
func TestClearAgentResourceConstraints_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id, now := uuid.New(), time.Now().UTC()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectConstraintsBeforeRead(mock, `{}`)
	mock.ExpectQuery("UPDATE agents").WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(auditArgsWithEventType(eventTypeAgentConstraintsCleared)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.ClearAgentResourceConstraints(context.Background(), id, "operator@example.com", now); err != nil {
		t.Fatalf("ClearAgentResourceConstraints() error = %v", err)
	}
	assertExpectationsMet(t, mock)
}

// TestGetAgentResourceConstraints_ReadsCurrentValue proves the advisory-view
// read path -- GetAgent (for the stored constraints), then agentConstraintsView's
// own second GetAgent (for AllowedTools), the catalog, and the live-delegation
// count -- with no write anywhere in the sequence.
func TestGetAgentResourceConstraints_ReadsCurrentValue(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	expectGetAgentRow(mock, id, []string{"Read"}, nil)
	expectGetAgentRow(mock, id, []string{"Read"}, nil)
	expectCatalog(mock, nil)
	expectLiveDelegations(mock, 1)

	view, err := s.GetAgentResourceConstraints(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAgentResourceConstraints() error = %v", err)
	}
	if view.AgentID != id {
		t.Errorf("AgentID = %s, want %s", view.AgentID, id)
	}
	if view.LiveDelegations != 1 {
		t.Errorf("LiveDelegations = %d, want 1", view.LiveDelegations)
	}
	assertExpectationsMet(t, mock)
}
