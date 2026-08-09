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

	"stratium/pkg/models"
)

const testTenant = "tenant-abc"

// newMockStore wires a Store to a sqlmock-backed *sql.DB. Expectations are
// matched in order by default (sqlmock.MatchExpectationsInOrder(true) is the
// default), which is exactly what proves SET LOCAL / set_config runs before
// any SELECT: an implementation that reordered them would ask sqlmock for a
// query it hasn't been told to expect yet, and the call would fail.
func newMockStore(t *testing.T) (*Store, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db, testTenant), mock
}

func expectSetTenant(mock sqlmock.Sqlmock) {
	mock.ExpectExec(regexp.QuoteMeta(setTenantQuery)).
		WithArgs(testTenant).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func assertExpectationsMet(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

// --- LoadAgent ---

func TestStore_LoadAgent_Success(t *testing.T) {
	s, mock := newMockStore(t)
	agentID := uuid.New()

	// Expectations are registered in the exact order the brief requires:
	// begin, THEN set the tenant, THEN the data query, THEN commit.
	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentQuery)).
		WithArgs(agentID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "trust_tier", "enabled", "suspended", "allowed_tools"}).
			AddRow(agentID.String(), int64(2), true, false, []byte(`["Bash","Read"]`)))
	mock.ExpectCommit()

	got, err := s.LoadAgent(context.Background(), agentID)
	if err != nil {
		t.Fatalf("LoadAgent() error = %v", err)
	}
	if got.ID != agentID {
		t.Errorf("ID = %s, want %s", got.ID, agentID)
	}
	if got.TrustTier != models.TrustTierCertified {
		t.Errorf("TrustTier = %v, want %v", got.TrustTier, models.TrustTierCertified)
	}
	if !got.Enabled || got.Suspended {
		t.Errorf("Enabled=%v Suspended=%v, want true/false", got.Enabled, got.Suspended)
	}
	want := []string{"Bash", "Read"}
	if len(got.AllowedTools) != len(want) || got.AllowedTools[0] != want[0] || got.AllowedTools[1] != want[1] {
		t.Errorf("AllowedTools = %v, want %v", got.AllowedTools, want)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadAgent_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	agentID := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentQuery)).
		WithArgs(agentID.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.LoadAgent(context.Background(), agentID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadAgent() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// A missing row and a real query failure must be distinguishable: only the
// former is ErrNotFound.
func TestStore_LoadAgent_QueryError(t *testing.T) {
	s, mock := newMockStore(t)
	agentID := uuid.New()
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentQuery)).
		WithArgs(agentID.String()).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	_, err := s.LoadAgent(context.Background(), agentID)
	if err == nil {
		t.Fatal("LoadAgent() error = nil, want error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadAgent() error = %v, must not be ErrNotFound for a query failure", err)
	}

	assertExpectationsMet(t, mock)
}

// A corrupt allowed_tools column must fail loudly, never decode into an
// empty (meaning unrestricted) slice.
func TestStore_LoadAgent_DecodeFailure(t *testing.T) {
	s, mock := newMockStore(t)
	agentID := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentQuery)).
		WithArgs(agentID.String()).
		WillReturnRows(sqlmock.NewRows([]string{"id", "trust_tier", "enabled", "suspended", "allowed_tools"}).
			AddRow(agentID.String(), int64(0), true, false, []byte(`not-json`)))
	mock.ExpectRollback()

	got, err := s.LoadAgent(context.Background(), agentID)
	if err == nil {
		t.Fatal("LoadAgent() error = nil, want decode error")
	}
	if len(got.AllowedTools) != 0 {
		t.Errorf("AllowedTools = %v, want empty/zero value on decode failure", got.AllowedTools)
	}

	assertExpectationsMet(t, mock)
}

// The tenant-set statement failing must abort before ever reaching the data
// query, and must roll back. Both LoadAgent and LoadChain share the same
// beginTenantTx helper, so exercising it once here covers both callers.
func TestStore_LoadAgent_SetTenantFails(t *testing.T) {
	s, mock := newMockStore(t)
	agentID := uuid.New()
	setErr := errors.New("invalid_parameter_value")

	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta(setTenantQuery)).
		WithArgs(testTenant).
		WillReturnError(setErr)
	mock.ExpectRollback()

	_, err := s.LoadAgent(context.Background(), agentID)
	if err == nil {
		t.Fatal("LoadAgent() error = nil, want error when SET LOCAL fails")
	}

	assertExpectationsMet(t, mock)
}

// --- LoadChain ---

func delegationColumns() []string {
	return []string{
		"id", "tenant_id", "user_id", "agent_id", "approved_tools", "max_action_tier",
		"classification_caps", "resource_constraints", "purpose", "expires_at",
		"created_at", "revoked", "revoked_at", "parent_delegation_id",
		"root_delegation_id", "depth", "chain_agent_ids",
	}
}

type delegationRow struct {
	id, parentID uuid.UUID
	hasParent    bool
	rootID       uuid.UUID
	agentID      uuid.UUID
	depth        int
	purpose      *string
}

func addDelegationRow(rows *sqlmock.Rows, r delegationRow) *sqlmock.Rows {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Hour)

	var parentVal interface{}
	if r.hasParent {
		parentVal = r.parentID.String()
	}
	var purposeVal interface{}
	if r.purpose != nil {
		purposeVal = *r.purpose
	}

	return rows.AddRow(
		r.id.String(), testTenant, "user-1", r.agentID.String(),
		[]byte(`["Bash"]`), int64(1),
		[]byte(`{}`), []byte(`{}`), purposeVal, expires,
		now, false, nil, parentVal,
		r.rootID.String(), int64(r.depth), []byte(`[]`),
	)
}

func TestStore_LoadChain_RootFirstThreeHops(t *testing.T) {
	s, mock := newMockStore(t)

	root := uuid.New()
	mid := uuid.New()
	leaf := uuid.New()
	agent := uuid.New()
	purpose := "test purpose"

	mock.ExpectBegin()
	expectSetTenant(mock)

	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(leaf.String()).
		WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()),
			delegationRow{id: leaf, hasParent: true, parentID: mid, rootID: root, agentID: agent, depth: 2}))
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(mid.String()).
		WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()),
			delegationRow{id: mid, hasParent: true, parentID: root, rootID: root, agentID: agent, depth: 1}))
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(root.String()).
		WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()),
			delegationRow{id: root, hasParent: false, rootID: root, agentID: agent, depth: 0, purpose: &purpose}))

	mock.ExpectCommit()

	got, err := s.LoadChain(context.Background(), leaf)
	if err != nil {
		t.Fatalf("LoadChain() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("LoadChain() returned %d delegations, want 3", len(got))
	}
	if got[0].ID != root || got[1].ID != mid || got[2].ID != leaf {
		t.Fatalf("LoadChain() order = [%s, %s, %s], want [root, mid, leaf]", got[0].ID, got[1].ID, got[2].ID)
	}
	if !got[0].IsRoot() {
		t.Error("got[0] must be the root (nil parent)")
	}
	if got[0].Purpose != purpose {
		t.Errorf("root Purpose = %q, want %q", got[0].Purpose, purpose)
	}
	if got[2].Purpose != "" {
		t.Errorf("leaf Purpose = %q, want empty (NULL column)", got[2].Purpose)
	}
	if got[1].ParentDelegationID == nil || *got[1].ParentDelegationID != root {
		t.Errorf("mid.ParentDelegationID = %v, want %s", got[1].ParentDelegationID, root)
	}
	if len(got[0].ApprovedTools) != 1 || got[0].ApprovedTools[0] != "Bash" {
		t.Errorf("ApprovedTools = %v, want [Bash]", got[0].ApprovedTools)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadChain_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.LoadChain(context.Background(), id)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadChain() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadChain_QueryError(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(id.String()).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	_, err := s.LoadChain(context.Background(), id)
	if err == nil {
		t.Fatal("LoadChain() error = nil, want error")
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadChain() error = %v, must not be ErrNotFound for a query failure", err)
	}

	assertExpectationsMet(t, mock)
}

// A JSONB decode failure partway up the chain must propagate as an error,
// never as a Delegation with an empty (meaning unrestricted) tool list.
func TestStore_LoadChain_DecodeFailure(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	agent := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(delegationColumns()).AddRow(
			id.String(), testTenant, "user-1", agent.String(),
			[]byte(`not-json`), int64(1),
			[]byte(`{}`), []byte(`{}`), nil, time.Now().Add(time.Hour),
			time.Now(), false, nil, nil,
			id.String(), int64(0), []byte(`[]`),
		))
	mock.ExpectRollback()

	got, err := s.LoadChain(context.Background(), id)
	if err == nil {
		t.Fatal("LoadChain() error = nil, want decode error")
	}
	if got != nil {
		t.Errorf("LoadChain() chain = %v, want nil on decode failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A cycle introduced by a bad write must not hang the PDP: the walk is
// bounded at maxChainWalk hops and errors rather than looping forever.
func TestStore_LoadChain_CycleIsBounded(t *testing.T) {
	s, mock := newMockStore(t)
	self := uuid.New()
	agent := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)

	// self-referential: parent_delegation_id points back at the same row, so
	// the walk never sees a nil parent. Exactly maxChainWalk queries should
	// be issued before the implementation gives up — if it queried a 65th
	// time, sqlmock would fail the test for an unexpected call, and if it
	// queried fewer than 64 times, ExpectationsWereMet would fail below for
	// unmet expectations.
	for i := 0; i < maxChainWalk; i++ {
		mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
			WithArgs(self.String()).
			WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()),
				delegationRow{id: self, hasParent: true, parentID: self, rootID: self, agentID: agent, depth: 1}))
	}
	mock.ExpectRollback()

	_, err := s.LoadChain(context.Background(), self)
	if err == nil {
		t.Fatal("LoadChain() error = nil, want error on unbounded cycle")
	}

	assertExpectationsMet(t, mock)
}
