package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/pkg/models"
)

// pastExpiry is a fixed, unambiguously-in-the-past instant used for a
// child's expires_at in tests that only care about narrowing (ScopeNarrows
// compares parent.ExpiresAt to child.ExpiresAt directly; it has no notion of
// wall-clock "now" — that's DelegationLeg's job at decision time via
// IsActive). A fixed value keeps these tests deterministic regardless of
// when they run, unlike computing an offset from time.Now().
var pastExpiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// wellFormedParentRow returns a delegationRow for a PARENT that is itself a
// root (rootID == id, depth 0) with the fixed shape addDelegationRow always
// produces: approved_tools ["Bash"], max_action_tier READ_ONLY (1),
// classification_caps {}, resource_constraints {}, expires_at ~now+1h. A
// child narrowing this parent must match tools exactly (a non-empty parent
// list rejects an empty child list) and introduce no classification cap
// (the parent has none).
func wellFormedParentRow(id, agentID uuid.UUID) delegationRow {
	return delegationRow{id: id, hasParent: false, rootID: id, agentID: agentID, depth: 0}
}

// narrowChildOf builds a child Delegation that is a valid (non-widening)
// narrowing of a wellFormedParentRow with the given id/agent: same single
// approved tool, no classification caps (parent has none to inherit), tier
// at or under READ_ONLY, and an expiry safely in the past relative to the
// parent's ~now+1h. parentID/rootID/depth are deliberately left at Go zero
// values — CreateDelegation must compute them from the loaded parent, never
// trust them from the caller (see delegation.go's doc comment).
func narrowChildOf(id, agentID uuid.UUID, parentID uuid.UUID) *models.Delegation {
	return &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools:       []string{"Bash"},
		MaxActionTier:       models.ActionTierReadOnly,
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
		Purpose:             "narrower re-delegation",
		ExpiresAt:           pastExpiry,
		ParentDelegationID:  &parentID,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}
}

// mustMarshal fails the test immediately rather than silently comparing
// against a zero value if json.Marshal itself cannot encode a fixture built
// entirely from []string/map[string]string/[]uuid.UUID — which is another
// way of saying this should never actually fail (see jsonMarshal's doc
// comment on why CreateDelegation's own marshal failure test needs a seam
// instead of a naturally-failing fixture).
func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("test setup: json.Marshal(%#v): %v", v, err)
	}
	return b
}

// --- CreateDelegation: root ---

func TestStore_CreateDelegation_RootInsertsSelfReferencingRootAndZeroDepth(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools:       []string{"Bash", "Read"},
		MaxActionTier:       models.ActionTierInternalModify,
		ClassificationCaps:  map[string]string{"nato": "CONFIDENTIAL"},
		ResourceConstraints: map[string]string{"project": "alpha"},
		Purpose:             "root grant",
		ExpiresAt:           pastExpiry,
		ChainAgentIDs:       []uuid.UUID{agentID},
		// Deliberately wrong, to prove CreateDelegation computes its own
		// root_delegation_id/depth for a root rather than trusting these:
		// a real caller could never legitimately set them, but if
		// CreateDelegation ever started trusting the input, these garbage
		// values are what would silently reach the database.
		RootDelegationID: uuid.New(),
		Depth:            99,
	}

	wantTools := mustMarshal(t, d.ApprovedTools)
	wantCaps := mustMarshal(t, d.ClassificationCaps)
	wantConstraints := mustMarshal(t, d.ResourceConstraints)
	wantChainAgents := mustMarshal(t, d.ChainAgentIDs)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertDelegationQuery)).
		WithArgs(
			id.String(), testTenant, "user-1", agentID.String(), wantTools, int64(models.ActionTierInternalModify),
			wantCaps, wantConstraints, "root grant", pastExpiry,
			nil, id.String(), int64(0), wantChainAgents, nil, // escalate_at: unset on this fixture
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.CreateDelegation(context.Background(), d); err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// A reachable escalate_at (at or below max_action_tier) persists as its
// int64 tier value, the same way max_action_tier itself does — proven on a
// root so ScopeNarrows (which has its own, separately tested, opinion about
// a CHILD's escalate_at relative to its parent's) is not in play here at
// all.
func TestStore_CreateDelegation_PersistsEscalateAt(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	threshold := models.ActionTierReadOnly
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools:       []string{"Bash"},
		MaxActionTier:       models.ActionTierInternalModify,
		EscalateAt:          &threshold,
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
		Purpose:             "root grant with a threshold",
		ExpiresAt:           pastExpiry,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}

	wantTools := mustMarshal(t, d.ApprovedTools)
	wantCaps := mustMarshal(t, d.ClassificationCaps)
	wantConstraints := mustMarshal(t, d.ResourceConstraints)
	wantChainAgents := mustMarshal(t, d.ChainAgentIDs)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertDelegationQuery)).
		WithArgs(
			id.String(), testTenant, "user-1", agentID.String(), wantTools, int64(models.ActionTierInternalModify),
			wantCaps, wantConstraints, "root grant with a threshold", pastExpiry,
			nil, id.String(), int64(0), wantChainAgents, int64(models.ActionTierReadOnly),
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.CreateDelegation(context.Background(), d); err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// A threshold above the delegation's own ceiling can never fire — the
// ceiling denies before DelegationLeg would ever check it (deny overrides
// escalate) — so CreateDelegation rejects it before an INSERT is even
// attempted. Proven with no mock.ExpectBegin/ExpectRollback at all: unlike
// ScopeNarrows' rejection (which needs the parent loaded, so it runs inside
// the transaction and rolls back), this is a self-contained property of d
// alone, checked before any transaction opens — if the implementation ever
// started opening one first, sqlmock would fail this test for an unexpected
// call rather than this assertion merely checking the returned error.
func TestStore_CreateDelegation_EscalateAtAboveCeilingRejected(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	unreachable := models.ActionTierExternalComms // 3, above the ceiling below
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools:       []string{"Bash"},
		MaxActionTier:       models.ActionTierReadOnly, // 1
		EscalateAt:          &unreachable,
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
		ExpiresAt:           pastExpiry,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}

	err := s.CreateDelegation(context.Background(), d)
	if !errors.Is(err, ErrEscalateAtUnreachable) {
		t.Fatalf("CreateDelegation() error = %v, want errors.Is(_, ErrEscalateAtUnreachable)", err)
	}

	assertExpectationsMet(t, mock)
}

// The boundary: escalate_at exactly AT the ceiling is one-point reachable
// (tier == max_action_tier == escalate_at) and must be accepted, not
// rejected as "above." Without this, a >= mutation on the rejection's own
// comparison would pass every other test in this file — none of them puts
// escalate_at exactly at max_action_tier — while quietly turning a legal
// one-point band into a write-time error.
func TestStore_CreateDelegation_EscalateAtAtCeilingAccepted(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	atCeiling := models.ActionTierReadOnly
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools:       []string{"Bash"},
		MaxActionTier:       models.ActionTierReadOnly, // equal to EscalateAt below
		EscalateAt:          &atCeiling,
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
		ExpiresAt:           pastExpiry,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertDelegationQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.CreateDelegation(context.Background(), d); err != nil {
		t.Fatalf("CreateDelegation() error = %v, want escalate_at == max_action_tier to be accepted", err)
	}

	assertExpectationsMet(t, mock)
}

// --- CreateDelegation: child ---

func TestStore_CreateDelegation_ChildInheritsParentRootAndDepthPlusOne(t *testing.T) {
	s, mock := newMockStore(t)
	parentID, agentID := uuid.New(), uuid.New()
	childID := uuid.New()
	child := narrowChildOf(childID, agentID, parentID)

	wantTools := mustMarshal(t, child.ApprovedTools)
	wantCaps := mustMarshal(t, child.ClassificationCaps)
	wantConstraints := mustMarshal(t, child.ResourceConstraints)
	wantChainAgents := mustMarshal(t, child.ChainAgentIDs)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(parentID.String()).
		WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()), wellFormedParentRow(parentID, agentID)))
	mock.ExpectExec(regexp.QuoteMeta(insertDelegationQuery)).
		WithArgs(
			childID.String(), testTenant, "user-1", agentID.String(), wantTools, int64(models.ActionTierReadOnly),
			wantCaps, wantConstraints, "narrower re-delegation", pastExpiry,
			parentID.String(), parentID.String(), int64(1), wantChainAgents, nil, // escalate_at: unset on this fixture
		).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.CreateDelegation(context.Background(), child); err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// A widening child must be rejected before any INSERT is attempted — proven
// here the same way the AppendAudit tests prove ordering: no ExpectExec is
// registered for insertDelegationQuery, so if CreateDelegation tried to
// insert anyway, sqlmock would fail this test for an unexpected call rather
// than this assertion merely checking the returned error.
func TestStore_CreateDelegation_WideningChildRejectedBeforeInsert(t *testing.T) {
	s, mock := newMockStore(t)
	parentID, agentID := uuid.New(), uuid.New()
	childID := uuid.New()
	child := narrowChildOf(childID, agentID, parentID)
	child.MaxActionTier = models.ActionTierDestructive // parent caps at READ_ONLY (1)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(parentID.String()).
		WillReturnRows(addDelegationRow(sqlmock.NewRows(delegationColumns()), wellFormedParentRow(parentID, agentID)))
	mock.ExpectRollback()

	err := s.CreateDelegation(context.Background(), child)
	if !errors.Is(err, ErrScopeWidens) {
		t.Fatalf("CreateDelegation() error = %v, want errors.Is(_, ErrScopeWidens)", err)
	}

	assertExpectationsMet(t, mock)
}

// A parent that does not exist (or belongs to another tenant, indistinguishable
// under RLS by design) must surface as ErrNotFound, and must not reach an insert.
func TestStore_CreateDelegation_ParentNotFound(t *testing.T) {
	s, mock := newMockStore(t)
	parentID, agentID := uuid.New(), uuid.New()
	child := narrowChildOf(uuid.New(), agentID, parentID)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadDelegationQuery)).
		WithArgs(parentID.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	err := s.CreateDelegation(context.Background(), child)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("CreateDelegation() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- CreateDelegation: marshal failure ---

// A JSONB marshal failure must abort the insert with an error, never fall
// through with an empty ("unrestricted") value in its place — the exact
// inversion the brief warns an empty approved_tools would produce.
// jsonMarshal is swapped for the duration of this test only; t.Cleanup
// restores it before any other test runs (these tests never call
// t.Parallel(), matching the rest of this package, so there is no
// concurrent access to the package-level var).
func TestStore_CreateDelegation_MarshalFailureAbortsWithoutInsert(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools: []string{"Bash"}, MaxActionTier: models.ActionTierReadOnly,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		ExpiresAt: pastExpiry, ChainAgentIDs: []uuid.UUID{agentID},
	}

	// Fails only approved_tools's own marshal call, identified by its
	// distinct Go type ([]string; ClassificationCaps/ResourceConstraints are
	// map[string]string, ChainAgentIDs is []uuid.UUID) rather than by call
	// order. Failing every field indiscriminately would let this test pass
	// even if approved_tools's own error check were deleted: the later
	// fields' still-broken marshal calls would return an error of their
	// own and mask the mutation. Isolating the failure to one field is what
	// makes this test actually pin approved_tools's own handling.
	marshalErr := errors.New("boom")
	original := jsonMarshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		if _, ok := v.([]string); ok {
			return nil, marshalErr
		}
		return json.Marshal(v)
	}
	t.Cleanup(func() { jsonMarshal = original })

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectRollback()

	err := s.CreateDelegation(context.Background(), d)
	if err == nil {
		t.Fatal("CreateDelegation() error = nil, want a marshal error")
	}
	if !errors.Is(err, marshalErr) {
		t.Fatalf("CreateDelegation() error = %v, want it to wrap the marshal error", err)
	}

	assertExpectationsMet(t, mock)
}

// --- CreateDelegation: insert failure ---

// A failure on the INSERT itself (constraint violation, connection drop,
// whatever) must propagate and must still roll back — the same discipline
// TestStore_AppendAudit_InsertErrorIsNotMislabeledAsConcurrent exercises for
// AppendAudit.
func TestStore_CreateDelegation_InsertErrorRollsBack(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	d := &models.Delegation{
		ID: id, UserID: "user-1", AgentID: agentID,
		ApprovedTools: []string{"Bash"}, MaxActionTier: models.ActionTierReadOnly,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		ExpiresAt: pastExpiry, ChainAgentIDs: []uuid.UUID{agentID},
	}
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(insertDelegationQuery)).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	err := s.CreateDelegation(context.Background(), d)
	if err == nil {
		t.Fatal("CreateDelegation() error = nil, want error")
	}

	assertExpectationsMet(t, mock)
}

// --- RevokeDelegation (Task 4: V4, delegation revocation) ---

// TestStore_RevokeDelegation_Success is V4's own write proof: revoked and
// revoked_at are set, the write is audited in the same transaction (N4),
// and the returned *models.Delegation reflects the change — reusing
// scanDelegation and addDelegationRow (both already established by
// LoadChain/LoadDelegation's own tests above) rather than a second,
// parallel fixture shape for this method's own RETURNING clause.
func TestStore_RevokeDelegation_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	// Not addDelegationRow (store_test.go): that fixture always sets
	// revoked=false, the PRE-write state, and RETURNING hands back the row
	// AFTER this UPDATE — addRevokedDelegationRow below is that post-write
	// shape, revoked=true and revoked_at=now.
	row := sqlmock.NewRows(delegationColumns())
	addRevokedDelegationRow(row, id, agentID, now)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(revokeDelegationQuery)).
		WithArgs(now, id.String()).
		WillReturnRows(row)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.RevokeDelegation(context.Background(), id, "operator-1", now)
	if err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}
	if !got.Revoked {
		t.Error("Revoked = false, want true")
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(now) {
		t.Errorf("RevokedAt = %v, want %v", got.RevokedAt, now)
	}

	assertExpectationsMet(t, mock)
}

// addRevokedDelegationRow appends one revokeDelegationQuery-shaped RETURNING
// row: the same column order and fixed values addDelegationRow uses for
// everything except revoked/revoked_at, which this UPDATE sets to true/now
// — what a real RETURNING clause hands back after the write, not the
// pre-write state addDelegationRow's own fixture describes.
func addRevokedDelegationRow(rows *sqlmock.Rows, id, agentID uuid.UUID, revokedAt time.Time) *sqlmock.Rows {
	now := time.Now().UTC().Truncate(time.Second)
	return rows.AddRow(
		id.String(), testTenant, "user-1", agentID.String(),
		[]byte(`["Bash"]`), int64(1),
		[]byte(`{}`), []byte(`{}`), nil, now.Add(time.Hour),
		now, true, revokedAt, nil,
		id.String(), int64(0), []byte(`[]`), nil,
	)
}

// TestStore_RevokeDelegation_NotFound proves an unknown (or another
// tenant's, indistinguishable by RLS) id refuses cleanly rather than
// silently affecting zero rows with no error.
func TestStore_RevokeDelegation_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(revokeDelegationQuery)).
		WithArgs(now, id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.RevokeDelegation(context.Background(), id, "operator-1", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("RevokeDelegation() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_RevokeDelegation_AlreadyRevokedIsAcceptedAsANoOp is the
// deliberate negative space: revoking an already-revoked delegation is not
// refused (there is no "already happened" error the way DecideApproval has
// for a non-pending approval — see RevokeDelegation's own doc comment for
// why a monotonic, one-way flag with no un-revoke path has no equivalent
// rule to enforce). If a well-meaning but wrong future change added an
// ErrAlreadyRevoked-style refusal here, this test would catch it refusing a
// write that must always succeed.
func TestStore_RevokeDelegation_AlreadyRevokedIsAcceptedAsANoOp(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	earlierRevocation := now.Add(-time.Hour)

	row := sqlmock.NewRows(delegationColumns())
	addRevokedDelegationRow(row, id, agentID, earlierRevocation)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(revokeDelegationQuery)).
		WithArgs(now, id.String()).
		WillReturnRows(row)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if _, err := s.RevokeDelegation(context.Background(), id, "operator-1", now); err != nil {
		t.Fatalf("RevokeDelegation() error = %v, want nil -- revoking an already-revoked delegation must succeed", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_RevokeDelegation_AuditFailureRollsBackWrite is N4's own proof
// for this method — see policy_test.go's
// TestStore_CreatePolicy_AuditFailureRollsBackWrite for the full reasoning.
func TestStore_RevokeDelegation_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	id, agentID := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	lockErr := errors.New("connection reset mid-audit")

	row := sqlmock.NewRows(delegationColumns())
	addRevokedDelegationRow(row, id, agentID, now)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(revokeDelegationQuery)).WithArgs(now, id.String()).WillReturnRows(row)
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).WillReturnError(lockErr)
	mock.ExpectRollback()

	if _, err := s.RevokeDelegation(context.Background(), id, "operator-1", now); err == nil {
		t.Fatal("RevokeDelegation() error = nil, want the audit failure to propagate")
	}

	assertExpectationsMet(t, mock)
}
