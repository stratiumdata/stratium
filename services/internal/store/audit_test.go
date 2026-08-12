package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"stratium/pkg/audit"
)

// fullAuditEntry returns an Entry with every field set to a distinguishable,
// non-placeholder value, including the fields that most often carry a Go
// zero in practice (ChainDepth, DeniedLeg, DeniedAtDepth). A second call
// with a different seed must never collide with the first.
func fullAuditEntry(tenantID string, seed byte) audit.Entry {
	agent := uuid.New()
	delegation := uuid.New()
	root := uuid.New()
	return audit.Entry{
		TenantID:             tenantID,
		OccurredAt:           time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC).Add(time.Duration(seed) * time.Minute),
		EventType:            "decision",
		Actor:                "agent:svc-a",
		AgentID:              &agent,
		DelegationID:         &delegation,
		RootDelegationID:     &root,
		ChainDepth:           2,
		ToolName:             "Bash",
		Action:               "run",
		DeclaredTier:         1,
		DerivedTier:          2,
		Decision:             "ALLOW",
		DeniedLeg:            "",
		DeniedAtDepth:        0,
		Reason:               "ok",
		PolicySource:         "cedar",
		PolicyID:             "policy-42",
		UnevaluatedPolicyIDs: []string{"orphan-1", "orphan-2"},
		InputDigest:          [32]byte{seed, seed + 1, seed + 2},
	}
}

func auditTailColumns() []string {
	return []string{
		"prev_hash", "tenant_id", "occurred_at", "event_type", "actor",
		"agent_id", "delegation_id", "root_delegation_id", "chain_depth",
		"tool_name", "action", "declared_tier", "derived_tier",
		"decision", "denied_leg", "denied_at_depth", "reason",
		"policy_source", "policy_id", "unevaluated_policy_ids", "input_digest",
	}
}

// pqArrayValue renders ids the way a real driver hands a TEXT[] column back
// from a Scan (lib/pq's own Postgres array text format), for sqlmock rows
// that must be scanned through pq.Array — mirrors uuidArg's role for the
// nullable UUID columns above. A nil slice renders as SQL NULL (pq.
// StringArray.Value's own documented behavior), which is what
// addAuditTailRow needs to exercise a genuinely-NULL column rather than an
// empty array — the two are the same Go zero value but different wire
// values, exactly the distinction TestStore_AppendAudit_
// TailReadDecodesNullUnevaluatedPolicyIDsAsNil below depends on.
func pqArrayValue(ids []string) interface{} {
	v, err := pq.StringArray(ids).Value()
	if err != nil {
		// StringArray.Value never actually returns an error; a panic here
		// would only ever fire if that stopped being true, which is a test
		// bug worth surfacing loudly rather than silently mis-building a
		// fixture.
		panic(err)
	}
	return v
}

// uuidArg renders a nullable UUID field the way a real driver hands it back
// from a Scan: the string form, or nil for NULL. Mirrors store_test.go's
// addDelegationRow, which already exercises this for parent_delegation_id.
func uuidArg(u *uuid.UUID) interface{} {
	if u == nil {
		return nil
	}
	return u.String()
}

// addAuditTailRow appends e as one auditTailQuery result row, in that
// query's column order.
func addAuditTailRow(rows *sqlmock.Rows, e audit.Entry) *sqlmock.Rows {
	return rows.AddRow(
		e.PrevHash[:], e.TenantID, e.OccurredAt, e.EventType, e.Actor,
		uuidArg(e.AgentID), uuidArg(e.DelegationID), uuidArg(e.RootDelegationID), int64(e.ChainDepth),
		e.ToolName, e.Action, int64(e.DeclaredTier), int64(e.DerivedTier),
		e.Decision, e.DeniedLeg, int64(e.DeniedAtDepth), e.Reason,
		e.PolicySource, e.PolicyID, pqArrayValue(e.UnevaluatedPolicyIDs), e.InputDigest[:],
	)
}

// nonNilStrings mirrors AppendAudit's own nil-to-empty-array coercion for
// unevaluated_policy_ids (see that function's own comment on why: pq.Array
// binds a nil slice as SQL NULL, and AppendAudit's discipline is that every
// column it writes for a row it is actually writing gets a concrete value).
// insertArgsFor needs the identical coercion so its expected argument
// matches what AppendAudit really sends — see expectations_go18.go's
// argsMatches, which converts both sides through driver.Valuer before
// comparing, so this must produce the same []string AppendAudit's own local
// variable would, not merely something that also renders to the same
// Postgres text form by coincidence.
func nonNilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// insertArgsFor returns the exact positional argument list AppendAudit must
// pass to insertAuditQuery for the already-linked entry, in that query's
// column order — tenant_id, prev_hash, entry_hash, then every remaining
// field audit.Entry.Hash covers. Centralizing this list is what lets each
// test assert on the full argument set instead of just "an INSERT
// happened": a column silently dropped from the real INSERT, reordered, or
// swapped with a neighbor makes the mock's expected arguments disagree with
// what AppendAudit actually sends, and sqlmock fails the test.
func insertArgsFor(linked audit.Entry, entryHash [32]byte) []driver.Value {
	return []driver.Value{
		linked.TenantID, linked.PrevHash[:], entryHash[:], linked.OccurredAt, linked.EventType, linked.Actor,
		linked.AgentID, linked.DelegationID, linked.RootDelegationID, linked.ChainDepth,
		linked.ToolName, linked.Action, linked.DeclaredTier, linked.DerivedTier,
		linked.Decision, linked.DeniedLeg, linked.DeniedAtDepth, linked.Reason,
		linked.PolicySource, linked.PolicyID, pq.Array(nonNilStrings(linked.UnevaluatedPolicyIDs)), linked.InputDigest[:],
	}
}

// advisoryLockQuery mirrors the exact SQL text AppendAudit issues to acquire
// the per-tenant serialization lock (see audit.go). Duplicated here rather
// than imported from a shared constant because audit.go inlines it verbatim
// rather than naming it — this string must match that literal exactly.
const advisoryLockQuery = `SELECT pg_advisory_xact_lock(hashtext($1))`

// expectAdvisoryLock registers the ordered expectation for AppendAudit's
// per-tenant advisory lock. Mirrors expectSetTenant in store_test.go.
func expectAdvisoryLock(mock sqlmock.Sqlmock) {
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// --- AppendAudit ---
//
// Every case below registers sqlmock expectations in the exact order
// AppendAudit must issue them — begin, set tenant, acquire the advisory
// lock, read the tail, insert, commit — which is what proves the lock is
// acquired before the tail read and the tail read and insert happen inside
// one transaction with the tenant set first: sqlmock matches expectations
// in registration order by default, so a real implementation that reordered
// or skipped a step would ask for a call it hasn't been told to expect and
// fail immediately, the same mechanism store_test.go relies on for
// LoadAgent/LoadChain.

func TestStore_AppendAudit_FirstEntryLinksToZeroHash(t *testing.T) {
	s, mock := newMockStore(t)
	e := fullAuditEntry(testTenant, 1)

	wantLinked := audit.Link(nil, e)
	wantHash := wantLinked.Hash()
	if wantLinked.PrevHash != audit.ZeroHash {
		t.Fatalf("test setup bug: audit.Link(nil, e).PrevHash = %x, want ZeroHash", wantLinked.PrevHash)
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_AppendAudit_SecondEntryLinksToPredecessorHash(t *testing.T) {
	s, mock := newMockStore(t)
	predecessor := fullAuditEntry(testTenant, 9)
	e := fullAuditEntry(testTenant, 1)
	e.PrevHash = [32]byte{0xFF, 0xFF} // must be overwritten by Link, never trusted from the caller

	wantLinked := audit.Link(&predecessor, e)
	wantHash := wantLinked.Hash()
	if wantLinked.PrevHash != predecessor.Hash() {
		t.Fatal("test setup bug: audit.Link(&predecessor, e).PrevHash must equal predecessor.Hash()")
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnRows(addAuditTailRow(sqlmock.NewRows(auditTailColumns()), predecessor))
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// policy_source and policy_id are nullable with no default (migrations/
// 000006_audit_policy_provenance), so a predecessor row written before that
// migration — or by any writer that never set them — comes back from the
// tail query as SQL NULL, not "". scanAuditTail must decode that NULL to
// Go's zero string, the same value a fresh Entry{} already has, or the
// recomputed PrevHash for the new entry will not match what a chain reader
// gets by reconstructing the same predecessor from its own zero-valued
// fields — silently forking what "the predecessor's hash" means depending
// on which code path computed it.
func TestStore_AppendAudit_TailReadDecodesNullPolicyColumnsAsEmptyString(t *testing.T) {
	s, mock := newMockStore(t)
	predecessor := fullAuditEntry(testTenant, 9)
	predecessor.PolicySource = "" // what AppendAudit itself writes for "no Deciding verdict"
	predecessor.PolicyID = ""
	e := fullAuditEntry(testTenant, 1)

	wantLinked := audit.Link(&predecessor, e)
	wantHash := wantLinked.Hash()
	if wantLinked.PrevHash != predecessor.Hash() {
		t.Fatal("test setup bug: audit.Link(&predecessor, e).PrevHash must equal predecessor.Hash()")
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	// nil, not "", in these two positions: this is what a real driver hands
	// back for SQL NULL, which is what addAuditTailRow(predecessor) would NOT
	// exercise (it would send the Go "" string as a driver value, not NULL).
	// unevaluated_policy_ids is left at predecessor's own (non-empty) value
	// here — this test is specifically about the two plain-string columns;
	// TestStore_AppendAudit_TailReadDecodesNullUnevaluatedPolicyIDsAsNil below
	// is its dedicated counterpart for the array column.
	row := sqlmock.NewRows(auditTailColumns()).AddRow(
		predecessor.PrevHash[:], predecessor.TenantID, predecessor.OccurredAt, predecessor.EventType, predecessor.Actor,
		uuidArg(predecessor.AgentID), uuidArg(predecessor.DelegationID), uuidArg(predecessor.RootDelegationID),
		int64(predecessor.ChainDepth), predecessor.ToolName, predecessor.Action,
		int64(predecessor.DeclaredTier), int64(predecessor.DerivedTier),
		predecessor.Decision, predecessor.DeniedLeg, int64(predecessor.DeniedAtDepth), predecessor.Reason,
		nil, nil, pqArrayValue(predecessor.UnevaluatedPolicyIDs), predecessor.InputDigest[:],
	)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnRows(row)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// unevaluated_policy_ids is nullable with no default (migrations/
// 000010_audit_unevaluated_policy_ids), so a predecessor row written before
// that migration — or by any writer that never set it — comes back from the
// tail query as SQL NULL, not an empty array. scanAuditTail must decode
// that NULL to a nil []string, the same value a fresh Entry{} already has
// (pq.StringArray's own Scan already does this — see scanAuditTail's own
// doc comment), or the recomputed PrevHash for the new entry will not match
// what a chain reader gets by reconstructing the same predecessor from its
// own zero-valued fields. The live, migration-crossing counterpart of this
// property is store_integration_test.go's "chain_verifies_across_the_
// migration_boundary" subtest of TestEndToEnd (build-tagged integration),
// which proves it against a real Postgres migrated live rather than a mock.
func TestStore_AppendAudit_TailReadDecodesNullUnevaluatedPolicyIDsAsNil(t *testing.T) {
	s, mock := newMockStore(t)
	predecessor := fullAuditEntry(testTenant, 9)
	predecessor.UnevaluatedPolicyIDs = nil // what a genuinely pre-migration row (or one never populated) looks like
	e := fullAuditEntry(testTenant, 1)

	wantLinked := audit.Link(&predecessor, e)
	wantHash := wantLinked.Hash()
	if wantLinked.PrevHash != predecessor.Hash() {
		t.Fatal("test setup bug: audit.Link(&predecessor, e).PrevHash must equal predecessor.Hash()")
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	// nil in this one position (not pqArrayValue(nil), though those render
	// identically): this is what a real driver hands back for SQL NULL.
	row := sqlmock.NewRows(auditTailColumns()).AddRow(
		predecessor.PrevHash[:], predecessor.TenantID, predecessor.OccurredAt, predecessor.EventType, predecessor.Actor,
		uuidArg(predecessor.AgentID), uuidArg(predecessor.DelegationID), uuidArg(predecessor.RootDelegationID),
		int64(predecessor.ChainDepth), predecessor.ToolName, predecessor.Action,
		int64(predecessor.DeclaredTier), int64(predecessor.DerivedTier),
		predecessor.Decision, predecessor.DeniedLeg, int64(predecessor.DeniedAtDepth), predecessor.Reason,
		predecessor.PolicySource, predecessor.PolicyID, nil, predecessor.InputDigest[:],
	)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnRows(row)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// The schema gives several hash-covered columns defaults that do not match
// Go's zero value (occurred_at DEFAULT NOW(), tool_name/action/reason
// DEFAULT to an empty string), which is exactly what makes an omitted
// column dangerous: the row would insert successfully and only fail
// verification later. This entry leaves every optional field at its Go
// zero (nil UUIDs, zero time, empty strings, zero tiers, zero InputDigest)
// so the recorded argument list must contain them explicitly or the mock
// match fails.
func TestStore_AppendAudit_InsertCarriesZeroValuedColumns(t *testing.T) {
	s, mock := newMockStore(t)
	e := audit.Entry{
		TenantID:  testTenant,
		EventType: "decision",
		Actor:     "agent:svc-a",
		Decision:  "ALLOW",
	}

	wantLinked := audit.Link(nil, e)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// UNIQUE (tenant_id, prev_hash) is the backstop for two writers racing on
// the same chain tail: exactly one of them gets 23505. AppendAudit must
// surface that as a distinguishable error, not retry and not swallow it.
func TestStore_AppendAudit_UniqueViolationIsDistinguishable(t *testing.T) {
	s, mock := newMockStore(t)
	e := fullAuditEntry(testTenant, 1)
	wantLinked := audit.Link(nil, e)
	wantHash := wantLinked.Hash()

	raceErr := &pq.Error{
		Code:       "23505",
		Message:    `duplicate key value violates unique constraint "audit_chain_tenant_prev_hash_unique"`,
		Constraint: "audit_chain_tenant_prev_hash_unique",
	}

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnError(raceErr)
	mock.ExpectRollback()

	err := s.AppendAudit(context.Background(), e)
	if !errors.Is(err, ErrConcurrentAppend) {
		t.Fatalf("AppendAudit() error = %v, want ErrConcurrentAppend", err)
	}

	assertExpectationsMet(t, mock)
}

// A non-23505 failure on the insert — a plain connectivity error, or a
// Postgres error of a different class such as a CHECK violation — must
// propagate as a real error without being mislabeled as the concurrency
// case. That distinction is the whole point of checking the SQLSTATE
// specifically rather than treating any *pq.Error as a race.
func TestStore_AppendAudit_InsertErrorIsNotMislabeledAsConcurrent(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"generic connection error", errors.New("connection reset")},
		{"different SQLSTATE (check_violation)", &pq.Error{Code: "23514", Message: "new row violates check constraint"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			e := fullAuditEntry(testTenant, 1)
			wantLinked := audit.Link(nil, e)
			wantHash := wantLinked.Hash()

			mock.ExpectBegin()
			expectSetTenant(mock)
			expectAdvisoryLock(mock)
			mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
				WillReturnError(sql.ErrNoRows)
			mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
				WithArgs(insertArgsFor(wantLinked, wantHash)...).
				WillReturnError(tt.err)
			mock.ExpectRollback()

			err := s.AppendAudit(context.Background(), e)
			if err == nil {
				t.Fatal("AppendAudit() error = nil, want error")
			}
			if errors.Is(err, ErrConcurrentAppend) {
				t.Fatalf("AppendAudit() error = %v, must not be ErrConcurrentAppend", err)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// A failure reading the tail — connection drop, statement timeout, whatever
// — must propagate and must not fall through to the insert. No ExpectExec
// is registered below: if AppendAudit tried to insert anyway, sqlmock would
// fail this test for an unexpected call.
func TestStore_AppendAudit_TailQueryErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	e := fullAuditEntry(testTenant, 1)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnError(dbErr)
	mock.ExpectRollback()

	err := s.AppendAudit(context.Background(), e)
	if err == nil {
		t.Fatal("AppendAudit() error = nil, want error")
	}
	if errors.Is(err, ErrConcurrentAppend) {
		t.Fatalf("AppendAudit() error = %v, must not be ErrConcurrentAppend", err)
	}

	assertExpectationsMet(t, mock)
}

// The advisory lock must be acquired inside the transaction, after the
// tenant is set but before the chain tail is read — a lock taken after the
// tail read would let two writers both read the tail before either one
// serializes. sqlmock matches expectations in registration order by default
// (see the comment above the "--- AppendAudit ---" section), so registering
// the lock expectation between expectSetTenant and the tail ExpectQuery is
// itself the proof: an implementation that read the tail first would ask
// sqlmock for a query it hasn't been told to expect next and fail
// immediately.
func TestStore_AppendAudit_AcquiresAdvisoryLockBeforeTailRead(t *testing.T) {
	s, mock := newMockStore(t)
	e := fullAuditEntry(testTenant, 1)
	wantLinked := audit.Link(nil, e)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.AppendAudit(context.Background(), e); err != nil {
		t.Fatalf("AppendAudit() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

// A failure acquiring the lock — connection drop, statement timeout,
// whatever — must abort the append immediately and must not fall through to
// the tail read or the insert. Neither a tail ExpectQuery nor an insert
// ExpectExec is registered below: if AppendAudit fell through to either
// after a lock failure, sqlmock would fail this test for an unexpected
// call, the same mechanism TestStore_AppendAudit_TailQueryErrorPropagates
// relies on.
func TestStore_AppendAudit_LockFailureAbortsWithoutWrite(t *testing.T) {
	s, mock := newMockStore(t)
	e := fullAuditEntry(testTenant, 1)
	lockErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).
		WithArgs(testTenant).
		WillReturnError(lockErr)
	mock.ExpectRollback()

	err := s.AppendAudit(context.Background(), e)
	if err == nil {
		t.Fatal("AppendAudit() error = nil, want error")
	}
	if errors.Is(err, ErrConcurrentAppend) {
		t.Fatalf("AppendAudit() error = %v, must not be ErrConcurrentAppend", err)
	}

	assertExpectationsMet(t, mock)
}
