package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"stratium/pkg/audit"
)

// auditTailQuery reads the tenant's current chain tail — the most recently
// inserted row, identified by ORDER BY seq DESC (seq is the table's single
// insertion-ordered identity; audit_chain_tenant_seq indexes exactly
// (tenant_id, seq), so RLS's rewrite to WHERE tenant_id = current_tenant()
// makes this an index seek, not a scan). No WHERE tenant_id clause here
// either, per the package doc: RLS is the only implementation of the tenant
// boundary.
//
// entry_hash is deliberately not selected. audit.Link takes the full
// predecessor Entry and recomputes its Hash() from that Entry's own
// columns; it does not accept a bare hash. That means AppendAudit never
// trusts a stored entry_hash value merely because it is present — it
// rederives it from the row that was actually hashed, the same discipline
// audit.Verify uses when it walks the chain.
const auditTailQuery = `SELECT prev_hash, tenant_id, occurred_at, event_type, actor, ` +
	`agent_id, delegation_id, root_delegation_id, chain_depth, ` +
	`tool_name, action, declared_tier, derived_tier, ` +
	`decision, denied_leg, denied_at_depth, reason, policy_source, policy_id, unevaluated_policy_ids, input_digest ` +
	`FROM audit_chain ORDER BY seq DESC LIMIT 1`

// insertAuditQuery writes every column audit.Entry.Hash covers, plus
// entry_hash (the computed digest of the linked entry — not an Entry field,
// never read back, only ever produced by Hash). Checked field by field
// against Hash's serialization in pkg/audit/chain.go:
//
//	Hash() writes         audit_chain column
//	PrevHash          ->  prev_hash
//	TenantID          ->  tenant_id
//	OccurredAt        ->  occurred_at
//	EventType         ->  event_type
//	Actor             ->  actor
//	AgentID           ->  agent_id
//	DelegationID      ->  delegation_id
//	RootDelegationID  ->  root_delegation_id
//	ChainDepth        ->  chain_depth
//	ToolName          ->  tool_name
//	Action            ->  action
//	DeclaredTier      ->  declared_tier
//	DerivedTier       ->  derived_tier
//	Decision          ->  decision
//	DeniedLeg         ->  denied_leg
//	DeniedAtDepth     ->  denied_at_depth
//	Reason            ->  reason
//	PolicySource      ->  policy_source
//	PolicyID          ->  policy_id
//	UnevaluatedPolicyIDs -> unevaluated_policy_ids
//	InputDigest       ->  input_digest
//
// All 21 Entry fields are listed (Entry has exactly 21 — see
// TestHash_CoversEveryField in pkg/audit). Every one is written explicitly,
// even where the Go zero value is what's being written: several columns
// have schema defaults that do not match that zero (occurred_at DEFAULT
// NOW(), tool_name/action/reason DEFAULT to an empty string), and a column
// an INSERT omitted would silently take that default instead of the value
// Hash actually consumed, failing verification later. policy_source,
// policy_id, and unevaluated_policy_ids have no default at all (migrations/
// 000006, 000010), so an omitted column would fail loudly (NULL is fine; a
// missing column entirely is not) rather than silently diverge — but they
// are still written explicitly, for the same reason as every other column
// here (see the nil-to-empty-array coercion in AppendAudit below for
// unevaluated_policy_ids specifically: pq.StringArray's own Value() method
// binds a nil slice as SQL NULL, so a caller that wants a genuinely-empty
// array written, not NULL, must hand it a non-nil one). seq is the only
// audit_chain column absent here — it is the table's own generated
// identity, not part of Entry, and Hash never covers it.
const insertAuditQuery = `INSERT INTO audit_chain (` +
	`tenant_id, prev_hash, entry_hash, occurred_at, event_type, actor, ` +
	`agent_id, delegation_id, root_delegation_id, chain_depth, ` +
	`tool_name, action, declared_tier, derived_tier, ` +
	`decision, denied_leg, denied_at_depth, reason, policy_source, policy_id, unevaluated_policy_ids, input_digest` +
	`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)`

// sqlStateUniqueViolation is PostgreSQL's SQLSTATE class for
// unique_violation. audit_chain_tenant_prev_hash_unique raises exactly this
// when two writers race on the same chain tail — see ErrConcurrentAppend.
const sqlStateUniqueViolation = "23505"

// ErrConcurrentAppend indicates two writers raced on the same tenant's
// chain tail: both read the same predecessor and both tried to link a new
// entry onto it. UNIQUE (tenant_id, prev_hash) lets exactly one of them
// succeed — this error reports that the constraint did its job, not that
// anything is broken. AppendAudit does not retry and does not fall back to
// appending unlinked; the caller denies the action on any error, so one of
// the two racing decisions is denied. See the Task 4 report for why this
// slice does not resolve the race itself.
var ErrConcurrentAppend = errors.New("store: concurrent audit append collided on the chain tail")

// noDenial is the DeniedAtDepth sentinel for an audit entry that records no
// denial. Every PAP CRUD write (policy.go, agent.go, tier_override.go) uses
// this: those writes only ever reach an audit call after every refusal path
// — a failed engine Validate, a lowering ValidateOverride, a missing
// required field — has already returned, so Decision is unconditionally
// "ALLOW" and there is no denial to record, the identical shape
// pdpgrpc/delegation.go's own appendDelegationAudit already documents for
// CreateDelegation's success-only audit call. Chain depth 0 is a real,
// meaningful value (a root delegation), so leaving DeniedAtDepth at its Go
// zero value here would misrepresent "not applicable" as "denied at the
// root" to anything scanning audit_chain across event types. Duplicated
// (not imported) from pdpgrpc/delegation.go's own identical constant:
// internal/store must not import internal/pdpgrpc (the dependency runs the
// other way — pdpgrpc imports store), and a two-line int16 constant is not
// worth restructuring either package's import graph to share.
const noDenial int16 = -1

// AppendAudit appends e to the tenant's hash chain in its own,
// single-purpose transaction: begin, set the tenant, then appendAuditTx.
// Callers with no accompanying row write to share a transaction with use
// this directly — pdpgrpc's own decision and delegation-creation audit
// entries, today's only callers outside this package. A caller that IS also
// writing a governed row in the same call (every PAP CRUD method in this
// package) must not use this: it opens and commits its own transaction, so
// a governed write and its audit entry would land in two separate
// transactions, exactly the gap N4 exists to close. Those callers open their
// own beginTenantTx and call appendAuditTx directly, inside it, instead.
func (s *Store) AppendAudit(ctx context.Context, e audit.Entry) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.appendAuditTx(ctx, tx, e); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// appendAuditTx performs AppendAudit's exact steps — acquire the per-tenant
// advisory lock, read the current chain tail, link e onto it, insert —
// against tx, a transaction the caller already opened (via beginTenantTx)
// and owns: the caller commits or rolls back, never this method. This is
// what makes N4 ("every write audited in the same transaction as the write
// it records") true by construction rather than by convention: a PAP CRUD
// method calls this between its own governed-row write and its own
// tx.Commit, so a failure here — same as a failure on the write itself —
// is caught by the caller's already-deferred tx.Rollback(), and a success
// here lands in the identical commit as the write. AppendAudit (above) is
// this same logic wrapped in its own transaction for a caller with nothing
// else to share one with.
//
// Extracted from AppendAudit itself (this method's entire body, byte for
// byte, is what AppendAudit's inline code used to be) specifically so this
// one implementation serves both shapes of caller — a lock taken here and a
// second one taken independently by some future "PAP audit" helper would
// serialize against each other, not together, and two writers computing
// PrevHash from two separately-read tails is exactly how a chain forks.
func (s *Store) appendAuditTx(ctx context.Context, tx *sql.Tx, e audit.Entry) error {
	// Serialize appends per tenant. Two writers that read the same chain tail
	// both link to it, and UNIQUE (tenant_id, prev_hash) then rejects one — which
	// D3 turns into a denied action. Measured at 30-70% denials for a single
	// tenant under ten concurrent decisions.
	//
	// pg_advisory_xact_lock is held for the transaction and released on commit or
	// rollback, including if the process dies, so a crashed writer cannot wedge a
	// tenant. hashtext gives a stable per-tenant key; collisions between distinct
	// tenants only serialize them unnecessarily, never mix their chains.
	//
	// This bounds a tenant's decision throughput by audit-write latency. If that
	// ceiling ever binds, the answer is batching appends behind the lock, not
	// removing it.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.tenantID); err != nil {
		return fmt.Errorf("acquire audit append lock: %w", err)
	}

	prev, err := scanAuditTail(tx.QueryRowContext(ctx, auditTailQuery))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: load audit chain tail: %w", err)
	}
	// err == sql.ErrNoRows means the tenant has no entries yet: prev is
	// already nil (scanAuditTail returns nil on any error), so e becomes
	// the tenant's first entry, linked to audit.ZeroHash below.

	linked := audit.Link(prev, e)
	entryHash := linked.Hash()

	// unevaluatedPolicyIDs is coerced to a non-nil, empty slice when linked
	// carries none: pq.StringArray.Value() (what pq.Array's binding calls)
	// writes SQL NULL for a nil slice, but AppendAudit's own discipline
	// (see insertAuditQuery's doc comment) is that every column it writes
	// gets a concrete value, never NULL, for a row it is actually writing —
	// the same "write the zero value explicitly" rule already applied to
	// policy_source/policy_id above. That is what keeps NULL meaning
	// exactly one thing in this column: a row written before migrations/
	// 000010, never one AppendAudit wrote itself.
	unevaluatedPolicyIDs := linked.UnevaluatedPolicyIDs
	if unevaluatedPolicyIDs == nil {
		unevaluatedPolicyIDs = []string{}
	}

	_, err = tx.ExecContext(ctx, insertAuditQuery,
		linked.TenantID, linked.PrevHash[:], entryHash[:], linked.OccurredAt, linked.EventType, linked.Actor,
		linked.AgentID, linked.DelegationID, linked.RootDelegationID, linked.ChainDepth,
		linked.ToolName, linked.Action, linked.DeclaredTier, linked.DerivedTier,
		linked.Decision, linked.DeniedLeg, linked.DeniedAtDepth, linked.Reason,
		linked.PolicySource, linked.PolicyID, pq.Array(unevaluatedPolicyIDs), linked.InputDigest[:],
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == sqlStateUniqueViolation {
			return fmt.Errorf("%w: %w", ErrConcurrentAppend, pqErr)
		}
		return fmt.Errorf("store: insert audit entry: %w", err)
	}

	return nil
}

// scanAuditTail scans one auditTailQuery row into an audit.Entry. On an
// empty chain it returns sql.ErrNoRows unchanged, exactly as row.Scan
// produces it — AppendAudit treats that as "no predecessor," not a
// failure.
//
// prev_hash and input_digest scan through a []byte intermediate because
// Entry stores them as [32]byte: a fixed-size array is neither one of
// database/sql's built-in scan targets nor (being unnamed) a type Go
// permits attaching a Scan method to. agent_id/delegation_id/
// root_delegation_id scan directly into their *uuid.UUID fields — the same
// nullable-pointer pattern store.go's scanDelegation already relies on for
// parent_delegation_id. policy_source/policy_id scan through sql.NullString
// for the same reason scanDelegation uses it for the nullable purpose
// column: Entry models them as plain strings, not pointers, and
// database/sql errors scanning a NULL directly into a string.
//
// unevaluated_policy_ids scans straight into pq.Array(&e.UnevaluatedPolicyIDs)
// — no sql.NullString-style intermediate needed, because pq.StringArray's
// own Scan already treats a SQL NULL source as "set the slice to nil"
// (lib/pq's array.go), which is exactly Go's own zero value for []string.
// That is what makes a row written before migrations/000010 (where this
// column does not exist and reads back NULL) decode identically to a row
// this package wrote with genuinely nothing unevaluated (an explicit empty
// array — see AppendAudit's own nil-to-empty-array coercion): pkg/audit.
// Entry.Hash's list encoding writes a count, and both cases count zero.
func scanAuditTail(row *sql.Row) (*audit.Entry, error) {
	var e audit.Entry
	var prevHash, inputDigest []byte
	var policySource, policyID sql.NullString

	err := row.Scan(
		&prevHash, &e.TenantID, &e.OccurredAt, &e.EventType, &e.Actor,
		&e.AgentID, &e.DelegationID, &e.RootDelegationID, &e.ChainDepth,
		&e.ToolName, &e.Action, &e.DeclaredTier, &e.DerivedTier,
		&e.Decision, &e.DeniedLeg, &e.DeniedAtDepth, &e.Reason,
		&policySource, &policyID, pq.Array(&e.UnevaluatedPolicyIDs), &inputDigest,
	)
	if err != nil {
		return nil, err
	}

	if len(prevHash) != 32 {
		return nil, fmt.Errorf("store: audit tail prev_hash has length %d, want 32", len(prevHash))
	}
	copy(e.PrevHash[:], prevHash)

	// NULL decodes to "", same as an Entry whose Deciding verdict was nil —
	// e.PolicySource/e.PolicyID are already that zero value, so only the
	// Valid case needs writing. This is what keeps Hash() reproducible for a
	// row written before migrations/000006 added these columns: such a row
	// reads back NULL here exactly as if AppendAudit had written "" for it.
	if policySource.Valid {
		e.PolicySource = policySource.String
	}
	if policyID.Valid {
		e.PolicyID = policyID.String
	}

	// input_digest is nullable in the schema; AppendAudit itself never
	// stores NULL there (input_digest is always written, zero-valued or
	// not), but a row scanned back is not required to have come from this
	// code path. NULL decodes to the zero [32]byte, same as an Entry that
	// never set InputDigest — e.InputDigest is already that zero value.
	if inputDigest != nil {
		if len(inputDigest) != 32 {
			return nil, fmt.Errorf("store: audit tail input_digest has length %d, want 32", len(inputDigest))
		}
		copy(e.InputDigest[:], inputDigest)
	}

	return &e, nil
}
