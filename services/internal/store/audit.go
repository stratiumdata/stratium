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
	`decision, denied_leg, denied_at_depth, reason, policy_source, policy_id, input_digest ` +
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
//	InputDigest       ->  input_digest
//
// All 20 Entry fields are listed (Entry has exactly 20 — see
// TestHash_CoversEveryField in pkg/audit). Every one is written explicitly,
// even where the Go zero value is what's being written: several columns
// have schema defaults that do not match that zero (occurred_at DEFAULT
// NOW(), tool_name/action/reason DEFAULT to an empty string), and a column
// an INSERT omitted would silently take that default instead of the value
// Hash actually consumed, failing verification later. policy_source and
// policy_id have no default at all (migrations/000006), so an omitted
// column would fail loudly (NULL is fine; a missing column entirely is
// not) rather than silently diverge — but they are still written
// explicitly, for the same reason as every other column here. seq is the
// only audit_chain column absent here — it is the table's own generated
// identity, not part of Entry, and Hash never covers it.
const insertAuditQuery = `INSERT INTO audit_chain (` +
	`tenant_id, prev_hash, entry_hash, occurred_at, event_type, actor, ` +
	`agent_id, delegation_id, root_delegation_id, chain_depth, ` +
	`tool_name, action, declared_tier, derived_tier, ` +
	`decision, denied_leg, denied_at_depth, reason, policy_source, policy_id, input_digest` +
	`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`

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

// AppendAudit appends e to the tenant's hash chain. It reads the current
// tail, links e onto it with audit.Link, computes the linked entry's hash,
// and inserts — all inside one transaction, so no other writer can insert
// between the read and the write and link onto the same predecessor
// undetected. UNIQUE (tenant_id, prev_hash) is the backstop for the case
// where one still does (see ErrConcurrentAppend).
func (s *Store) AppendAudit(ctx context.Context, e audit.Entry) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

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

	_, err = tx.ExecContext(ctx, insertAuditQuery,
		linked.TenantID, linked.PrevHash[:], entryHash[:], linked.OccurredAt, linked.EventType, linked.Actor,
		linked.AgentID, linked.DelegationID, linked.RootDelegationID, linked.ChainDepth,
		linked.ToolName, linked.Action, linked.DeclaredTier, linked.DerivedTier,
		linked.Decision, linked.DeniedLeg, linked.DeniedAtDepth, linked.Reason,
		linked.PolicySource, linked.PolicyID, linked.InputDigest[:],
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == sqlStateUniqueViolation {
			return fmt.Errorf("%w: %w", ErrConcurrentAppend, pqErr)
		}
		return fmt.Errorf("store: insert audit entry: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
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
func scanAuditTail(row *sql.Row) (*audit.Entry, error) {
	var e audit.Entry
	var prevHash, inputDigest []byte
	var policySource, policyID sql.NullString

	err := row.Scan(
		&prevHash, &e.TenantID, &e.OccurredAt, &e.EventType, &e.Actor,
		&e.AgentID, &e.DelegationID, &e.RootDelegationID, &e.ChainDepth,
		&e.ToolName, &e.Action, &e.DeclaredTier, &e.DerivedTier,
		&e.Decision, &e.DeniedLeg, &e.DeniedAtDepth, &e.Reason,
		&policySource, &policyID, &inputDigest,
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
