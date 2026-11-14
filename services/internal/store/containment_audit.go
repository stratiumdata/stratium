// containment_audit.go records what an agent-grant write widened.
//
// The three endpoints that change an agent's grant -- PUT /v1/agents/{id},
// and the caps and resource-constraints routes -- set the template copied
// onto every ROOT delegation issued afterwards
// (internal/pdpgrpc/delegation.go). Until this file, nothing compared the new
// template to the old one, so widening an agent's scope was both unchecked
// and invisible.
//
// The write still lands. Blocking here would need a break-glass and would
// stall a tenant's first grant, which has no baseline to be contained in;
// recording the verdict in the one log the system can prove was not edited
// afterwards is the trade this design took.
//
// Only the AGENT grant is covered, not all six epoch-bumping tables. The
// other four -- policies, tool_catalog, tier_overrides, resource_label_rules
// -- change the classification FUNCTION (what tier an action derives, what
// label a resource resolves to), not a permission set, so containment does
// not typecheck against them. See the design doc's consumer section.
//
// All three grant endpoints are wired, each comparing exactly the dimensions
// its own write touches:
//
//	PUT /v1/agents/{id}/classification-caps  ClassificationCaps
//	PUT /v1/agents/{id}/resource-constraints ResourceConstraints
//	PUT /v1/agents/{id}                      Tools (allowed_tools)
//
// The third one is not an afterthought. It writes NEITHER of the first two
// columns -- updateAgentQuery's own doc comment (agent.go) records why both
// are absent from its SET list -- so there is nothing to compare on those
// dimensions and comparing them would be comparing a value to itself. But it
// does write allowed_tools, which IS a permission dimension
// (permset.Set.Tools, registry.go), and it is the one of the three gated at
// RoleEditor rather than RoleAdmin. An editor moving a restricted allowlist
// to the empty (meaning UNRESTRICTED) one is the widest single widening any
// of these endpoints can make.
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/permset"
)

const eventTypeContainment = "containment"

// containmentReason returns the reason this write widened the grant, or the
// empty string when it narrowed or left it unchanged.
//
// It is permset.GrantWidens, and it is a named function here only so this
// file's callers read in one register. The argument order that looks
// backwards -- before is the OUTER set -- and the whole explanation of why
// this is not a bare permset.Contains call live on GrantWidens itself. Read
// that doc comment before changing anything here; the two-line difference it
// describes is the difference between recording real widenings and stamping
// "widened" on the most protective write an operator makes.
func containmentReason(before, after permset.Set) string {
	return permset.GrantWidens(before, after)
}

// recordWideningTx appends the containment verdict to the tenant's hash chain
// when after is not contained in before, and does nothing at all otherwise --
// a verdict on every write would train operators to ignore the event type.
//
// Called inside the caller's own transaction, after its governed-row write
// and its own audit entry, so the verdict commits with the write it describes
// or not at all (N4). appendAuditTx is re-entrant within one transaction:
// pg_advisory_xact_lock is held for the transaction, so taking it a second
// time is free, and the chain-tail read that follows sees the caller's first
// entry, which this transaction has already inserted. The two rows chain onto
// each other in insertion order.
//
// occurredAt is the UPDATE's own RETURNING updated_at, the same value the
// caller stamped its first entry with: both rows describe one write, at the
// one clock the row itself recorded.
func (s *Store) recordWideningTx(
	ctx context.Context, tx *sql.Tx, id uuid.UUID, actor string,
	occurredAt time.Time, before, after permset.Set,
) error {
	reason := containmentReason(before, after)
	if reason == "" {
		return nil
	}
	return s.appendAuditTx(ctx, tx, audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    occurredAt,
		EventType:     eventTypeContainment,
		Actor:         actor,
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        "agent grant widened: " + reason,
	})
}
