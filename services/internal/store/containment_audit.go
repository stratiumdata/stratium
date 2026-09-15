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
// Of the three grant endpoints, two are wired here: the caps and
// resource-constraints routes. PUT /v1/agents/{id} writes neither column
// (updateAgentQuery's own doc comment, agent.go, records why both are absent
// from its SET list) but it DOES write allowed_tools, which is a permission
// dimension (permset.Set.Tools) and can be widened from a restricted
// allowlist to the empty, unrestricted one. That write is not covered here,
// because this task's brief names only these two files -- a real gap, named
// rather than left to be discovered.
package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/permset"
)

const eventTypeContainment = "containment"

// containmentReason returns the reason the new grant is not contained in the
// old one, or the empty string when the write narrows or leaves it unchanged.
//
// Argument order reads backwards on purpose: Contains(outer, inner) asks
// whether inner fits inside outer, so the BEFORE value is the outer one. A
// write is a widening exactly when the after value does not fit inside it.
//
// The before value is first given every caps/constraints KEY the after value
// introduces, at the after value's own setting, and that is not a detail.
// Contains is written for delegation attenuation, where a child that
// introduces a key its parent does not hold is refused even though it
// narrows -- contains.go's own doc comment calls both of those rules
// deliberately stricter than the lattice, and tells you not to "fix" them.
// Asked as a before/after question the same rule is simply backwards: an
// agent with no caps enforces nothing, so the first PUT that sets one -- the
// narrowest write an operator ever makes, and the most common one on this
// path -- would be recorded as a widening. Pre-filling makes an introduced
// key compare equal to itself, which leaves exactly the widenings: a key
// DROPPED, a cap RAISED, a prefix WIDENED.
//
// ponytail: the same asymmetry exists on EscalateAt (introducing one where
// the before value has none reports a widening) and is NOT handled, because
// neither caller sets that field -- both compare one map dimension with
// every other field at its zero value on both sides. A future caller that
// passes a whole agent grant needs the EscalateAt case added here first.
func containmentReason(before, after permset.Set) string {
	// before is a copy (Set is a value), and both fills build new maps, so
	// the caller's own maps -- one of which is the row this write is about to
	// describe -- are never written through.
	before.ClassificationCaps = withIntroducedKeys(before.ClassificationCaps, after.ClassificationCaps)
	before.ResourceConstraints = withIntroducedKeys(before.ResourceConstraints, after.ResourceConstraints)
	return permset.Contains(before, after)
}

// withIntroducedKeys returns a new map holding base plus every key of extra
// that base does not already hold, at extra's value. Neither input is
// modified.
func withIntroducedKeys(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range extra {
		out[k] = v
	}
	for k, v := range base {
		out[k] = v
	}
	return out
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
