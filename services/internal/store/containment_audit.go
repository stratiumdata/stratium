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
func containmentReason(before, after permset.Set) string {
	// DO NOT DELETE THESE TWO LINES AS A SIMPLIFICATION. They are the whole
	// difference between this function and a bare call to permset.Contains,
	// and removing them puts a FALSE "widened" verdict on the most common
	// write this package makes. The reasoning, in full:
	//
	// WHAT CONTAINS DOES. Given a key the inner set holds and the outer set
	// does not, Contains refuses it -- "child caps hierarchy X which parent
	// does not cap", "child constrains resource key X which parent does not
	// constrain". That is DELIBERATE where Contains was written, and
	// contains.go's own doc comment says so and tells you not to "fix" it:
	// those two rules are explicitly NOT lattice containment (spec 4.3.1).
	// They exist so a child delegation's SHAPE is derivable from its
	// parent's -- a child may not invent a dimension the parent never had.
	//
	// WHY THAT ANSWER IS INVERTED HERE. An agent grant before/after is a
	// pure LATTICE question, not a delegation-shape one. An absent cap means
	// UNRESTRICTED (classification.CheckCap ALLOWs when len(caps)==0) and an
	// absent constraint key means unrestricted too, so introducing either
	// one NARROWS the grant. Under a bare Contains, the first cap and the
	// first id_prefix an agent ever gets -- the narrowest, most common write
	// an operator makes -- would each be recorded as a widening. That is
	// exactly the noise that teaches operators to ignore an event type, and
	// this whole file is worthless once they do.
	//
	// WHAT THE PRE-FILL DOES, AND ONLY THAT. It gives the before value every
	// key the after value introduces, at the after value's own setting, so
	// an introduced key compares equal to itself and is silent. Nothing else
	// moves: a key DROPPED, a cap RAISED and a prefix WIDENED all still
	// report, which contains_test.go's siblings in containment_audit_test.go
	// pin in both directions.
	//
	// WHERE THIS BELONGS LONG TERM. In pkg/permset, as a named second
	// operation beside Contains and Union -- this is a general question
	// ("did this grant widen?"), not a store concern, and an adapter in
	// internal/store is the wrong home for it. The controller has ledgered
	// that as a follow-up. Until it lands, this is the seam; do not close it
	// by deleting it.
	//
	// before is a copy (Set is a value) and withIntroducedKeys allocates, so
	// the caller's own maps -- one of which is the row this write is about
	// to describe -- are never written through.
	before.ClassificationCaps = withIntroducedKeys(before.ClassificationCaps, after.ClassificationCaps)
	before.ResourceConstraints = withIntroducedKeys(before.ResourceConstraints, after.ResourceConstraints)

	// ponytail: the same asymmetry exists on EscalateAt (introducing one
	// where the before value has none reports a widening) and is NOT
	// handled, because no caller sets that field -- each compares one
	// dimension with the rest at their zero value on both sides. Tools needs
	// no pre-fill at all: Contains' tools clause is already a pure lattice
	// rule, skipping entirely when the outer list is the empty (meaning
	// unrestricted) one. A future caller that passes a whole agent grant
	// needs the EscalateAt case added here first.
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
