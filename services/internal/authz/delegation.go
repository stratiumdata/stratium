package authz

import (
	"fmt"
	"time"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// DelegationLeg evaluates every hop in the chain, returning the leg result and
// the depth at which a denial occurred, or -1.
//
// This leg is structural and never policy-configurable. It is the ceiling: if
// policy could raise it, the signed delegation artifact would mean nothing
// (spec §4.3).
//
// Escalation is structural too, for the same reason (spec's E9 ruling):
// EscalateAt lives on the delegation, not on a policy verdict, so this leg
// computes it directly rather than folding a verdict. For each hop, given its
// own EscalateAt and MaxActionTier:
//
//	derived > MaxActionTier       -> DENY (checked first; unchanged by this leg)
//	EscalateAt <= derived <= max  -> ESCALATE
//	derived < EscalateAt          -> this hop has no opinion
//
// A hop whose band is met does not return immediately: a later, deeper hop
// can still deny for an unrelated reason (revoked, expired, wrong tool, a
// tighter cap), and deny overrides escalate within this leg exactly as it
// does across Decide's three legs. That rule has to be enforced here, not
// merely trusted to hold once Decide combines legs afterward, because a
// single delegation chain can produce both signals itself. So the loop keeps
// checking every remaining hop for a denial before an escalate found earlier
// is allowed to stand; only once the whole chain has cleared does a recorded
// escalate get returned.
//
// derived is the server-computed tier; the caller's declared tier never
// reaches this function.
func DelegationLeg(
	chain []*models.Delegation,
	a Action,
	derived models.ActionTier,
	resource map[string]string,
	resourceIDs []string,
	now time.Time,
	maxDepth int,
) (LegResult, int) {
	if len(chain) == 0 {
		return LegResult{Effect: EffectDeny, Reason: "no delegation in chain"}, -1
	}
	if len(chain)-1 > maxDepth {
		return LegResult{
			Effect: EffectDeny,
			Reason: fmt.Sprintf("delegation chain depth %d exceeds maximum %d", len(chain)-1, maxDepth),
		}, chain[len(chain)-1].Depth
	}

	// escalate holds the first hop (root-first, the same order a denial
	// binds in below) whose own band was met, or nil if none was. Recording
	// rather than returning is what lets a later hop's deny still win — see
	// the doc comment above.
	var escalate *LegResult

	for _, d := range chain {
		if d.Revoked {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("delegation %s at depth %d is revoked", d.ID, d.Depth)}, d.Depth
		}
		if !d.IsActive(now) {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("delegation %s at depth %d expired at %s",
					d.ID, d.Depth, d.ExpiresAt.Format(time.RFC3339))}, d.Depth
		}
		if derived > d.MaxActionTier {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("action tier %s exceeds delegation max_action_tier %s at depth %d",
					derived, d.MaxActionTier, d.Depth)}, d.Depth
		}
		if a.Tool != "" && !d.HasTool(a.Tool) {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("tool %q not in delegation approved_tools at depth %d",
					a.Tool, d.Depth)}, d.Depth
		}

		// Checked before CheckCap, not merely beside it: ResourceConstraints
		// names the specific key the request omitted or got wrong, which is
		// more actionable than CheckCap's own denial can be -- even now that
		// CheckCap denies loudly on missing classification too (Task 3, R2),
		// the most it can say is that the cap was uncheckable, never which
		// resource attribute was the problem. Ordering the more specific
		// reason first is what an operator most needs whenever both would
		// independently deny.
		//
		// This ordering was chosen at Task 2, when the reason was stronger
		// still: CheckCap read a resource with no classification as an
		// unconditional allow -- exactly the shape Task 1's own defect
		// produced -- so putting a silent pass behind a named denial was a
		// correctness argument, not merely a style one. Task 3 closed that
		// gap (CheckCap denies on its own now), leaving only the specificity
		// argument above -- recorded so a future reader does not wonder why
		// this comment changed but the order did not.
		if allowed, reason := checkResourceConstraints(d.ResourceConstraints, resource, resourceIDs); !allowed {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("%s (depth %d)", reason, d.Depth)}, d.Depth
		}
		if allowed, reason := classification.CheckCap(d.ClassificationCaps, resource); !allowed {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("%s (depth %d)", reason, d.Depth)}, d.Depth
		}

		// Reaching here means derived <= d.MaxActionTier (the ceiling check
		// above would have returned otherwise), so EscalateAt <= derived is
		// exactly the closed-band membership test — no separate upper-bound
		// check is needed at this line.
		if escalate == nil && d.EscalateAt != nil && *d.EscalateAt <= derived {
			escalate = &LegResult{Effect: EffectEscalate, Reason: fmt.Sprintf(
				"action tier %s at or above delegation escalate_at %s at depth %d",
				derived, *d.EscalateAt, d.Depth)}
		}
	}

	if escalate != nil {
		// Not a denial, so the depth sentinel is -1, matching
		// Result.DeniedAtDepth's own documented meaning; the escalating
		// hop's depth is still named in Reason above for audit.
		return *escalate, -1
	}
	return LegResult{Effect: EffectAllow}, -1
}

// checkResourceConstraints enforces a delegation's ResourceConstraints
// against the request's resource attributes, returning the same (bool,
// string) shape as classification.CheckCap so the two calls above read as
// one register.
//
// ScopeNarrows (pkg/models/delegation.go) answers a different question --
// what a child delegation may inherit from its parent -- and has done so
// since Phase 0. Nothing has ever compared a constraint against a request;
// these rules are new here:
//
//   - a key the constraints require but the request does not carry -> DENY.
//     This is the load-bearing rule: the constraint exists to bound what the
//     agent may reach, and a request that does not say what it is reaching
//     cannot be shown to satisfy that bound. Passing here would recreate,
//     for identity, exactly the defect this phase exists to fix for
//     classification -- CheckCap reading an absent attribute as nothing to
//     restrict.
//   - a key both sides carry, with different values -> DENY.
//   - a key both sides carry, with the same value -> that key is satisfied.
//     Comparison is exact -- no prefixes, wildcards, or ranges. Same reason
//     ScopeNarrows' own resource-constraint comment gives: every such
//     interpretation is a place a widening can hide, and values here are
//     opaque caller-defined strings with no ordering to narrow along.
//   - a resource attribute the constraints do not mention -> ignored. A
//     constraint set is a filter, not a schema; it only ever speaks to the
//     keys it names.
//   - constraints itself is empty -> unrestricted, matching
//     Delegation.HasTool's treatment of an empty approved-tools list (both
//     read as zero iterations below, with no special case needed). This is
//     the one place that empty-means-unrestricted convention survives past
//     spec section 4.3.1's tightening -- ScopeNarrows' own resource-constraint
//     loops enforce the opposite direction for inheritance (a child may not
//     add a key its parent left unconstrained, so "empty" only ever
//     propagates forward through a lineage, never backward) -- called out
//     because a reader who knows §4.3.1 will otherwise expect the strict
//     reading here too.
func checkResourceConstraints(constraints, resource map[string]string, ids []string) (bool, string) {
	for key, want := range constraints {
		// The one key with prefix semantics. Checked against the resolved
		// identities rather than resource[key], because a shell call has
		// several identities and no "id" attribute at all — writing one
		// would let a decoy satisfy this while another path did the work.
		if key == models.ResourceIDPrefixKey {
			if ok, reason := satisfiesIDPrefix(ids, want); !ok {
				return false, reason
			}
			continue
		}
		got, ok := resource[key]
		if !ok {
			return false, fmt.Sprintf("resource constraint %q is required but absent from the request", key)
		}
		if got != want {
			return false, fmt.Sprintf("resource constraint %s=%q does not match request value %q", key, want, got)
		}
	}
	return true, ""
}
