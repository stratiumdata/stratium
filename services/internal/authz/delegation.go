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
