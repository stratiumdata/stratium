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
	}
	return LegResult{Effect: EffectAllow}, -1
}
