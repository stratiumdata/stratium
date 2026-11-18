package pdpgrpc

import (
	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/pkg/models"
)

// effectiveEscalateAt decides the threshold a new delegation is stored with.
//
// inherited is where the threshold comes from by default: the agent's, for a
// root, or the parent's, for a child. Neither is something the caller can
// write. requested is the caller's own ask. The result is the LOWER of the
// two, with nil meaning "never escalate", so a caller can make a delegation
// stricter but can never raise or remove the inherited threshold, whether by
// asking for more or by asking for nothing. That is the one property this
// function exists for: the caller is the party being policed.
//
// For a child whose parent has no threshold, a requested one is returned as
// is, and store.CreateDelegation's permset.Contains refuses it ("child
// introduces escalate_at"). That shape rule is deliberate and not this
// function's to relax.
//
// A threshold above the granted ceiling can never fire, so it is dropped and
// reported. That grants nothing: no reachable tier is at or above it. For a
// child this is exactly the case permset.Contains allows (a ceiling strictly
// below the parent's threshold), since the result is at most the parent's.
func effectiveEscalateAt(
	inherited, requested *models.ActionTier, grantedMax models.ActionTier,
) (*models.ActionTier, *authz.ClampRemoval) {
	t := inherited
	if requested != nil && (t == nil || *requested < *t) {
		r := *requested
		t = &r
	}
	if t != nil && *t > grantedMax {
		return nil, &authz.ClampRemoval{
			Dimension: "escalate_at",
			Value:     t.String(),
			Reason:    authz.ClampReasonUnreachable,
			Detail:    "granted max_action_tier " + grantedMax.String() + " is below it, so it could never fire",
		}
	}
	return t, nil
}

// escalateAtAuditValue is the delegation_created audit entry's Action value
// for a delegation's threshold. "none" is written out rather than left empty,
// so an entry issued without a threshold is distinguishable from one written
// before thresholds were recorded at all.
func escalateAtAuditValue(t *models.ActionTier) string {
	if t == nil {
		return "escalate_at none"
	}
	return "escalate_at " + t.String()
}
