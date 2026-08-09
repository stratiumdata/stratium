// Package policy is the seam the policy engines plug into in Phase 2.
//
// It has one implementation today and that implementation denies. There is
// deliberately no allow-all variant, not even behind a flag: the predecessor
// carried a development-only auth fallback into production, where any OIDC
// blip silently accepted forged tokens. A bypass outlives the reason it was
// added.
package policy

import (
	"context"

	"stratium/internal/authz"
)

// PrincipalPolicy answers whether the principal may perform this action on this
// resource, independent of which agent is acting.
type PrincipalPolicy interface {
	Evaluate(ctx context.Context, p authz.Principal, action authz.Action, resource map[string]string) authz.LegResult
}

type unconfigured struct{}

// Unconfigured denies every request with a legible reason. It is the only
// implementation in Phase 1c.
func Unconfigured() PrincipalPolicy { return unconfigured{} }

func (unconfigured) Evaluate(context.Context, authz.Principal, authz.Action, map[string]string) authz.LegResult {
	return authz.LegResult{
		Effect: authz.EffectDeny,
		Reason: "principal: no policy engine configured (Phase 2)",
	}
}
