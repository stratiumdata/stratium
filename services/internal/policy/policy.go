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

// PrincipalPolicy decides the principal leg: whether the human on whose
// behalf the agent acts may perform this action, on this resource, in this
// context. Evaluate receives the agent and delegation dimensions too (see
// EvaluationInput) so a policy can condition on them — "deny Unverified
// agents on financial tools" — but it still answers for the principal leg
// alone; the agent and delegation legs are decided elsewhere, as separate AND
// terms, so nothing here can widen what they allow.
//
// Evaluate returns every verdict it consulted — authz.FoldVerdicts is what
// combines them with deny-overrides — so provenance for each one survives
// into the response and the audit row.
type PrincipalPolicy interface {
	Evaluate(ctx context.Context, in EvaluationInput) []authz.PolicyVerdict
}

type unconfigured struct{}

// Unconfigured denies every request with a legible reason. It is the only
// implementation in Phase 1c.
func Unconfigured() PrincipalPolicy { return unconfigured{} }

func (unconfigured) Evaluate(context.Context, EvaluationInput) []authz.PolicyVerdict {
	// Exactly one verdict, not zero. FoldVerdicts folds a nil/empty slice to
	// deny too, but with its own generic "default deny: no policy verdict
	// allowed" text — only a real verdict carries this specific reason
	// through to the response and the audit row.
	return []authz.PolicyVerdict{{
		Effect: authz.EffectDeny,
		Source: "none",
		Reason: "principal: no policy engine configured (Phase 2)",
	}}
}
