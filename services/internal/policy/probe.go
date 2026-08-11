package policy

import (
	"context"
	"fmt"

	"stratium/internal/authz"
	"stratium/pkg/models"
)

// GrantProbe asks what a principal may delegate, as distinct from what they
// may do. It answers only the resource-independent dimensions — the
// action-tier ceiling and the tool set (spec §3.8 G6, amended 2026-08-10) —
// because a probe carries no resource and a resource-conditional policy
// would not match one. Resource scope and classification are left to the
// runtime principal leg, which has the concrete resource and evaluates every
// action anyway.
type GrantProbe struct {
	Principal authz.Principal
	Tool      string // empty when probing the tier ceiling
	Tier      models.ActionTier
}

// Probe asks set whether p's principal may hold what p describes, and
// reports whether the result allows. It builds an EvaluationInput with no
// resource and no agent — at delegation-creation time there is neither, only
// the principal and the dimension being probed — evaluates it against set,
// and folds the verdicts with authz.FoldVerdicts rather than a second
// combining rule: deny-overrides and default-deny apply here exactly as they
// do to a runtime decision, and this is precisely why C12's fold moved into
// authz — a security property enforced in two places drifts.
//
// An engine error is not swallowed. It denies — fail-closed, the same as
// Configured.Evaluate's own failure paths — and is also returned, so a
// caller can distinguish "policy says no" from "we could not ask."
func Probe(ctx context.Context, set CompiledPolicySet, p GrantProbe) (bool, error) {
	in := EvaluationInput{
		Principal:   p.Principal,
		Action:      authz.Action{Tool: p.Tool},
		DerivedTier: p.Tier,
		// Resource and Agent are deliberately left at their zero values: a
		// probe asks what the principal may hold before any concrete
		// resource or acting agent exists. Do not populate Resource here —
		// see GrantProbe's doc comment and probe_test.go's
		// resource-scoped-policy test for why a resourceless probe
		// under-granting resource-conditional policies is accepted, not a
		// gap to fill in.
	}

	verdicts, err := set.Evaluate(ctx, in)
	if err != nil {
		return false, fmt.Errorf("probe: %w", err)
	}

	result, _ := authz.FoldVerdicts(verdicts)
	return result.Effect == authz.EffectAllow, nil
}
