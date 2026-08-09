package authz

// Config is the tenant's resolved decision configuration, loaded by the caller.
type Config struct {
	Tiers    TierTable
	Trust    TrustTable
	MaxDepth int
}

// Decide computes the compound authorization decision.
//
//	allow = principal ∧ agent ∧ delegation
//
// Each leg is an independent AND term. Because the structural legs are
// separate terms, a policy returning ALLOW can never exceed the delegation
// artifact — the ceiling holds by construction (spec §4.3).
//
// Deny-overrides: any single deny is final. Escalate surfaces only when
// nothing denies.
func Decide(req Request, cfg Config) Result {
	res := Result{DeniedAtDepth: -1}

	// Derive the tier server-side. The declared value is never an input here
	// (spec §4.4, C3).
	derived, err := DeriveTier(cfg.Tiers, req.Action)
	if err != nil {
		res.Effect = EffectDeny
		res.DeniedLeg = "delegation"
		res.Reason = err.Error()
		res.Delegation = LegResult{Effect: EffectDeny, Reason: err.Error()}
		return res
	}
	res.DerivedTier = derived

	// Under-declaration is a spoofing attempt (C1), rejected before any leg is
	// consulted and attributed to the agent — the agent is what lied.
	if check := CheckDeclaredTier(derived, req.Action.DeclaredTier); check.Effect != EffectAllow {
		res.Effect = EffectDeny
		res.DeniedLeg = "agent"
		res.Reason = check.Reason
		res.Agent = check
		return res
	}

	// The principal leg's zero value is EffectDeny, so a caller that forgets to
	// evaluate it denies rather than silently permitting (C11, C13).
	res.Principal = req.PrincipalDecision
	res.Agent = AgentLeg(req.Agent, req.Action, derived, cfg.Trust)
	delegationLeg, deniedDepth := DelegationLeg(
		req.Chain, req.Action, derived, req.Resource, req.Now, cfg.MaxDepth)
	res.Delegation = delegationLeg

	// Deny-overrides, in a fixed order so attribution is deterministic (C12, C13).
	for _, leg := range []struct {
		name   string
		result LegResult
	}{
		{"principal", res.Principal},
		{"agent", res.Agent},
		{"delegation", res.Delegation},
	} {
		if leg.result.Effect == EffectDeny {
			res.Effect = EffectDeny
			res.DeniedLeg = leg.name
			res.Reason = leg.result.Reason
			if res.Reason == "" {
				res.Reason = leg.name + " leg denied"
			}
			if leg.name == "delegation" {
				res.DeniedAtDepth = deniedDepth
			}
			return res
		}
	}

	// Nothing denied. Escalate wins over allow if any leg requests it.
	for _, leg := range []LegResult{res.Principal, res.Agent, res.Delegation} {
		if leg.Effect == EffectEscalate {
			res.Effect = EffectEscalate
			res.Reason = leg.Reason
			return res
		}
	}

	res.Effect = EffectAllow
	return res
}
