package authz

// FoldVerdicts combines policy verdicts with deny-overrides and default-deny.
//
//  1. any deny               -> DENY
//  2. otherwise any escalate -> ESCALATE
//  3. otherwise no allow     -> DENY (default-deny)
//  4. otherwise              -> ALLOW
//
// Escalate is checked BEFORE default-deny because an escalate is a grant with
// a condition attached — "allow, pending human approval" — so it satisfies the
// "something granted this" requirement that default-deny tests for. With the
// checks the other way round, a policy whose only outcome is escalate produces
// a flat DENY and the rule is dead code, which is not a conservative default
// but a broken feature. Corrected 2026-08-09 after the original ordering was
// found to make a bare escalate inert.
//
// Step 3 is what preserves the invariant that an unevaluated principal leg
// denies. It used to hold because LegResult's zero value was EffectDeny; it
// now holds because a nil slice contains no allow. Same guarantee, different
// mechanism — which is why it is pinned by its own test rather than assumed
// to have carried over.
//
// The effect is order-independent by construction. The attributed reason is
// made order-independent too: among equally-decisive verdicts the fold picks
// the lexicographically smallest (Source, PolicyID), so a decision's recorded
// reason does not change between runs because a map iterated differently.
// Every verdict is preserved in provenance regardless, so nothing is lost.
func FoldVerdicts(vs []PolicyVerdict) (LegResult, *PolicyVerdict) {
	if d := decisiveVerdict(vs, EffectDeny); d != nil {
		return LegResult{Effect: EffectDeny, Reason: d.Reason}, d
	}

	if e := decisiveVerdict(vs, EffectEscalate); e != nil {
		return LegResult{Effect: EffectEscalate, Reason: e.Reason}, e
	}

	a := decisiveVerdict(vs, EffectAllow)
	if a == nil {
		return LegResult{Effect: EffectDeny, Reason: "default deny: no policy verdict allowed"}, nil
	}

	return LegResult{Effect: EffectAllow, Reason: a.Reason}, a
}

// decisiveVerdict returns the verdict in vs matching effect with the
// lexicographically smallest (Source, PolicyID), or nil if none match.
// Picking the minimum rather than the first match in slice order is what
// keeps attribution stable no matter how the caller assembled vs.
func decisiveVerdict(vs []PolicyVerdict, effect Effect) *PolicyVerdict {
	var best *PolicyVerdict
	for _, v := range vs {
		if v.Effect != effect {
			continue
		}
		if best == nil || v.Source < best.Source ||
			(v.Source == best.Source && v.PolicyID < best.PolicyID) {
			winner := v
			best = &winner
		}
	}
	return best
}
