package authz

// FoldVerdicts combines policy verdicts with deny-overrides and default-deny.
//
//  1. any deny            -> DENY
//  2. otherwise no allow  -> DENY (default-deny)
//  3. otherwise any escalate -> ESCALATE
//  4. otherwise           -> ALLOW
//
// Step 2 is what preserves the invariant that an unevaluated principal leg
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

	if decisiveVerdict(vs, EffectAllow) == nil {
		return LegResult{Effect: EffectDeny, Reason: "default deny: no policy verdict allowed"}, nil
	}

	if e := decisiveVerdict(vs, EffectEscalate); e != nil {
		return LegResult{Effect: EffectEscalate, Reason: e.Reason}, e
	}

	a := decisiveVerdict(vs, EffectAllow)
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
