package xacml

import (
	"context"
	"fmt"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

// compiledPolicy is one StoredPolicy's validated, evaluable form — built
// once by Prepare from parseAndValidate's output and walked, never
// re-parsed, by Evaluate. name and priority are carried alongside the
// validated document because they come from StoredPolicy, not from the
// XML text itself (the same split jsonpolicy's compiledPolicy and rego's
// compiledPolicy make for their own StoredPolicy-only metadata).
type compiledPolicy struct {
	id       string
	name     string
	priority int
	target   *xmlTarget
	rules    []compiledRule
}

// compiledRule is one <Rule>, reduced to what Evaluate needs: Effect
// converted to authz.Effect once here, in Prepare, rather than on every
// decision.
type compiledRule struct {
	id     string
	effect authz.Effect
	target *xmlTarget
}

// newCompiledPolicy builds a compiledPolicy from sp's metadata and doc, a
// document parseAndValidate has already fully validated — this function
// performs no validation of its own and cannot fail.
func newCompiledPolicy(sp policy.StoredPolicy, doc xmlPolicy) compiledPolicy {
	rules := make([]compiledRule, len(doc.Rules))
	for i, r := range doc.Rules {
		rules[i] = compiledRule{id: r.RuleID, effect: effectOf(r.Effect), target: r.Target}
	}
	return compiledPolicy{
		id:       sp.ID,
		name:     sp.Name,
		priority: sp.Priority,
		target:   doc.Target,
		rules:    rules,
	}
}

// effectOf converts a validated Rule's Effect attribute into authz.Effect.
// (xmlRule).validate has already rejected every value except effectPermit
// and effectDeny by the time this is called, so the fallthrough to
// EffectDeny below is unreachable in practice — but EffectDeny is also
// authz.Effect's zero value, deliberately (see authz.Effect's own doc
// comment: "a leg that is never evaluated must deny rather than silently
// permit"), so even a hypothetical future caller with an unvalidated Effect
// fails in the safe direction rather than panicking or defaulting to
// allow. The same choice jsonpolicy's own effectOf makes.
func effectOf(s string) authz.Effect {
	if s == effectPermit {
		return authz.EffectAllow
	}
	return authz.EffectDeny
}

// compiledSet is Engine's policy.CompiledPolicySet: every policy's
// validated, compiled form, in a slice built once by Prepare and never
// mutated afterward — so a compiledSet is safe for concurrent Evaluate
// calls, the property policy.CompiledPolicySet requires.
type compiledSet struct {
	policies []compiledPolicy
}

var _ policy.CompiledPolicySet = compiledSet{}

// Evaluate returns one authz.PolicyVerdict per policy whose evaluation
// resolved to Permit, Deny, or Indeterminate — every policy with something
// to say, not just one a cross-policy combining rule would pick (that
// combining belongs to authz.FoldVerdicts alone; see the package doc). The
// returned slice is built fresh on every call, appended into a nil local
// that is never a field on compiledSet: a compiled set is shared across
// every concurrent decision for a tenant, so a verdict slice reused or
// precomputed across calls would let two goroutines race the instant a
// caller (multiSet.Evaluate, see policy/multi.go) appended to or sorted its
// own copy of what it got back — the exact bug Task 2 found live in
// multi.go's own Evaluate before it was fixed there.
func (c compiledSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	var verdicts []authz.PolicyVerdict
	for _, cp := range c.policies {
		if v := cp.evaluate(in); v != nil {
			verdicts = append(verdicts, *v)
		}
	}
	return verdicts, nil
}

// evaluate is one Policy's complete contribution to a decision: at most one
// verdict, or nil when nothing about this policy applies to in. Rule
// combining here is deny-overrides only — the one combining decision this
// engine implements, because it is internal to a single <Policy> rather
// than the cross-policy combining authz.FoldVerdicts alone owns (see the
// package doc).
//
// An Indeterminate outcome — the Policy's own Target, or any Rule's,
// naming an attribute designator that cannot be resolved — returns a deny
// verdict immediately, never nil and never a silent skip: that branch is
// what the package doc's "Indeterminate: an unresolvable designator
// denies" section requires, and it is why this function returns *before*
// even looking at the Rules once the Policy's own Target is Indeterminate,
// and returns immediately on the first Indeterminate Rule rather than
// finishing the loop.
func (cp compiledPolicy) evaluate(in policy.EvaluationInput) *authz.PolicyVerdict {
	matched, indeterminateOn := cp.target.evaluate(in)
	if indeterminateOn != "" {
		return cp.denyVerdict(fmt.Sprintf("policy %s (%s): target attribute designator %q could not be resolved (Indeterminate)", cp.id, cp.name, indeterminateOn))
	}
	if !matched {
		return nil // this policy's target excludes the request: no verdict, not a denial
	}

	var permitRuleID string
	sawPermit := false
	for _, r := range cp.rules {
		rMatched, rIndeterminateOn := r.target.evaluate(in)
		if rIndeterminateOn != "" {
			// Deny-overrides: an Indeterminate rule is folded in as a deny
			// signal (see the package doc), and a Deny signal — explicit or
			// via Indeterminate — is immediately decisive. No later rule in
			// this policy can change that, so this returns now rather than
			// finishing the loop.
			return cp.denyVerdict(fmt.Sprintf("policy %s (%s) rule %s: target attribute designator %q could not be resolved (Indeterminate)", cp.id, cp.name, r.id, rIndeterminateOn))
		}
		if !rMatched {
			continue
		}
		if r.effect == authz.EffectDeny {
			return cp.verdict(authz.EffectDeny, fmt.Sprintf("policy %s (%s) rule %s (Deny) matched", cp.id, cp.name, r.id))
		}
		// A matched Permit rule is recorded, not returned immediately: a
		// later rule in document order might still Deny or be
		// Indeterminate, either of which must override it under
		// deny-overrides. Only the first matched Permit is kept — which
		// rule's ID appears in the verdict's Reason if several would have
		// matched is otherwise an arbitrary choice, and "first in document
		// order" is a deterministic one, unlike Go's randomised map
		// iteration elsewhere in this package tree.
		if !sawPermit {
			sawPermit = true
			permitRuleID = r.id
		}
	}
	if sawPermit {
		return cp.verdict(authz.EffectAllow, fmt.Sprintf("policy %s (%s) rule %s (Permit) matched", cp.id, cp.name, permitRuleID))
	}
	return nil // no rule matched: this policy contributes nothing
}

// verdict builds this policy's contribution with the given effect and
// reason, carrying provenance (Source, PolicyID, Priority) the same way
// every other engine's own verdict constructor does.
func (cp compiledPolicy) verdict(effect authz.Effect, reason string) *authz.PolicyVerdict {
	return &authz.PolicyVerdict{
		Effect:   effect,
		Reason:   "xacml: " + reason,
		Source:   language,
		PolicyID: cp.id,
		Priority: cp.priority,
	}
}

func (cp compiledPolicy) denyVerdict(reason string) *authz.PolicyVerdict {
	return cp.verdict(authz.EffectDeny, reason)
}

// evaluate is a Match's tri-state outcome: definitely true, definitely
// false, or Indeterminate — indeterminateOn names the AttributeDesignator
// that could not be resolved, and is empty in both definite cases (safe as
// a sentinel because (*xmlMatch's own Designator).validate has already
// rejected an empty AttributeId — see xmlMatch.validate). XACML defines
// this third outcome specifically for the case handled here — an
// attribute designator with no resolvable value — and this package's
// mandate (see the package doc) is to carry it through, never to quietly
// collapse it into "did not match" along the way.
func (m xmlMatch) evaluate(in policy.EvaluationInput) (matched bool, indeterminateOn string) {
	value, ok := resolveAttr(in, m.Designator.AttributeID)
	if !ok {
		return false, m.Designator.AttributeID
	}
	return value == m.Value.Text, ""
}

// evaluate is AllOf's tri-state outcome: AND across every Match, with
// Indeterminate treated as absorbing rather than XACML's full
// strong-Kleene short-circuiting (where a definite false elsewhere in the
// same AllOf could "rescue" an indeterminate sibling back to a clean
// false) — see the package doc's "Indeterminate" section for why that
// simplification is deliberate and safe here: it can only make this engine
// deny in a few cases the full algebra would have called a non-match,
// never the reverse.
func (a xmlAllOf) evaluate(in policy.EvaluationInput) (matched bool, indeterminateOn string) {
	for _, m := range a.Match {
		mMatched, indet := m.evaluate(in)
		if indet != "" {
			return false, indet
		}
		if !mMatched {
			return false, ""
		}
	}
	return true, ""
}

// evaluate is AnyOf's tri-state outcome: OR across every AllOf, same
// Indeterminate-is-absorbing simplification as (xmlAllOf).evaluate.
func (o xmlAnyOf) evaluate(in policy.EvaluationInput) (matched bool, indeterminateOn string) {
	for _, a := range o.AllOf {
		aMatched, indet := a.evaluate(in)
		if indet != "" {
			return false, indet
		}
		if aMatched {
			return true, ""
		}
	}
	return false, ""
}

// evaluate is Target's tri-state outcome: OR across every AnyOf, with one
// deliberate special case ahead of the loop. t is a pointer specifically so
// this method can be called directly on a nil Target (Policy- or
// Rule-level Target entirely absent) without its caller needing a separate
// nil check first — Go permits calling a pointer-receiver method on a nil
// receiver as long as the method itself does not dereference it before
// checking, which is exactly what happens here.
func (t *xmlTarget) evaluate(in policy.EvaluationInput) (matched bool, indeterminateOn string) {
	if t == nil || len(t.AnyOf) == 0 {
		// XACML defines a Target with no AnyOf — including one that is
		// entirely absent, the shape this engine's own AllowAll/DenyAll
		// fixtures use — as an unconditional Match, not as the "OR of zero
		// terms is false" a naive reading of the loop below would produce.
		// This is a deliberate branch, not a fallthrough: without it, the
		// loop's zero-iteration default would report NoMatch, and every
		// "applies to everything" policy or rule in this engine would
		// silently stop matching anything.
		return true, ""
	}
	for _, a := range t.AnyOf {
		aMatched, indet := a.evaluate(in)
		if indet != "" {
			return false, indet
		}
		if aMatched {
			return true, ""
		}
	}
	return false, ""
}
