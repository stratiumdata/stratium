package cedar

import (
	"context"
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

// compiledSet is Engine's policy.CompiledPolicySet: a parsed cedar.PolicySet
// plus the per-policy metadata (name, priority) Cedar itself doesn't carry.
// Both fields are populated once by Prepare and never mutated afterward —
// cedar.PolicySet.All() only reads, and Cedar's own Authorize does not
// mutate the policies it evaluates — so a compiledSet is safe for
// concurrent Evaluate calls, the property policy.CompiledPolicySet requires.
type compiledSet struct {
	policies *cedarlib.PolicySet
	meta     map[string]policyMeta
}

var _ policy.CompiledPolicySet = compiledSet{}

// Evaluate maps in onto a Cedar request (see the package doc) and returns
// one authz.PolicyVerdict per policy that matched — every policy that
// matched, not just the one Cedar's own deny-overrides fold would decide on.
//
// Cedar's top-level Authorize applies deny-overrides itself across the whole
// PolicySet: once any forbid matches, it reports only the forbids as
// "reasons" and silently drops which permits also matched. Calling it once
// over the whole set would therefore lose verdicts — exactly the ones the
// priority-independence test (and the real fold, authz.FoldVerdicts,
// downstream) need to see. Instead this runs Authorize once per policy,
// against a singleton set containing only that policy: for one policy,
// Cedar's decision is entirely determined by whether it matched and what its
// own effect is, so this reuses Cedar's real match-and-error semantics
// (including that a per-policy evaluation error is treated the same as a
// non-match) rather than reimplementing them.
func (c compiledSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	req, entities := buildRequest(in)

	var verdicts []authz.PolicyVerdict
	for id, pol := range c.policies.All() {
		decision, diag := cedarlib.Authorize(cedarlib.PolicyMap{id: pol}, entities, req)
		if len(diag.Reasons) == 0 {
			continue // did not match; an evaluation error is silent the same way
		}

		effect := authz.EffectDeny
		if decision == cedarlib.Allow {
			effect = authz.EffectAllow
		}

		m := c.meta[string(id)]
		verdicts = append(verdicts, authz.PolicyVerdict{
			Effect:   effect,
			Reason:   fmt.Sprintf("cedar: policy %s (%s) matched", id, m.name),
			Source:   "cedar",
			PolicyID: string(id),
			Priority: m.priority,
		})
	}
	return verdicts, nil
}
