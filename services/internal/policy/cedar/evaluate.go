package cedar

import (
	"context"
	"fmt"
	"strings"

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
// one authz.PolicyVerdict per policy that matched or failed to evaluate —
// every policy with something to say, not just the one Cedar's own
// deny-overrides fold would decide on.
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
// rather than reimplementing them.
//
// A per-policy evaluation error — diag.Errors non-empty — denies and names
// the policy (below), rather than being discarded the way a genuine
// non-match is. This is the fix for a review-found Critical: this method
// used to read only diag.Reasons and treat an evaluation error exactly like
// a non-match, silently dropping both the denial XACML's own Indeterminate
// branch (xacml/evaluate.go) would have produced for the equivalent case
// and the precise message Cedar had already computed to explain why. The
// project's recurring shape is a fail-closed guard placed one layer above
// the code that actually routes every case: multi.go's own deny-on-failure
// (multiSet.Evaluate, policy/multi.go) already guards a *language*
// erroring outright, one layer above this engine, but that guard was never
// reachable here because Evaluate never returned an error for a per-policy
// failure to trigger it. This closes the hole at the layer that does.
func (c compiledSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	req, entities := buildRequest(in)

	var verdicts []authz.PolicyVerdict
	for id, pol := range c.policies.All() {
		decision, diag := cedarlib.Authorize(cedarlib.PolicyMap{id: pol}, entities, req)
		m := c.meta[string(id)]

		if len(diag.Errors) > 0 {
			verdicts = append(verdicts, authz.PolicyVerdict{
				Effect:   authz.EffectDeny,
				Reason:   fmt.Sprintf("cedar: policy %s (%s) failed to evaluate: %s", id, m.name, joinDiagnosticErrors(diag.Errors)),
				Source:   language,
				PolicyID: string(id),
				Priority: m.priority,
			})
			continue
		}
		if len(diag.Reasons) == 0 {
			continue // did not match, no error: this policy contributes nothing
		}

		effect := authz.EffectDeny
		if decision == cedarlib.Allow {
			effect = authz.EffectAllow
		}

		verdicts = append(verdicts, authz.PolicyVerdict{
			Effect:   effect,
			Reason:   fmt.Sprintf("cedar: policy %s (%s) matched", id, m.name),
			Source:   language,
			PolicyID: string(id),
			Priority: m.priority,
		})
	}
	return verdicts, nil
}

// joinDiagnosticErrors formats every DiagnosticError's message for a
// verdict's Reason. cedar-go's own Diagnostic can carry more than one error
// for a single policy (e.g. independently-failing clauses of one
// condition), and the verdict must not silently drop all but the first.
func joinDiagnosticErrors(errs []cedarlib.DiagnosticError) string {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Message
	}
	return strings.Join(msgs, "; ")
}
