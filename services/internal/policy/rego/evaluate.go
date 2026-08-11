package rego

import (
	"context"
	"fmt"

	regolib "github.com/open-policy-agent/opa/v1/rego"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

// compiledSet is Engine's policy.CompiledPolicySet: every policy's
// rego.PreparedEvalQuery plus its metadata, keyed by StoredPolicy.ID.
// Populated once by Prepare and never mutated afterward — OPA documents a
// PreparedEvalQuery as safe to evaluate concurrently from many goroutines,
// and this map is never written to after Prepare returns — so a compiledSet
// is safe for concurrent Evaluate calls, the property policy.CompiledPolicySet
// requires.
type compiledSet struct {
	policies map[string]compiledPolicy
}

var _ policy.CompiledPolicySet = compiledSet{}

// Evaluate maps in onto the OPA input document (see input.go) and returns
// one authz.PolicyVerdict per policy that matched — every policy that
// matched, not just whichever one a combining rule would pick. The returned
// slice is built fresh on every call (appended into a nil local, never a
// field on compiledSet): a compiled set is shared across every concurrent
// decision for a tenant, so a verdict slice reused or precomputed across
// calls would let two goroutines race over the same backing array the
// instant a caller (multiSet.Evaluate, see policy/multi.go) appended to or
// sorted its own copy of what it got back.
func (c compiledSet) Evaluate(ctx context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	input := buildInput(in)

	var verdicts []authz.PolicyVerdict
	for id, cp := range c.policies {
		rs, err := cp.query.Eval(ctx, regolib.EvalInput(input))
		if err != nil {
			// A per-policy runtime error — e.g. a type mismatch a tenant's
			// own rule body triggers only against this particular input —
			// is not a match, the same way Cedar treats a per-policy
			// evaluation error as equivalent to a non-match rather than
			// aborting the whole set (see cedar/evaluate.go's own doc
			// comment). One broken policy contributing nothing must not
			// cost this tenant's other Rego policies their verdicts too;
			// see multiSet.Evaluate's own doc comment for why the same
			// principle applies one level up, across languages.
			continue
		}

		allow, deny := decision(rs)
		if !allow && !deny {
			continue // neither rule fired: this policy did not match
		}

		effect := authz.EffectAllow
		if deny {
			// Both true resolves to deny — see the package doc's "query
			// convention" section for why that is decided here rather than
			// left to authz.FoldVerdicts.
			effect = authz.EffectDeny
		}

		verdicts = append(verdicts, authz.PolicyVerdict{
			Effect:   effect,
			Reason:   fmt.Sprintf("rego: policy %s (%s) matched", id, cp.name),
			Source:   "rego",
			PolicyID: id,
			Priority: cp.priority,
		})
	}
	return verdicts, nil
}

// decision reads the allow and deny keys off a query result for
// queryPath ("data.stratium.policy"). Only a literal boolean true counts as
// a match for either key: an absent key (the rule was never defined, or was
// defined but its condition did not hold and it has no `default`) and a
// present-but-false key (the rule fired its `default ... := false` case)
// are both "did not match" — collapsing them is deliberate, not an
// oversight, because a tenant is free to author either style and both must
// mean the same thing to this engine. A malformed or missing result — an
// empty ResultSet, no expressions, or a value that is not a JSON object —
// is treated the same way: no match, not an error, so that a policy whose
// module declares a different package (and therefore never populates
// queryPath at all) yields silence rather than a panic.
func decision(rs regolib.ResultSet) (allow, deny bool) {
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return false, false
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return false, false
	}
	allow, _ = doc["allow"].(bool)
	deny, _ = doc["deny"].(bool)
	return allow, deny
}
