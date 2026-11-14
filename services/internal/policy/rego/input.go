package rego

import (
	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

// buildInput maps a policy.EvaluationInput onto the plain map[string]any OPA
// evaluates policy text against as `input`. See the package doc's "input
// mapping" section for field naming and the two deliberate departures from
// Cedar's mapping.
func buildInput(in policy.EvaluationInput) map[string]any {
	return map[string]any{
		"principal": map[string]any{
			"subject":    in.Principal.Subject,
			"attributes": stringMapOrEmpty(in.Principal.Attributes),
		},
		"action": map[string]any{
			"tool": in.Action.Tool,
		},
		"resource":     stringMapOrEmpty(in.Resource),
		"derived_tier": int(in.DerivedTier),
		"agent":        agentDoc(in.Agent),
		"delegation":   delegationDoc(in.Delegation),
	}
}

// agentDoc carries the agent dimension under input.agent, named to match
// Cedar's context.agent record field for field (see the package doc).
func agentDoc(a authz.AgentInfo) map[string]any {
	return map[string]any{
		"id":            a.ID.String(),
		"trust_tier":    a.TrustTier.String(),
		"enabled":       a.Enabled,
		"suspended":     a.Suspended,
		"allowed_tools": stringsOrEmpty(a.AllowedTools),
	}
}

// delegationDoc carries the delegation dimension under input.delegation,
// named to match Cedar's context.delegation record field for field (see the
// package doc).
func delegationDoc(d policy.DelegationContext) map[string]any {
	return map[string]any{
		"depth":               d.Depth,
		"max_action_tier":     d.MaxActionTier.String(),
		"classification_caps": stringMapOrEmpty(d.ClassificationCaps),
		"purpose":             d.Purpose,
	}
}

// stringMapOrEmpty returns m, or a non-nil empty map when m is nil. A nil Go
// map passed through rego.EvalInput converts to Rego/JSON null, not {} — and
// count(), key lookup, and iteration over null are all undefined in Rego, not
// merely zero-valued (confirmed against this exact OPA release before
// writing this: a rule testing count(input.delegation.classification_caps)
// == 0 against a nil ClassificationCaps produces no result at all, not
// true). Cedar never has this problem — stringRecord ranges over its input
// map, and ranging over a nil map in Go is zero iterations, so Cedar's
// mapping already produces an empty Record for a nil field. This function is
// what makes Rego's mapping behave the same way Cedar's does: "no caps set"
// reads as an empty object in both languages, never null in one and {} in
// the other.
func stringMapOrEmpty(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// stringsOrEmpty is stringMapOrEmpty's counterpart for AllowedTools: a nil
// []string becomes Rego/JSON null the same way a nil map does, and
// `"x" in null` is undefined rather than false. An empty array keeps
// membership checks like `"x" in input.agent.allowed_tools` well-defined
// (false, not undefined) when an agent has no allowed tools recorded.
func stringsOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
