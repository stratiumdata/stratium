package jsonpolicy

import (
	"context"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

// compiledPolicy is one StoredPolicy's validated, evaluable form — built
// once by Prepare from parseDoc's output and walked, never re-parsed, by
// Evaluate. reason is precomputed here rather than formatted per decision,
// the same choice Cedar and Rego make for their own verdict Reason strings.
type compiledPolicy struct {
	id       string
	priority int
	effect   authz.Effect
	reason   string
	// match is never nil on a compiledPolicy Prepare produced: parseDoc
	// rejects a missing match block before Prepare ever builds one of
	// these. A non-nil *match with every field nil (the {} case) is the
	// documented match-everything policy, not a special case this type
	// needs to represent separately.
	match *match
}

// compiledSet is Engine's policy.CompiledPolicySet: every policy's validated
// match tree plus its metadata, in a slice built once by Prepare and never
// mutated afterward — so a compiledSet is safe for concurrent Evaluate
// calls, the property policy.CompiledPolicySet requires.
type compiledSet struct {
	policies []compiledPolicy
}

var _ policy.CompiledPolicySet = compiledSet{}

// Evaluate returns one authz.PolicyVerdict per policy whose match tree is
// satisfied by in — every policy that matched, not just one a combining rule
// would pick. The returned slice is built fresh on every call, appended into
// a nil local that is never a field on compiledSet: a compiled set is shared
// across every concurrent decision for a tenant, so a verdict slice reused or
// precomputed across calls would let two goroutines race the instant a
// caller (multiSet.Evaluate, see policy/multi.go) appended to or sorted its
// own copy of what it got back — the exact bug Task 2 found live in
// multi.go's own Evaluate before it was fixed there.
func (c compiledSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	var verdicts []authz.PolicyVerdict
	for _, cp := range c.policies {
		if !cp.match.matches(in) {
			continue
		}
		verdicts = append(verdicts, authz.PolicyVerdict{
			Effect:   cp.effect,
			Reason:   cp.reason,
			Source:   language,
			PolicyID: cp.id,
			Priority: cp.priority,
		})
	}
	return verdicts, nil
}

// matches reports whether in satisfies every present key in m — AND across
// match's five keys, exactly the package doc's "every key inside match is
// ANDed" rule. An absent key (nil) is not a constraint and is simply
// skipped; a non-nil match with every field nil (the {} case) never enters
// any of the five branches below and falls through to the final "return
// true," which is the documented "empty match matches everything" behaviour
// falling naturally out of this loop rather than needing a special case for
// it.
//
// Agent and delegation resolve their attribute's value with agentAttrValue /
// delegationAttrValue and discard the returned ok: a compiledPolicy's match
// only ever reaches here after parseDoc's validate has already confirmed the
// attr is a known one (see attrMatch.validate), so ok is always true for any
// policy this engine itself prepared. If that invariant were ever violated,
// ok false resolves to the empty string, which valueMatch.matches simply
// treats as a specific (and, in practice, non-matching) value — the same
// fail-closed direction as every other gap in this engine, never a panic and
// never an unintended match.
func (m *match) matches(in policy.EvaluationInput) bool {
	if m.Subject != nil && !m.Subject.matches(in.Principal.Attributes[m.Subject.Attr]) {
		return false
	}
	if m.Tool != nil && !m.Tool.matches(in.Action.Tool) {
		return false
	}
	if m.DerivedTier != nil && !m.DerivedTier.matches(in.DerivedTier) {
		return false
	}
	if m.Agent != nil {
		value, _ := agentAttrValue(in.Agent, m.Agent.Attr)
		if !m.Agent.matches(value) {
			return false
		}
	}
	if m.Delegation != nil {
		value, _ := delegationAttrValue(in.Delegation, m.Delegation.Attr)
		if !m.Delegation.matches(value) {
			return false
		}
	}
	return true
}
