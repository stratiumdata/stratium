package jsonpolicy

import (
	"errors"
	"fmt"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
)

// policyDoc is the on-the-wire shape of one JSON policy's text — a literal
// transcription of task-4-brief.md's schema. See the package doc (engine.go)
// for the schema in full and the reasoning behind each choice below.
type policyDoc struct {
	Effect string `json:"effect"`
	Match  *match `json:"match"`
}

// match is the match object. Every field is a pointer so parseDoc can tell
// "key absent" (nil) apart from "key present" — the distinction the package
// doc's "an absent key is not a constraint" and "an empty match object
// matches everything" rules both depend on: a *match that is non-nil with
// every field nil is the empty-object case, and matches (evaluate.go) falls
// through all five checks and returns true for exactly that reason, with no
// separate case needed for it.
type match struct {
	Subject     *attrMatch  `json:"subject"`
	Tool        *valueMatch `json:"tool"`
	DerivedTier *tierMatch  `json:"derived_tier"`
	Agent       *attrMatch  `json:"agent"`
	Delegation  *attrMatch  `json:"delegation"`
}

// validate checks every present key in m. Each key is independent, so
// validate simply checks each in turn and returns the first error found,
// prefixed with which key it came from.
func (m *match) validate() error {
	if m.Subject != nil {
		// subject.attr indexes Principal.Attributes, tenant-supplied
		// free-form data with no fixed field set (see the package doc's
		// mapping section), so there is no closed set to check it against —
		// pass a nil known func, unlike agent and delegation below.
		if err := m.Subject.validate(nil); err != nil {
			return fmt.Errorf("subject: %w", err)
		}
	}
	if m.Tool != nil {
		if err := m.Tool.validate(); err != nil {
			return fmt.Errorf("tool: %w", err)
		}
	}
	if m.DerivedTier != nil {
		if err := m.DerivedTier.validate(); err != nil {
			return fmt.Errorf("derived_tier: %w", err)
		}
	}
	if m.Agent != nil {
		if err := m.Agent.validate(agentAttrKnown); err != nil {
			return fmt.Errorf("agent: %w", err)
		}
	}
	if m.Delegation != nil {
		if err := m.Delegation.validate(delegationAttrKnown); err != nil {
			return fmt.Errorf("delegation: %w", err)
		}
	}
	return nil
}

// valueMatch is the {"equals": ...} / {"in": [...]} shape shared by every
// constraint in this schema. Exactly one of Equals or In must be set —
// checked by validate, not by the JSON shape alone, since encoding/json has
// no "exactly one of these fields" construct of its own.
type valueMatch struct {
	Equals *string  `json:"equals"`
	In     []string `json:"in"`
}

func (v valueMatch) validate() error {
	switch {
	case v.Equals != nil && v.In != nil:
		return errors.New("equals and in are mutually exclusive; exactly one operator is required")
	case v.Equals == nil && v.In == nil:
		return errors.New("exactly one operator (equals or in) is required")
	}
	return nil
}

// matches reports whether value satisfies v — the comparison every
// attr-based key (subject, agent, delegation) and tool all reduce to once
// the field under test has been resolved to a string.
func (v valueMatch) matches(value string) bool {
	if v.Equals != nil {
		return value == *v.Equals
	}
	for _, want := range v.In {
		if value == want {
			return true
		}
	}
	return false
}

// attrMatch is subject/agent/delegation's shape: a named attribute plus a
// valueMatch operator. tool has no attr of its own — Action.Tool is a single
// string field, not a bag of named attributes — so match.Tool embeds
// valueMatch directly instead of going through attrMatch.
type attrMatch struct {
	Attr string `json:"attr"`
	valueMatch
}

// validate checks a is well-formed. known is nil for subject, which has no
// closed attribute set (see match.validate); for agent and delegation it is
// agentAttrKnown / delegationAttrKnown — the same functions matches
// (evaluate.go) uses to resolve a real value — so the allow-list enforced
// here and the lookup used there are one definition, not two lists a future
// edit could let drift apart.
func (a attrMatch) validate(known func(string) bool) error {
	if a.Attr == "" {
		return errors.New("attr is required")
	}
	if known != nil && !known(a.Attr) {
		return fmt.Errorf("unknown attr %q", a.Attr)
	}
	return a.valueMatch.validate()
}

// tierMatch is derived_tier's shape: at_most only. equals and in are
// deliberately not offered here — the brief scopes at_most to "tiers only,"
// derived_tier is the only tier dimension match exposes, and a ceiling is
// the only operation this key needs; adding equals/in here would be
// improvising past the schema the brief defines.
type tierMatch struct {
	AtMost *int `json:"at_most"`
}

func (t tierMatch) validate() error {
	if t.AtMost == nil {
		return errors.New("at_most is required")
	}
	return nil
}

// matches applies the ceiling as a real integer comparison — tier <=
// AtMost — never a comparison of their decimal string forms:
// models.ActionTier's ordinal order is load-bearing (see that type's own
// doc comment), and string comparison is lexicographic, which disagrees
// with numeric order for any pair spanning a digit-count boundary ("10" <
// "9" as strings). ActionTier's five members (0-4) never reach two digits on
// their own, so a lexicographic mutant here would still agree with the
// correct comparison for every real ActionTier value; TestEvaluate_
// DerivedTierAtMost's "ceiling above the tier lattice" subtest
// (evaluate_test.go) deliberately uses an AtMost value the schema permits
// but no ActionTier reaches, to force the two comparisons apart rather than
// assume in-range values alone would ever expose the bug.
func (t tierMatch) matches(tier models.ActionTier) bool {
	return int(tier) <= *t.AtMost
}

// agentAttrKnown reports whether attr is a name agentAttrValue resolves —
// attrMatch.validate's known func for the agent dimension.
func agentAttrKnown(attr string) bool {
	_, ok := agentAttrValue(authz.AgentInfo{}, attr)
	return ok
}

// agentAttrValue resolves attr against a. This switch is the single source
// of truth for agent.attr's legal name set: agentAttrKnown calls it (with a
// zero AgentInfo{}, discarding the value) to reject an unknown attr at
// authoring time, and matches (evaluate.go) calls it again at decision time
// to read the real value. One definition, not an allow-list and a lookup
// kept in sync by hand.
//
// Only trust_tier is wired up — see the package doc's mapping section for
// why this is narrower than Cedar's and Rego's full agent context.
func agentAttrValue(a authz.AgentInfo, attr string) (value string, ok bool) {
	switch attr {
	case "trust_tier":
		return a.TrustTier.String(), true
	default:
		return "", false
	}
}

// delegationAttrKnown is agentAttrKnown's counterpart for delegation.attr.
func delegationAttrKnown(attr string) bool {
	_, ok := delegationAttrValue(policy.DelegationContext{}, attr)
	return ok
}

// delegationAttrValue is agentAttrValue's counterpart for delegation.attr.
// Only purpose is wired up — see the package doc's mapping section.
func delegationAttrValue(d policy.DelegationContext, attr string) (value string, ok bool) {
	switch attr {
	case "purpose":
		return d.Purpose, true
	default:
		return "", false
	}
}
