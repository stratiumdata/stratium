// Package cedar implements policy.PolicyEngine using the Cedar policy
// language (github.com/cedar-policy/cedar-go, v1.8.0). It is Stratium's
// first policy engine: Cedar is native Go with no CGO, it is typed and
// statically analysable, and its template model maps closely onto scoped
// delegation — none of which this package exercises yet (templates are a
// later task), but all of which are why Cedar goes first.
//
// # Compile once, evaluate many
//
// Prepare parses every StoredPolicy's text into one cedar.PolicySet, keyed
// by StoredPolicy.ID. A malformed policy fails Prepare with an error naming
// both that policy's ID and its name — an operator with fifty policies needs
// to know which one is broken, not that "a policy" is. The returned
// CompiledPolicySet holds only the parsed set and read-only per-policy
// metadata, so it is safe for concurrent Evaluate calls without locking.
//
// # The mapping
//
// Evaluate maps a policy.EvaluationInput onto a Cedar request:
//
//   - Principal and resource become entities. They are the two things a
//     Cedar scope clause (principal == User::"x", resource in Folder::"y")
//     can match against — the only reason Cedar has entities at all.
//   - The action becomes an action UID, identified by Action.Tool.
//   - Agent and delegation become context attributes, not entities. Cedar
//     entities exist to carry a hierarchy a policy's scope can walk with
//     `in` — group membership, parent-of relationships. Nothing here needs
//     that: spec Y3's example ("deny Unverified agents on financial tools")
//     is answered entirely by reading a flat attribute
//     (context.agent.trust_tier) inside a `when` clause. Modeling agent and
//     delegation as entities would mean inventing an entity hierarchy this
//     system uses nowhere else, on spec, for a need that does not exist yet.
//     A later engine should follow this same call or diverge from it
//     deliberately — not by drift. If a rule ever needs agents-as-groups
//     ("any agent in AgentGroup::trusted-crawlers"), that is the point to
//     revisit it.
//   - DerivedTier becomes a context attribute, context.derived_tier —
//     mapped as a Cedar Long, not a String like delegation.max_action_tier,
//     because a tier-ceiling policy needs a real >= comparison. ActionTier's
//     ordinal order is load-bearing (see that type's doc comment); Cedar
//     string comparison is lexicographic and disagrees with it
//     ("EXTERNAL_COMMS" < "INTERNAL_MODIFY" as strings — backwards from the
//     real ranking, where EXTERNAL_COMMS outranks INTERNAL_MODIFY). Added
//     for the delegation-creation clamp (Phase 2d Task 2): the clamp's tier
//     walk-down probes one tier at a time and has nothing to walk against
//     if a policy cannot tell which tier is being asked about.
//
// EvaluationInput.Environment is not yet mapped into the request: no rule in
// scope needs it. Extend buildRequest (request.go) when a rule actually
// needs it, rather than guessing its shape now.
//
// # The narrowing invariant
//
// A policy verdict can never widen anything. authz.PolicyVerdict carries
// only Effect, Reason, Source, PolicyID, and Priority — no field through
// which a verdict could raise a tier, add a tool, or loosen a cap — and
// Priority is recorded for provenance only (spec Y7): nothing in this
// package sorts, filters, or short-circuits evaluation by it. Evaluate
// returns every policy that matched, independently, in whatever order
// Cedar's own PolicySet iterates them; authz.FoldVerdicts, not this
// package, applies deny-overrides across the result.
package cedar

import (
	"context"
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"

	"stratium/internal/policy"
)

// Engine implements policy.PolicyEngine for Cedar. It holds no state: the
// cedar.PolicySet a Prepare call produces is everything a decision needs.
type Engine struct{}

var _ policy.PolicyEngine = Engine{}

// New returns a Cedar policy.PolicyEngine.
func New() Engine { return Engine{} }

// Language is the value stored in policies.language for Cedar policies.
func (Engine) Language() string { return "cedar" }

// Prepare parses every policy's text into one cedar.PolicySet, keyed by
// StoredPolicy.ID so a parse failure — and later, every verdict Evaluate
// returns — can be attributed back to the specific policy that produced it.
// A nil or empty policies prepares successfully to a set that evaluates to
// zero verdicts.
//
// checkDeadForms runs right after parseOne succeeds, not after — a policy
// that parses cleanly but can never fire (see deadform.go) must be rejected
// before it is ever added to the set, the same "authoring time, not
// decision time" placement rego's checkPackage uses.
func (Engine) Prepare(_ context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	set := cedarlib.NewPolicySet()
	meta := make(map[string]policyMeta, len(policies))
	for _, sp := range policies {
		parsed, err := parseOne(sp.ID, sp.Text)
		if err != nil {
			return nil, fmt.Errorf("cedar: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		if err := checkDeadForms(parsed); err != nil {
			return nil, fmt.Errorf("cedar: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		set.Add(cedarlib.PolicyID(sp.ID), parsed)
		meta[sp.ID] = policyMeta{name: sp.Name, priority: sp.Priority}
	}
	return compiledSet{policies: set, meta: meta}, nil
}

// Validate checks policy text without persisting or evaluating it, for the
// PAP's authoring path: a bad policy is refused at write time rather than
// discovered at decision time. It runs the same checkDeadForms check
// Prepare does, so anything Validate accepts, Prepare accepts too.
func (Engine) Validate(_ context.Context, text string) error {
	parsed, err := parseOne("validate", text)
	if err != nil {
		return fmt.Errorf("cedar: validate: %w", err)
	}
	if err := checkDeadForms(parsed); err != nil {
		return fmt.Errorf("cedar: validate: %w", err)
	}
	return nil
}

// parseOne parses text as exactly one Cedar policy statement. A Stratium
// StoredPolicy is one policy; text that parses to zero or several Cedar
// statements has nowhere to attribute a StoredPolicy.ID to and is treated as
// invalid, the same as a syntax error. name is used only for Position data
// in parse errors (see cedar.NewPolicyListFromBytes) — it is not read back
// as a policy identifier.
func parseOne(name, text string) (*cedarlib.Policy, error) {
	list, err := cedarlib.NewPolicyListFromBytes(name, []byte(text))
	if err != nil {
		return nil, err
	}
	if len(list) != 1 {
		return nil, fmt.Errorf("expected exactly one policy statement, found %d", len(list))
	}
	return list[0], nil
}

// policyMeta is what a StoredPolicy carries that a parsed *cedar.Policy does
// not: Cedar has no notion of a policy's display name or of Stratium's own
// Priority field. compiledSet keeps them alongside the parsed set, keyed by
// the same StoredPolicy.ID used as the Cedar PolicyID.
type policyMeta struct {
	name     string
	priority int
}
