// Package jsonpolicy implements policy.PolicyEngine using a small, fixed
// JSON schema — a house DSL for tenants who want auditability over
// expressiveness, unlike Cedar and Rego's general-purpose expression
// languages. The schema is not this package's to extend: task-4-brief.md
// defines it completely, and every type in schema.go is a literal
// transcription of that document, not an approximation of it.
//
// # The schema
//
//	{
//	  "effect": "allow" | "deny",
//	  "match": {
//	    "subject":      {"attr": "department", "equals": "finance"},
//	    "tool":         {"in": ["Read", "Grep"]},
//	    "derived_tier": {"at_most": 2},
//	    "agent":        {"attr": "trust_tier", "equals": "Verified"},
//	    "delegation":   {"attr": "purpose", "equals": "quarterly-close"}
//	  }
//	}
//
// Every key inside match is ANDed; an absent key is not a constraint, and an
// empty match object matches everything. match itself being absent is
// rejected by Validate rather than treated as match-all: a rule that matches
// everything must say so in its own text, because "I meant to match
// everything" and "I forgot the match block" are one JSON key apart, and
// only one of them is a working rule rather than a silent outage. This is
// the same silent-dead-rule failure class Task 3 found in Rego (a typo'd
// package declaration that validated cleanly and then never fired), applied
// one layer up, at authoring time instead of compile time.
//
// The three operators are equals (exact string), in (membership), and
// at_most (integer ceiling, valid only under derived_tier — the only tier
// dimension match exposes). No wildcards, no regex, no ranges, no type
// coercion: every one of those is a place a widening can hide, which is
// exactly what this engine exists to close off. Unknown keys — a typo'd
// operator, a typo'd match key, a typo'd top-level field, at any nesting
// depth — fail Validate; see parseDoc.
//
// Two operator shapes are rejected even though they are structurally
// well-formed JSON, because Validate accepting them would let a rule read as
// working when it is not: an empty in list ("in": []) can never match any
// value, the same failure class as a missing match block (see
// valueMatch.validate). at_most outside models.ActionTier's own valid range
// is rejected for two related but distinct reasons depending on direction
// (see tierMatch.validate): negative is the identical "can never match"
// defect an empty in list has (no real tier is negative); above the highest
// tier is not vacuous — it matches every tier there is, exactly as if
// derived_tier had been omitted from match entirely — but a tenant who
// wrote an explicit ceiling almost certainly meant it to constrain
// something, and a schema that lets "no real ceiling" be spelled two
// different ways (omit the key, or write a number large enough to be a
// no-op) works against the same auditability this engine exists for.
//
// # Compile once, evaluate many
//
// Prepare parses and validates every StoredPolicy's text exactly once,
// through parseDoc, into a *match tree compiledPolicy carries and Evaluate
// only ever walks. parseDoc is the single function in this package
// permitted to decode JSON: spec defect D5 was an engine re-parsing policy
// text inside Evaluate, once per policy per decision, instead of once per
// policy inside Prepare, and TestDecodeOnlyCalledFromParseDoc
// (engine_test.go) guards that structurally — see that test's own doc
// comment for why only a structural check, not a behavioural one, can catch
// this class of regression.
//
// # The input mapping, and where it deliberately narrows from Cedar and Rego
//
// match's five keys read the same EvaluationInput dimensions Cedar and Rego
// do, under the same names (trust_tier, purpose, derived_tier), so a
// Y3-style rule expresses the same intent in all three languages. Two
// deliberate narrowings, both because this schema has no general
// attribute-path expression — attr names exactly one fixed field, never an
// arbitrary path:
//
//   - subject.attr indexes Principal.Attributes directly, with no allow-list
//     to check it against: Attributes is tenant-supplied free-form data (see
//     EvaluationInput's own doc comment), so any string is a legal key. A
//     typo'd attr name here fails in only the safe direction — the
//     constraint simply never matches — the same way an unrecognized Cedar
//     attribute or Rego input path does.
//   - agent.attr and delegation.attr are each checked against a small,
//     closed set instead (agentAttrValue, delegationAttrValue in schema.go):
//     AgentInfo and DelegationContext are fixed Go structs, so — unlike
//     subject — every legal name is enumerable up front, and a name outside
//     that set can only be a typo. Rejecting it at Validate is this engine's
//     own version of the defense Task 3 added for Rego's package
//     declaration: a rule that would otherwise validate cleanly and then
//     never fire. The sets are deliberately narrower than Cedar's and
//     Rego's full context (which also expose enabled, suspended,
//     allowed_tools, id, depth, max_action_tier, classification_caps):
//     those are general-purpose expression languages where exposing one
//     more field costs nothing, but every field this schema exposes needs a
//     real equals/in-comparable string representation and a named test, so
//     only trust_tier and purpose — the two names the brief's own schema
//     shows — are wired up. Extend agentAttrValue or delegationAttrValue
//     when a concrete rule needs another named attribute, rather than
//     guessing which ones matter now — the same discipline this package
//     applies to every dimension it does not yet expose.
//
// # The narrowing invariant
//
// Same as Cedar and Rego: a policy verdict can never widen anything.
// authz.PolicyVerdict carries only Effect, Reason, Source, PolicyID, and
// Priority — no field through which a verdict could raise a tier, add a
// tool, or loosen a cap — and Priority is recorded for provenance only (spec
// Y7): nothing in this package sorts, filters, or short-circuits evaluation
// by it. Evaluate returns every policy that matched, independently;
// authz.FoldVerdicts, not this package, applies deny-overrides across the
// result.
package jsonpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

const (
	// language is the value stored in policies.language for this engine —
	// and, via NewMulti's own construction-time panic, the only Registry key
	// this Engine may ever be registered under (see policy.Registry's doc
	// comment).
	language = "json"

	effectAllow = "allow"
	effectDeny  = "deny"
)

// Engine implements policy.PolicyEngine for the JSON schema. It holds no
// state: every compiledPolicy a Prepare call produces is everything a
// decision needs, and those live in the returned compiledSet.
type Engine struct{}

var _ policy.PolicyEngine = Engine{}

// New returns a JSON policy.PolicyEngine.
func New() Engine { return Engine{} }

// Language is the value stored in policies.language for JSON policies.
func (Engine) Language() string { return language }

// Prepare parses and validates every policy's text exactly once via
// parseDoc, keyed by StoredPolicy.ID so a validation failure — and later,
// every verdict Evaluate returns — can be attributed back to the specific
// policy that produced it. A nil or empty policies prepares successfully to
// a set that evaluates to zero verdicts. Preparation stops at the first
// policy that fails: the error names only that policy, never a well-formed
// neighbor that happened to share the same Prepare call (see policytest's
// own "does not blame the neighbor" property).
//
// The produced verdict's effect comes from the policy text's own "effect"
// key (via effectOf) — the same choice Cedar and Rego make for their own
// languages' native effect syntax (permit/forbid, allow/deny rules). It is
// the only source: StoredPolicy carries no separate effect field to trust
// instead (Phase 4a Task 4 removed it — no engine ever read it, and a stored
// value could actively disagree with the text sitting right next to it).
func (Engine) Prepare(_ context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	compiled := make([]compiledPolicy, 0, len(policies))
	for _, sp := range policies {
		d, err := parseDoc(sp.Text)
		if err != nil {
			return nil, fmt.Errorf("json: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		compiled = append(compiled, compiledPolicy{
			id:       sp.ID,
			priority: sp.Priority,
			effect:   effectOf(d.Effect),
			reason:   fmt.Sprintf("json: policy %s (%s) matched", sp.ID, sp.Name),
			match:    d.Match,
		})
	}
	return compiledSet{policies: compiled}, nil
}

// Validate checks policy text without persisting or evaluating it, for the
// PAP's authoring path: a bad policy — including one that would silently
// never fire, such as a missing match block or an unknown attr — is refused
// at write time rather than discovered at decision time. It parses text
// through the same parseDoc Prepare uses, so anything Validate accepts,
// Prepare accepts too.
func (Engine) Validate(_ context.Context, text string) error {
	if _, err := parseDoc(text); err != nil {
		return fmt.Errorf("json: validate: %w", err)
	}
	return nil
}

// effectOf converts a parseDoc-validated effect string into authz.Effect.
// parseDoc has already rejected every value except effectAllow and
// effectDeny by the time Prepare calls this, so the fallthrough to
// EffectDeny below is unreachable in practice for this package's own
// callers — but EffectDeny is also authz.Effect's zero value, deliberately
// (see authz.Effect's own doc comment: "a leg that is never evaluated must
// deny rather than silently permit"), so even a hypothetical future caller
// with unvalidated input fails in the safe direction rather than panicking
// or defaulting to allow.
func effectOf(s string) authz.Effect {
	if s == effectAllow {
		return authz.EffectAllow
	}
	return authz.EffectDeny
}

// parseDoc is the single choke point every policy text passes through,
// called from both Prepare and Validate — the same shape rego's checkPackage
// takes, and for the same reason: anything Validate accepts must also
// prepare, and there must be exactly one place that requirement could drift
// out of sync with itself. json.NewDecoder(...).DisallowUnknownFields() is
// what makes "unknown keys fail Validate" hold at every nesting level — the
// top-level object, match, and every constraint inside it — in one decode
// call, rather than a hand-written key-walk repeated per level.
func parseDoc(text string) (policyDoc, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	var d policyDoc
	if err := dec.Decode(&d); err != nil {
		return policyDoc{}, fmt.Errorf("parse: %w", err)
	}
	// A second Decode call that succeeds (anything but io.EOF) means text
	// held more than one JSON value: trailing content after the policy
	// object. cedar's parseOne rejects the analogous case (text that parses
	// to more than one Cedar policy statement) for the same reason — a
	// StoredPolicy is one policy, and text with no single attributable
	// meaning is invalid, not "the first value, ignoring the rest."
	if err := dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return policyDoc{}, errors.New("parse: unexpected content after the policy JSON value")
	}

	if d.Effect != effectAllow && d.Effect != effectDeny {
		return policyDoc{}, fmt.Errorf("effect must be %q or %q, got %q", effectAllow, effectDeny, d.Effect)
	}
	if d.Match == nil {
		return policyDoc{}, errors.New("match is required (an empty match object {} matches everything; a missing match key does not — see the package doc)")
	}
	if err := d.Match.validate(); err != nil {
		return policyDoc{}, fmt.Errorf("match: %w", err)
	}
	return d, nil
}
