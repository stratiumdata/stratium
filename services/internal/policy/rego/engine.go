// Package rego implements policy.PolicyEngine using the Rego policy language
// via OPA (github.com/open-policy-agent/opa v1.19.0 — the module's current
// release as of this task; the predecessor,
// ~/Development/stratium/go/pkg/policy_engine/opa_engine.go, pinned v1.0.0).
//
// This package imports github.com/open-policy-agent/opa/v1/rego, not the
// unversioned github.com/open-policy-agent/opa/rego the predecessor used.
// OPA v1.0 split its Go API in two: the unversioned path is now documented
// as "intended for older projects transitioning from OPA v0.x ... its use is
// not recommended," kept only so pre-1.0 callers compile unchanged, and for
// that reason it silently defaults to the old v0 Rego syntax. The v1 path is
// the actively maintained one and defaults to Rego v1 syntax — rule bodies
// require `if` — which is the syntax every fixture and doc example below
// uses, and the only syntax this package's Prepare accepts.
//
// # Compile once, evaluate many
//
// Prepare compiles every StoredPolicy independently: one
// rego.New(...).PrepareForEval(ctx) call per policy, each with its own
// module named by StoredPolicy.ID, producing its own rego.PreparedEvalQuery
// stored in the returned compiledSet. That query is reused, unrecompiled, by
// every later Evaluate call (see evaluate.go) — the same compile-once
// property policy.PolicyEngine's own doc comment requires and spec defect D5
// named: the predecessor called PrepareForEval inside Evaluate, once per
// policy per decision.
//
// Compiling each policy into its own isolated program, rather than loading
// every policy as a module in one shared compilation, is deliberate and for
// the same reason Cedar evaluates one policy at a time against a singleton
// set instead of its whole PolicySet (see cedar/evaluate.go's doc comment —
// the same reasoning binds this package). Rego modules that share a package
// merge into one namespace: two policies each defining `allow` under
// `package stratium.policy` in a single shared compilation would have OPA
// itself combine them, because a rule with multiple bodies is a logical OR
// across all of them. That is exactly the combining this task's engines are
// forbidden from doing — see "no engine implements combining" below.
// Compiling each policy in its own program keeps that decision out of this
// engine's hands entirely: nothing here ever sees more than one policy's
// text at compile time.
//
// # The query convention
//
// Every policy is a module whose package must be `stratium.policy`. Prepare
// queries `data.stratium.policy` — the package's whole document — rather
// than data.stratium.policy.allow and data.stratium.policy.deny separately.
// OPA's document semantics already omit a rule that produced no value for
// the given input from its enclosing package's object (an allow rule with an
// unmet condition and no `default` is simply absent from the resulting
// object, not present as false), so reading the "allow" and "deny" keys off
// one Eval call's result is behaviourally identical to querying each rule
// separately — at half the PreparedEvalQuery count and half the per-decision
// Eval calls. A key that is missing, or present but not literally `true` (a
// tenant's own `default allow := false` makes a non-matching policy's
// "allow" key present and false, not absent — both are treated identically:
// only literal true signals a match), means that rule did not fire. A policy
// whose module defines neither rule therefore yields no verdict rather than
// an error; see decision in evaluate.go.
//
// A policy defining both allow and deny as true resolves to a deny verdict,
// decided here, in the engine — the one exception the task brief grants to
// "no engine implements combining": this is a contradiction produced by a
// single policy's own two rules, not by two different policies, so
// authz.FoldVerdicts — which only ever sees verdicts engines have already
// resolved — is not positioned to see it at all. Once resolved to one
// verdict, the fold treats it exactly like any other single-policy deny.
//
// # The input mapping
//
// EvaluationInput becomes the plain map[string]any OPA evaluates policy text
// against as `input` (see input.go). Naming mirrors Cedar's context
// attributes exactly — trust_tier, max_action_tier, classification_caps, and
// so on — so the same rule reads the same way in both languages. Two
// deliberate departures from Cedar's mapping, both because Rego has no
// entity system: everything Cedar models as an entity (principal, resource)
// is just another input field here.
//
//   - input.principal is {subject, attributes}, not a flat object the way
//     Cedar's principal entity attributes are (a Cedar policy reads
//     `principal.dept` directly). Cedar can flatten because Subject is the
//     entity's identity, structurally separate from its Attributes record —
//     nothing a Cedar policy writes as principal.<attr> can ever collide
//     with how the entity is identified. Rego has no such separation:
//     Subject and Attributes are two fields of the same
//     authz.Principal struct, and flattening them into one object risks a
//     tenant-supplied attribute literally named "subject" silently
//     overwriting the real one. Nesting under "attributes" costs one extra
//     path segment and removes the collision entirely.
//   - input.derived_tier is a JSON number — the tier's ordinal int — not its
//     String() form, matching Cedar's own Long (not String) mapping for this
//     one field, for the same reason Cedar's package doc gives: the
//     delegation-creation clamp's tier walk-down needs a real >= comparison,
//     and ActionTier's ordinal order is load-bearing (see that type's doc
//     comment) while string comparison — in both Cedar and Rego — is
//     lexicographic and disagrees with it ("EXTERNAL_COMMS" <
//     "INTERNAL_MODIFY" as strings, backwards from the real ranking).
//     delegation.max_action_tier stays a string in both languages, matching
//     Cedar's own choice there: nothing in scope needs an ordinal comparison
//     against the ceiling itself, only against derived_tier.
//
// EvaluationInput.Environment is not mapped, for the same reason Cedar
// leaves it unmapped: no rule in scope needs it. Extend buildInput
// (input.go) when a rule actually needs it, rather than guessing its shape
// now.
//
// # The narrowing invariant
//
// Same as Cedar: a policy verdict can never widen anything.
// authz.PolicyVerdict carries only Effect, Reason, Source, PolicyID, and
// Priority — no field through which a verdict could raise a tier, add a
// tool, or loosen a cap. Evaluate returns every policy that matched,
// independently; authz.FoldVerdicts, not this package, applies
// deny-overrides across the result.
package rego

import (
	"context"
	"fmt"

	regolib "github.com/open-policy-agent/opa/v1/rego"

	"stratium/internal/policy"
)

// queryPath is the fixed Rego query every policy is compiled and evaluated
// against — see the package doc's "query convention" section for why it
// targets the whole package document rather than the two rules separately.
const queryPath = "data.stratium.policy"

// Engine implements policy.PolicyEngine for Rego. It holds no state: the
// per-policy rego.PreparedEvalQuery values a Prepare call produces are
// everything a decision needs, and they live in the returned compiledSet.
type Engine struct{}

var _ policy.PolicyEngine = Engine{}

// New returns a Rego policy.PolicyEngine.
func New() Engine { return Engine{} }

// Language is the value stored in policies.language for Rego policies.
func (Engine) Language() string { return "rego" }

// Prepare compiles every policy's text into its own isolated
// rego.PreparedEvalQuery, keyed by StoredPolicy.ID so a compile failure —
// and later, every verdict Evaluate returns — can be attributed back to the
// specific policy that produced it. A nil or empty policies prepares
// successfully to a set that evaluates to zero verdicts. Compilation stops
// at the first policy that fails: the error names only that policy, never a
// well-formed neighbor that happened to share the same Prepare call (see
// policytest's own "does not blame the neighbor" property).
func (Engine) Prepare(ctx context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	compiled := make(map[string]compiledPolicy, len(policies))
	for _, sp := range policies {
		pq, err := regolib.New(
			regolib.Query(queryPath),
			regolib.Module(sp.ID, sp.Text),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, fmt.Errorf("rego: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		compiled[sp.ID] = compiledPolicy{query: pq, name: sp.Name, priority: sp.Priority}
	}
	return compiledSet{policies: compiled}, nil
}

// Validate checks policy text without persisting or evaluating it, for the
// PAP's authoring path: a bad policy is refused at write time rather than
// discovered at decision time. It compiles text the same way Prepare does —
// same query, same syntax requirements — so anything Validate accepts,
// Prepare accepts too.
func (Engine) Validate(ctx context.Context, text string) error {
	if _, err := regolib.New(
		regolib.Query(queryPath),
		regolib.Module("validate", text),
	).PrepareForEval(ctx); err != nil {
		return fmt.Errorf("rego: validate: %w", err)
	}
	return nil
}

// compiledPolicy is one policy's compiled query plus the per-policy metadata
// (name, priority) a rego.PreparedEvalQuery does not itself carry. Unlike
// Cedar — whose cedar.PolicySet is a third-party type with no room to attach
// metadata, forcing a second, parallel map kept in sync by StoredPolicy.ID —
// this package owns compiledSet's storage outright, so the query and its
// metadata live in one struct, in one map, with no second collection whose
// keys could drift out of sync with the first.
type compiledPolicy struct {
	query    regolib.PreparedEvalQuery
	name     string
	priority int
}
