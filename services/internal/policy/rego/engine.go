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
// entity system: everything Cedar models as an entity (principal, resource,
// action) is just another input field here — a Cedar rule reads
// `action == Action::"Bash"`, a Rego rule reads `input.action.tool ==
// "Bash"`.
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
// # Absence is undefined, not false — and != silently inherits that
//
// Every OPA comparison builtin (==, !=, <, <=, >, >=) needs BOTH operands
// defined to produce a value at all. stringMapOrEmpty and stringsOrEmpty
// (input.go) already guarantee the three tenant-open fields —
// principal.attributes, resource, delegation.classification_caps — are
// never Rego/JSON null, but neither can guarantee any particular KEY inside
// one of them is present, because those maps are free-form and
// tenant-supplied with no fixed key set to enumerate (see schema.go's "why
// the three tenant-supplied maps stay undeclared"). Indexing a missing key
// is itself undefined, and a comparison built on an undefined operand is
// undefined too — not false, not an error, simply no value. A rule body is
// an implicit AND of every expression in it, and one undefined expression
// makes the whole body undefined: the rule produces no value for this
// input, exactly as if none of its conditions had ever been written.
// decision (evaluate.go) cannot tell that apart from "this policy
// legitimately did not match," and neither can Eval itself — a missing key
// is not an OPA error (the same "empty result proves nothing" trap
// checkPackage's own doc comment describes for a different cause).
//
// This bites hardest on deny rules built around !=, because the author's
// intent is almost always "anything other than the expected value should be
// denied — including no value at all":
//
//	INTENT: deny unless principal.mfa is exactly "true". No mfa attribute present.
//
//	deny if { input.principal.attributes.mfa != "true" }         undefined -> rule does not fire
//	deny if { not input.principal.attributes.mfa == "true" }     not(undefined) is true -> denies
//
// The second spelling works because Rego's `not` treats an undefined inner
// expression as a hit: `not X` holds whenever X is false OR undefined, and
// fails only when X is true — exactly the "absence counts as not-equal"
// semantics a deny-unless rule needs, and != does not have: it is an
// ordinary two-argument builtin, and an ordinary builtin given an undefined
// argument simply does not run. With mfa actually present but wrong
// ("false" rather than "true"), both spellings deny identically — the
// divergence above is specifically about absence, not a general difference
// in what the two spellings mean (see
// TestEvaluate_NotEqualsOnAbsentAttributeFailsOpen, evaluate_test.go, which
// pins both the failure and the fix, plus that control, against the real
// engine).
//
// One Rego policy failing to fire is not, on its own, a fail-open PDP:
// authz.FoldVerdicts is deny-overrides, so this only matters when nothing
// else in the tenant's principal leg denies the same request — but a
// deny-unless rule is usually written precisely because nothing else does,
// which makes this exactly the shape of policy most likely to be the only
// thing standing between a request and an unconditional allow.
//
// No static check catches this: it was investigated and rejected, not
// merely left undone — see schema.go's "why there is no absence check" for
// the reasoning. Prefer `not X == Y` (or `not X in [...]` for membership)
// over `X != Y` in any deny rule that touches principal.attributes,
// resource, or delegation.classification_caps — the three paths where a key
// can be legitimately absent at all; every other input path is exhaustively
// populated by buildInput (input.go) and never has this problem.
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

	"github.com/open-policy-agent/opa/v1/ast"
	regolib "github.com/open-policy-agent/opa/v1/rego"

	"github.com/stratiumdata/stratium/internal/policy"
)

// queryPath is the fixed Rego query every policy is compiled and evaluated
// against — see the package doc's "query convention" section for why it
// targets the whole package document rather than the two rules separately.
const queryPath = "data.stratium.policy"

// language is the value stored in policies.language for this engine, and
// evaluate.go's own Source for every verdict it produces — one package-level
// const referenced by both, the same shape jsonpolicy and xacml already use,
// so the two can never drift apart the way two separately hardcoded "rego"
// literals could (see cedar/engine.go's own const of the same name and doc
// comment for the full reasoning, which applies identically here).
const language = "rego"

// Engine implements policy.PolicyEngine for Rego. It holds no state: the
// per-policy rego.PreparedEvalQuery values a Prepare call produces are
// everything a decision needs, and they live in the returned compiledSet.
type Engine struct{}

var _ policy.PolicyEngine = Engine{}

// New returns a Rego policy.PolicyEngine.
func New() Engine { return Engine{} }

// Language is the value stored in policies.language for Rego policies.
func (Engine) Language() string { return language }

// Prepare compiles every policy's text into its own isolated
// rego.PreparedEvalQuery, keyed by StoredPolicy.ID so a compile failure —
// and later, every verdict Evaluate returns — can be attributed back to the
// specific policy that produced it. A nil or empty policies prepares
// successfully to a set that evaluates to zero verdicts. Compilation stops
// at the first policy that fails: the error names only that policy, never a
// well-formed neighbor that happened to share the same Prepare call (see
// policytest's own "does not blame the neighbor" property).
//
// checkPackage runs before PrepareForEval, not after: a module declaring
// any package compiles cleanly (data.stratium.policy simply never resolves
// to anything for a differently-packaged module — see checkPackage's own
// doc comment), so nothing about a successful PrepareForEval call would
// ever have caught this on its own. checkComparisonTypes runs right after
// checkPackage for the identical reason, one layer up: PrepareForEval
// accepts input.agent.trust_tier > 2 as cleanly as any other well-formed
// comparison — see schema.go's package comment for why that is Rego's
// documented total-order behavior, not a bug, and why a schema attached to
// PrepareForEval alone cannot catch it either. regolib.Schemas(inputSchemaSet)
// is still attached below, for the mismatched-== forms it does catch (also
// schema.go).
func (Engine) Prepare(ctx context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	compiled := make(map[string]compiledPolicy, len(policies))
	for _, sp := range policies {
		if err := checkPackage(sp.ID, sp.Text); err != nil {
			return nil, fmt.Errorf("rego: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		if err := checkComparisonTypes(sp.ID, sp.Text); err != nil {
			return nil, fmt.Errorf("rego: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		pq, err := regolib.New(
			regolib.Query(queryPath),
			regolib.Module(sp.ID, sp.Text),
			regolib.Schemas(inputSchemaSet),
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
// same query, same syntax requirements, same checkPackage and
// checkComparisonTypes calls, same schema — so anything Validate accepts,
// Prepare accepts too, and a tenant who mistypes their package declaration,
// or ports a Cedar ordinal comparison onto the wrong Rego field, is told at
// authoring time rather than shipping a rule that is dead on arrival, or
// worse, unconditionally true.
func (Engine) Validate(ctx context.Context, text string) error {
	if err := checkPackage("validate", text); err != nil {
		return fmt.Errorf("rego: validate: %w", err)
	}
	if err := checkComparisonTypes("validate", text); err != nil {
		return fmt.Errorf("rego: validate: %w", err)
	}
	if _, err := regolib.New(
		regolib.Query(queryPath),
		regolib.Module("validate", text),
		regolib.Schemas(inputSchemaSet),
	).PrepareForEval(ctx); err != nil {
		return fmt.Errorf("rego: validate: %w", err)
	}
	return nil
}

// checkPackage parses text with ast.ParseModule and confirms its declared
// package is exactly stratium.policy (queryPath, reused here rather than a
// second literal, so the query and the requirement it depends on cannot
// drift apart). This is the fix for a review finding: rego.New(...).
// PrepareForEval accepts a module declaring any package without complaint —
// queryPath simply never resolves to anything for a differently-packaged
// module, and decision (evaluate.go) cannot tell that apart from "this
// policy's rules are legitimately undefined for this input" — so a typo'd
// package (`stratium.polic`, `stratium.oops`) used to compile cleanly and
// stay silently dead at every later decision: no error at write time, no
// verdict distinguishing it from a rule that correctly never fires, ever.
// That is spec defect D10's failure mode — a policy that cannot be
// evaluated must deny, never be silently ignored — reappearing one layer
// below where D10 itself was closed, and multi.go's orphanVerdicts cannot
// help here: the rego engine *is* registered and Prepare *does* succeed.
//
// A runtime probe (compiling the text and evaluating it once against a
// generic input, checking for an empty result) was considered and
// rejected: this package's own WellFormed fixture — `allow if {
// input.principal.subject == "nobody-in-particular" }` — also yields an
// empty result against a generic input, because it legitimately does not
// match. An empty result cannot distinguish "wrong package" from
// "correctly did not match," so only a static check of the declared
// package, independent of any input, is reliable.
func checkPackage(id, text string) error {
	mod, err := ast.ParseModule(id, text)
	if err != nil {
		return err
	}
	if got := mod.Package.Path.String(); got != queryPath {
		return fmt.Errorf("policy declares package %s, want %s (every policy's module must declare `package stratium.policy`)", got, queryPath)
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
