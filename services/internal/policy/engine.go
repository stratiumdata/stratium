package policy

import (
	"context"

	"github.com/stratiumdata/stratium/internal/authz"
)

// PolicyEngine compiles policy text. Compilation is separate from evaluation
// because spec defect D5 was engines recompiling on every request: the
// predecessor called rego.New(...) + PrepareForEval(ctx) and Cedar's
// NewPolicySetFromBytes(...) inside Evaluate, once per policy per decision —
// and the PDP looped the whole policy set, so a single decision paid for M
// compilations, M being the policy count. PrepareForEval is precisely the API
// OPA exposes so a caller compiles once and reuses the result; calling it per
// request discards the entire optimisation it exists for. Prepare is that
// compile-once step. Evaluate, on the CompiledPolicySet Prepare returns, is
// the per-decision step that reuses it — cheaply, and as many times as
// decisions arrive.
//
// This interface only establishes the shape. No implementation lives here:
// Cedar is a later task, and so is any cache of prepared sets (a cache is a
// measurement question, not a shape question — see the plan).
type PolicyEngine interface {
	// Language is the value stored in policies.language.
	Language() string

	// Prepare compiles a tenant's policy set once. The returned value is safe
	// for concurrent use by many evaluations. A nil or empty policies prepares
	// successfully to a set that evaluates to zero verdicts — no policies is
	// not an error, it is a policy engine with nothing to say; default-deny
	// downstream is what turns silence into a denial.
	Prepare(ctx context.Context, policies []StoredPolicy) (CompiledPolicySet, error)

	// Validate checks policy text without persisting or evaluating it, for the
	// PAP's authoring path: a bad policy is refused at write time rather than
	// discovered at decision time.
	Validate(ctx context.Context, text string) error
}

// CompiledPolicySet evaluates a prepared set. Implementations must be
// goroutine-safe: one compiled set serves every concurrent decision for a
// tenant. That property is what a future cache of prepared sets would rely
// on (Task 5 measures whether one is warranted; this package does not add
// one).
type CompiledPolicySet interface {
	Evaluate(ctx context.Context, in EvaluationInput) ([]authz.PolicyVerdict, error)
}

// StoredPolicy is one row of the policies table.
//
// policies.effect is deliberately not represented here: no engine reads it
// (all four derive effect from the policy text itself), and a stale row —
// stored effect='deny' whose text says permit(...) — would read back as an
// allow anyway, making the column actively misleading rather than merely
// redundant. See LoadAllPolicies' own doc comment (store/policy.go) for why
// the database column stays despite that.
type StoredPolicy struct {
	ID       string
	Name     string
	Language string
	Text     string

	// Priority is recorded for provenance and audit only. Spec Y7 removed
	// priority as security-relevant: first-applicable-by-priority is a classic
	// source of "why didn't that policy apply," and deny-overrides replaced
	// it. An engine must not sort, filter, or short-circuit evaluation by this
	// field — doing so would quietly reopen what Y7 closed.
	Priority int

	// Version is loaded but not yet read by anything: spec Y2 wants it as a
	// cache key, and Phase 4 has no cache yet (Task 5/6 measure whether one
	// is warranted before one gets built around a guessed compile-versus-
	// evaluate ratio — see PolicyEngine's own doc comment). It is loaded now,
	// ahead of that decision, so the next reader finds it already threaded
	// through the store rather than needing a second migration-shaped change
	// once caching actually lands. Do not delete this as dead: unlike the
	// policies.effect column discussed above, nothing about Version can go
	// stale by sitting unread — it is just early.
	Version int64
}
