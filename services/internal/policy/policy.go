// Package policy is the seam the policy engines plug into.
//
// PrincipalPolicy is declared here; Multi (multi.go) is the only production
// implementation — it evaluates a tenant's policies across every registered
// language engine (cedar, rego, json, xacml). Two earlier implementations
// used to live in this file and in configured.go: Unconfigured, which always
// denied, for a deployment with no policy engine wired at all; and
// Configured, which delegated to exactly one PolicyEngine. Phase 4a Task 4
// deleted both once Multi's Registry subsumed them — a Registry with one
// entry behaves identically to what Configured did, and an empty Registry
// denies exactly as Unconfigured did — and because Configured was worse than
// merely redundant: it silently evaluated only one tenant-authored language
// and ignored the rest, no error, no verdict, no audit trace (defect D10,
// the reason this phase exists). There is deliberately no unconditional
// allow-all variant, not even behind a flag: a predecessor carried a
// development-only auth fallback into production, where any OIDC blip
// silently accepted forged tokens. A bypass outlives the reason it was
// added. TestNoExportedConstructorAllows (policy_test.go) is the guard
// against one being added here later.
package policy

import (
	"context"

	"github.com/stratiumdata/stratium/internal/authz"
)

// PrincipalPolicy decides the principal leg: whether the human on whose
// behalf the agent acts may perform this action, on this resource, in this
// context. Evaluate receives the agent and delegation dimensions too (see
// EvaluationInput) so a policy can condition on them — "deny Unverified
// agents on financial tools" — but it still answers for the principal leg
// alone; the agent and delegation legs are decided elsewhere, as separate AND
// terms, so nothing here can widen what they allow.
//
// Evaluate returns every verdict it consulted — authz.FoldVerdicts is what
// combines them with deny-overrides — so provenance for each one survives
// into the response and the audit row.
type PrincipalPolicy interface {
	Evaluate(ctx context.Context, in EvaluationInput) []authz.PolicyVerdict
}
