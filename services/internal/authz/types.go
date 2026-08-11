// Package authz is the single place a Stratium authorization decision is
// computed. It is pure: no database handles, no network clients, no ambient
// clock. Callers load the data and pass it in; authz decides.
//
// Every enforcement surface — gRPC proxy, MCP, hooks, Envoy ext-authz —
// reaches this code through the PDP. Nothing else may compute a decision.
// Three parallel implementations drifting apart is the specific failure this
// package exists to prevent.
//
// TierTable.Catalog (tier.go) is seeded by DefaultCatalog (catalog.go) with
// tool names — "Read", "Write", "WebFetch" — that are Claude Code's names,
// not a framework-agnostic vocabulary, even though this package's stated job
// is to serve any agent framework. That mismatch is a deliberate, temporary
// trade, not an oversight: a catalog nobody populates leaves the
// tool-input-has-no-verb defect exactly where it was (see DeriveTier's and
// BuiltinTier's doc comments), and the failure mode of shipping the trade is
// silent rather than loud — a tool name this catalog does not recognize
// simply falls through to BuiltinTier or the tenant's UnknownTier floor,
// same as before the catalog existed, never an error. The eventual home for
// this table is a database-backed, per-tenant catalog; DefaultCatalog is the
// seed it starts from, not the end state.
package authz

import (
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// Effect is the outcome of a decision, or of one leg of it.
type Effect int

const (
	// EffectDeny is the zero value deliberately: a leg that is never evaluated
	// must deny rather than silently permit. Do not reorder these.
	EffectDeny Effect = iota
	EffectAllow
	EffectEscalate
)

func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "ALLOW"
	case EffectEscalate:
		return "ESCALATE"
	default:
		return "DENY"
	}
}

// LegResult is one leg's contribution to the compound decision.
type LegResult struct {
	Effect Effect
	Reason string
}

// PolicyVerdict is one policy's answer about the principal. It is plain data:
// the engines produce it, authz consumes it, and no engine dependency enters
// this package.
type PolicyVerdict struct {
	Effect Effect
	Reason string

	// Source names the engine or grant model — "cedar", "rego", "xacml",
	// "json", "entitlement". Recorded for provenance.
	Source string

	// PolicyID identifies the specific policy or entitlement row.
	PolicyID string

	// Priority is recorded for audit and debugging and is NOT consulted by the
	// fold. Deny-overrides makes priority security-irrelevant (spec §3.3 Y7);
	// ordering by it here would reinstate the bug class Y7 removed.
	Priority int
}

// Action describes what the agent is attempting.
type Action struct {
	Tool     string // "Bash", "Read", "mcp__stripe__create_refund"
	Verb     string // "read", "write", "delete"
	RawInput string // the actual command or path, used for derivation

	// NormalizedInput is a caller-supplied, best-effort extraction from
	// RawInput (e.g. a PEP pulling "ls -la" out of {"command":"ls -la"}).
	// BuiltinTier classifies both and combines them by evidence: a positive
	// destructive-or-external match on RawInput always wins, otherwise a
	// NormalizedInput that positively classifies is used, otherwise
	// RawInput's own result (including its default). An extraction that
	// under-reports, or is left empty, can only fail to raise the tier — it
	// can never lower RawInput below what a destructive or external match on
	// RawInput alone would produce. See BuiltinTier's doc comment.
	NormalizedInput string

	// DeclaredTier is what the caller claims. It never derives the tier — it is
	// only cross-checked against the derived value (C1, C2, C3).
	DeclaredTier *models.ActionTier
}

// Principal is the human on whose behalf the agent acts.
type Principal struct {
	Subject    string
	Attributes map[string]string
}

// AgentInfo is the acting agent's registry record, reduced to what a decision
// needs.
type AgentInfo struct {
	ID           uuid.UUID
	TrustTier    models.AgentTrustTier
	Enabled      bool
	Suspended    bool
	AllowedTools []string
}

// Request is a complete decision input. Chain is ordered root-first, with the
// acting delegation last.
type Request struct {
	TenantID  string
	Principal Principal
	Agent     AgentInfo
	Chain     []*models.Delegation
	Action    Action
	Resource  map[string]string

	// Now is injected so decisions are deterministic and testable.
	Now time.Time

	// PrincipalVerdicts are the policy engines' per-policy verdicts, evaluated
	// before this call and combined by FoldVerdicts. A nil or empty slice
	// folds to deny (default-deny), so a caller that forgets to evaluate it
	// denies rather than permitting.
	PrincipalVerdicts []PolicyVerdict
}

// Result is the compound decision.
type Result struct {
	Effect      Effect
	DerivedTier models.ActionTier

	Principal  LegResult
	Agent      LegResult
	Delegation LegResult

	// PrincipalVerdicts is every verdict consulted, in the order supplied.
	PrincipalVerdicts []PolicyVerdict
	// Deciding names the verdict Principal.Reason was attributed to, or nil
	// when the decision was default-deny with no verdict at all. That case
	// is real (an empty PrincipalVerdicts slice folds to deny) and must not
	// be papered over with a zero-value verdict: "no policy spoke" and "a
	// policy denied" are different facts an auditor needs told apart.
	Deciding *PolicyVerdict

	// DeniedAtDepth is the chain depth at which a denial occurred, or -1.
	DeniedAtDepth int
	DeniedLeg     string
	Reason        string
}
