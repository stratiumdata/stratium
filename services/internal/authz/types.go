// Package authz is the single place a Stratium authorization decision is
// computed. It is pure: no database handles, no network clients, no ambient
// clock. Callers load the data and pass it in; authz decides.
//
// Every enforcement surface — gRPC proxy, MCP, hooks, Envoy ext-authz —
// reaches this code through the PDP. Nothing else may compute a decision.
// Three parallel implementations drifting apart is the specific failure this
// package exists to prevent.
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

	// DeniedAtDepth is the chain depth at which a denial occurred, or -1.
	DeniedAtDepth int
	DeniedLeg     string
	Reason        string
}
