package models

import "github.com/google/uuid"

// AgentEscalationView is what every /v1/agents/{id}/escalation route
// returns, the same advisory shape AgentConstraintsView carries: the value,
// and the consequence the stored value cannot show by itself.
type AgentEscalationView struct {
	AgentID uuid.UUID `json:"agent_id"`

	// EscalateAt is null when the agent has no threshold (never escalate).
	EscalateAt *ActionTier `json:"escalate_at"`

	// LiveDelegations counts delegations this write does NOT affect, because
	// the threshold is copied at issuance. A warning, not a confirmation.
	LiveDelegations int `json:"live_delegations"`

	// Applies is always "at next issuance". Display only.
	Applies string `json:"applies"`
}
