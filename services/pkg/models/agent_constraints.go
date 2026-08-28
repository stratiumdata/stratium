package models

import "github.com/google/uuid"

// AgentConstraintsView is what the resource-constraints routes return: the
// scope itself plus the two warnings an operator needs to read it correctly.
// Deliberately the same shape as AgentCapsView, which carries the same two
// warnings for the same reasons.
type AgentConstraintsView struct {
	AgentID             uuid.UUID         `json:"agent_id"`
	ResourceConstraints map[string]string `json:"resource_constraints"`

	// UnsatisfiableTools are tools that can satisfy NO constraint, because
	// they resolve no resource identity at all -- a catalogued tool with
	// neither a resource_field nor a command_field. Not "denied by this
	// scope": denied by any scope whatsoever. Same computation and same
	// caveats as AgentCapsView.UnsatisfiableTools, including that an
	// UNRESTRICTED agent's uncatalogued tools cannot be enumerated.
	UnsatisfiableTools []string `json:"unsatisfiable_tools"`

	// LiveDelegations counts the agent's delegations that are neither revoked
	// nor expired -- the ones this write does NOT affect, because constraints
	// are copied at issuance. A warning, not a confirmation.
	LiveDelegations int `json:"live_delegations"`
}
