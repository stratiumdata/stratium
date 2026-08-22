package models

import "github.com/google/uuid"

// AgentCapsView is what the classification-caps routes return. Every field
// beyond ClassificationCaps is advisory: setting a cap has consequences that
// are invisible in the stored value, and this type is where they are stated.
type AgentCapsView struct {
	AgentID            uuid.UUID         `json:"agent_id"`
	ClassificationCaps map[string]string `json:"classification_caps"`

	// CatchAll gives the level the empty-prefix rule resolves to per capped
	// hierarchy, or nil where there is none -- reachable only via
	// ?allow_uncovered=true, and the state in which every unmatched resource
	// denies.
	CatchAll map[string]*string `json:"catch_all"`

	// UnsatisfiableTools are tools that can never satisfy ANY cap, because they
	// declare no resource_field and so produce no resource to label. Not
	// "denied by this cap" -- denied by any cap at all.
	UnsatisfiableTools []string `json:"unsatisfiable_tools"`

	// LiveDelegations counts the agent's delegations that are neither revoked
	// nor expired. These are the delegations this cap does NOT affect. A
	// warning, not a confirmation.
	LiveDelegations int `json:"live_delegations"`

	// Applies is a fixed human-readable string, always "at next issuance".
	// Present so a reader of the raw response need not infer timing. Not
	// machine-readable; clients must not branch on it.
	Applies string `json:"applies"`
}
