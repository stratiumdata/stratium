package models

import "github.com/google/uuid"

// Agent is a registered non-person entity that acts on a principal's behalf.
type Agent struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	Name     string `json:"name"     db:"name"`
	Provider string `json:"provider" db:"provider"`
	ModelID  string `json:"model_id" db:"model_id"`

	TrustTier AgentTrustTier `json:"trust_tier" db:"trust_tier"`
	Enabled   bool           `json:"enabled"    db:"enabled"`
	Suspended bool           `json:"suspended"  db:"suspended"`

	AllowedTools []string `json:"allowed_tools" db:"allowed_tools"`
}

// HasTool reports whether a tool is within the agent's allowlist. An empty
// allowlist is unrestricted — the delegation is the real constraint, and this
// matches Delegation.HasTool so the two never disagree.
func (a *Agent) HasTool(tool string) bool {
	if len(a.AllowedTools) == 0 {
		return true
	}
	for _, t := range a.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}
