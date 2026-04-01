package models

import (
	"time"

	"github.com/google/uuid"
)

// AgentTrustTier represents the trust level assigned to an agent.
type AgentTrustTier int

const (
	TrustTierUnverified      AgentTrustTier = 0 // Read-only, sandboxed
	TrustTierRegistered      AgentTrustTier = 1 // Read + limited write, approval for sensitive
	TrustTierCertified       AgentTrustTier = 2 // Full read/write within delegation scope
	TrustTierPlatformTrusted AgentTrustTier = 3 // System-level actions (compliance, security)
)

// String returns the human-readable name of the trust tier.
func (t AgentTrustTier) String() string {
	switch t {
	case TrustTierUnverified:
		return "unverified"
	case TrustTierRegistered:
		return "registered"
	case TrustTierCertified:
		return "certified"
	case TrustTierPlatformTrusted:
		return "platform-trusted"
	default:
		return "unknown"
	}
}

// ActionTier represents the sensitivity level of an action.
type ActionTier int

const (
	ActionTierReasoning      ActionTier = 0 // Reasoning only, no side effects
	ActionTierReadOnly       ActionTier = 1 // Read-only data retrieval
	ActionTierInternalModify ActionTier = 2 // Internal data modifications
	ActionTierExternalComms  ActionTier = 3 // External communications (email, webhook, API)
	ActionTierDestructive    ActionTier = 4 // Destructive or financially binding actions
)

// String returns the human-readable name of the action tier.
func (t ActionTier) String() string {
	switch t {
	case ActionTierReasoning:
		return "reasoning"
	case ActionTierReadOnly:
		return "read-only"
	case ActionTierInternalModify:
		return "internal-modify"
	case ActionTierExternalComms:
		return "external-comms"
	case ActionTierDestructive:
		return "destructive"
	default:
		return "unknown"
	}
}

// ExecutionMode defines how an agent is acting.
type ExecutionMode int

const (
	ExecutionModeDelegated ExecutionMode = 0 // Agent acts FOR user (intersection of rights)
	ExecutionModeSystem    ExecutionMode = 1 // Agent acts AS system function (separate policy)
)

// AgentCertStatus represents the certification status of an agent.
type AgentCertStatus string

const (
	AgentCertStatusPending   AgentCertStatus = "PENDING"
	AgentCertStatusCertified AgentCertStatus = "CERTIFIED"
	AgentCertStatusSuspended AgentCertStatus = "SUSPENDED"
	AgentCertStatusRevoked   AgentCertStatus = "REVOKED"
)

// Agent represents a registered AI agent in the system.
type Agent struct {
	ID              uuid.UUID              `json:"id" db:"id"`
	Name            string                 `json:"name" db:"name"`
	Description     string                 `json:"description" db:"description"`
	Provider        string                 `json:"provider" db:"provider"`
	ModelIdentifier string                 `json:"model_identifier" db:"model_id"`
	TrustTier       AgentTrustTier         `json:"trust_tier" db:"trust_tier"`
	AllowedTools    []string               `json:"allowed_tools" db:"allowed_tools"`
	AllowedActions  []ActionTier           `json:"allowed_actions" db:"allowed_actions"`
	TenantID        string                 `json:"tenant_id" db:"tenant_id"`
	CertStatus      AgentCertStatus        `json:"cert_status" db:"cert_status"`
	ClientID        string                 `json:"client_id" db:"client_id"`
	ClientSecret    []byte                 `json:"-" db:"client_secret"` // Never serialized
	Metadata        map[string]interface{} `json:"metadata" db:"metadata"`
	Enabled         bool                   `json:"enabled" db:"enabled"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy       string                 `json:"created_by" db:"created_by"`
}

// MaxActionTier returns the highest action tier this agent is allowed.
func (a *Agent) MaxActionTier() ActionTier {
	max := ActionTierReasoning
	for _, t := range a.AllowedActions {
		if t > max {
			max = t
		}
	}
	return max
}

// HasTool returns true if the agent is allowed to use the given tool.
// An empty AllowedTools list means no restriction — all tools are permitted.
// This is consistent with the PAP scope validator and the local hook enforcement.
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

// CreateAgentRequest represents a request to register a new agent.
type CreateAgentRequest struct {
	Name            string                 `json:"name" binding:"required"`
	Description     string                 `json:"description"`
	Provider        string                 `json:"provider" binding:"required"`
	ModelIdentifier string                 `json:"model_identifier"`
	TrustTier       AgentTrustTier         `json:"trust_tier"`
	AllowedTools    []string               `json:"allowed_tools"`
	AllowedActions  []ActionTier           `json:"allowed_actions"`
	TenantID        string                 `json:"tenant_id" binding:"required"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// UpdateAgentRequest represents a request to update an agent.
type UpdateAgentRequest struct {
	Name            *string                `json:"name"`
	Description     *string                `json:"description"`
	TrustTier       *AgentTrustTier        `json:"trust_tier"`
	AllowedTools    []string               `json:"allowed_tools"`
	AllowedActions  []ActionTier           `json:"allowed_actions"`
	Metadata        map[string]interface{} `json:"metadata"`
	Enabled         *bool                  `json:"enabled"`
}

// ListAgentsRequest represents query parameters for listing agents.
type ListAgentsRequest struct {
	TenantID    string          `form:"tenant_id"`
	TrustTier   *AgentTrustTier `form:"trust_tier"`
	EnabledOnly bool            `form:"enabled_only"`
	Limit       int             `form:"limit"`
	Offset      int             `form:"offset"`
}
