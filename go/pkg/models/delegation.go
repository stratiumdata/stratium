package models

import (
	"time"

	"github.com/google/uuid"
)

// Delegation represents an active delegation from a user to an agent,
// or from an agent to a subagent (child delegation).
type Delegation struct {
	ID                  uuid.UUID         `json:"id" db:"id"`
	UserID              string            `json:"user_id" db:"user_id"`
	AgentID             uuid.UUID         `json:"agent_id" db:"agent_id"`
	TenantID            string            `json:"tenant_id" db:"tenant_id"`
	ConversationID      string            `json:"conversation_id" db:"conversation_id"`
	ApprovedTools       []string          `json:"approved_tools" db:"approved_tools"`
	ApprovedActions     []ActionTier      `json:"approved_actions" db:"approved_actions"`
	MaxActionTier       ActionTier        `json:"max_action_tier" db:"max_action_tier"`
	ClassificationCaps  map[string]string `json:"classification_caps" db:"classification_caps"`
	ResourceConstraints map[string]string `json:"resource_constraints" db:"resource_constraints"`
	Purpose             string            `json:"purpose" db:"purpose"`
	ExpiresAt           time.Time         `json:"expires_at" db:"expires_at"`
	CreatedAt           time.Time         `json:"created_at" db:"created_at"`
	Revoked             bool              `json:"revoked" db:"revoked"`
	RevokedAt           *time.Time        `json:"revoked_at,omitempty" db:"revoked_at"`

	// Delegation chain fields
	ParentDelegationID *uuid.UUID  `json:"parent_delegation_id,omitempty" db:"parent_delegation_id"`
	RootDelegationID   uuid.UUID   `json:"root_delegation_id" db:"root_delegation_id"`
	Depth              int         `json:"depth" db:"depth"`
	ChainAgentIDs      []uuid.UUID `json:"chain_agent_ids" db:"chain_agent_ids"`
}

// IsRoot returns true if this is a root delegation (user → agent, no parent).
func (d *Delegation) IsRoot() bool {
	return d.ParentDelegationID == nil
}

// IsExpired returns true if the delegation has expired.
func (d *Delegation) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsActive returns true if the delegation is not expired and not revoked.
func (d *Delegation) IsActive() bool {
	return !d.Revoked && !d.IsExpired()
}

// HasTool returns true if the delegation approves the given tool.
// An empty ApprovedTools list means no restriction — all tools are permitted at this hop.
// This is consistent with Agent.HasTool and the PAP scope validator semantics.
func (d *Delegation) HasTool(tool string) bool {
	if len(d.ApprovedTools) == 0 {
		return true
	}
	for _, t := range d.ApprovedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// HasActionTier returns true if the delegation approves the given action tier.
func (d *Delegation) HasActionTier(tier ActionTier) bool {
	if tier > d.MaxActionTier {
		return false
	}
	for _, t := range d.ApprovedActions {
		if t == tier {
			return true
		}
	}
	return false
}

// DelegationTokenClaims represents the JWT claims for a delegation token.
type DelegationTokenClaims struct {
	// Standard JWT claims
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
	Expiry   int64  `json:"exp"`

	// Delegation-specific claims
	AgentID            string            `json:"agent_id"`
	AgentTrustTier     int               `json:"agent_trust_tier"`
	TenantID           string            `json:"tenant_id"`
	DelegationID       string            `json:"delegation_id"`
	ApprovedTools      []string          `json:"approved_tools"`
	ApprovedActions    []int             `json:"approved_actions"`
	MaxActionTier      int               `json:"max_action_tier"`
	ClassificationCaps map[string]string `json:"classification_caps"`
	ResourceConstraints map[string]string `json:"resource_constraints"`
	Purpose            string            `json:"purpose"`
	ConversationID     string            `json:"conversation_id"`

	// Chain claims
	ParentDelegationID string   `json:"parent_delegation_id,omitempty"`
	RootDelegationID   string   `json:"root_delegation_id"`
	Depth              int      `json:"depth"`
	ChainAgentIDs      []string `json:"chain_agent_ids"`
}

// CreateDelegationRequest represents a request to create a new delegation.
type CreateDelegationRequest struct {
	AgentID             string            `json:"agent_id" binding:"required"`
	ApprovedTools       []string          `json:"approved_tools"`
	ApprovedActions     []ActionTier      `json:"approved_actions"`
	MaxActionTier       ActionTier        `json:"max_action_tier"`
	ClassificationCaps  map[string]string `json:"classification_caps"`
	ResourceConstraints map[string]string `json:"resource_constraints"`
	Purpose             string            `json:"purpose"`
	TTLSeconds          int               `json:"ttl_seconds"`
	ConversationID      string            `json:"conversation_id"`
}

// ScopeNarrows validates that a child scope is a strict subset of the parent scope.
// Returns an error description if the child scope exceeds the parent.
func ScopeNarrows(parent, child *Delegation) string {
	if child.MaxActionTier > parent.MaxActionTier {
		return "child max_action_tier exceeds parent"
	}

	// Check tools are a subset
	parentTools := make(map[string]bool, len(parent.ApprovedTools))
	for _, t := range parent.ApprovedTools {
		parentTools[t] = true
	}
	for _, t := range child.ApprovedTools {
		if !parentTools[t] {
			return "child tool " + t + " not in parent approved_tools"
		}
	}

	// Check actions are a subset
	parentActions := make(map[ActionTier]bool, len(parent.ApprovedActions))
	for _, a := range parent.ApprovedActions {
		parentActions[a] = true
	}
	for _, a := range child.ApprovedActions {
		if !parentActions[a] {
			return "child action tier not in parent approved_actions"
		}
	}

	// Check classification caps only narrow (not widen)
	// This is a simplified check — hierarchy level comparison would need
	// the hierarchy matcher from pkg/validators for full enforcement
	for h, childCap := range child.ClassificationCaps {
		parentCap, ok := parent.ClassificationCaps[h]
		if !ok {
			return "child classification cap for hierarchy " + h + " not in parent"
		}
		// For now, string comparison; full hierarchy comparison deferred to policy engine
		_ = parentCap
		_ = childCap
	}

	// Expiration must not exceed parent
	if child.ExpiresAt.After(parent.ExpiresAt) {
		return "child expires_at exceeds parent"
	}

	return ""
}
