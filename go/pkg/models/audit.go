package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// EntityType represents the type of entity being audited
type EntityType string

const (
	EntityTypePolicy      EntityType = "policy"
	EntityTypeEntitlement EntityType = "entitlement"
	// Agent-authorization audit entity types (CHECK constraint extended by
	// migration 04-init-agent-auth.sql).
	EntityTypeAgent      EntityType = "agent"
	EntityTypeDelegation EntityType = "delegation"
)

// AuditAction represents the action being audited
type AuditAction string

const (
	AuditActionCreate   AuditAction = "create"
	AuditActionUpdate   AuditAction = "update"
	AuditActionDelete   AuditAction = "delete"
	AuditActionEvaluate AuditAction = "evaluate"
	AuditActionTest     AuditAction = "test"
	// Agent-authorization audit actions
	AuditActionAuthorize AuditAction = "authorize"
	AuditActionRevoke    AuditAction = "revoke"
	AuditActionSuspend   AuditAction = "suspend"
)

// AuditLog represents an audit log entry.
//
// The Agent* fields are optional extensions populated only by the agent-gateway
// service when recording delegation lifecycle and authorization decisions
// (CreateDelegation, ExecuteAction, RevokeDelegation, SuspendAgent). For
// callers writing non-agent audit rows (PAP policies, entitlements), leave
// them nil and they will be inserted as NULL.
type AuditLog struct {
	ID         uuid.UUID              `json:"id" db:"id"`
	EntityType EntityType             `json:"entity_type" db:"entity_type"`
	EntityID   *uuid.UUID             `json:"entity_id,omitempty" db:"entity_id"`
	Action     AuditAction            `json:"action" db:"action"`
	Actor      string                 `json:"actor" db:"actor"`
	Changes    map[string]interface{} `json:"changes,omitempty" db:"changes"`
	Result     map[string]interface{} `json:"result,omitempty" db:"result"`
	Timestamp  time.Time              `json:"timestamp" db:"timestamp"`
	IPAddress  string                 `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent  string                 `json:"user_agent,omitempty" db:"user_agent"`

	// Agent-authorization extensions (columns added by 04-init-agent-auth.sql).
	AgentID            *uuid.UUID `json:"agent_id,omitempty"            db:"agent_id"`
	DelegationID       *uuid.UUID `json:"delegation_id,omitempty"       db:"delegation_id"`
	AgentTrustTier     *int16     `json:"agent_trust_tier,omitempty"    db:"agent_trust_tier"`
	ToolName           *string    `json:"tool_name,omitempty"           db:"tool_name"`
	ActionTier         *int16     `json:"action_tier,omitempty"         db:"action_tier"`
	ExecutionMode      *string    `json:"execution_mode,omitempty"      db:"execution_mode"`
	ConversationID     *string    `json:"conversation_id,omitempty"     db:"conversation_id"`
	UserDecision       *string    `json:"user_decision,omitempty"       db:"user_decision"`
	AgentDecision      *string    `json:"agent_decision,omitempty"      db:"agent_decision"`
	DelegationDecision *string    `json:"delegation_decision,omitempty" db:"delegation_decision"`
	ChainDepth         *int16     `json:"chain_depth,omitempty"         db:"chain_depth"`
	ChainAgentIDs      []string   `json:"chain_agent_ids,omitempty"     db:"chain_agent_ids"`
	RootDelegationID   *uuid.UUID `json:"root_delegation_id,omitempty"  db:"root_delegation_id"`
	DeniedAtDepth      *int16     `json:"denied_at_depth,omitempty"     db:"denied_at_depth"`
	DeniedPrincipal    *string    `json:"denied_principal,omitempty"    db:"denied_principal"`
}

// CreateAuditLogRequest represents a request to create an audit log entry
type CreateAuditLogRequest struct {
	EntityType EntityType
	EntityID   *uuid.UUID
	Action     AuditAction
	Actor      string
	Changes    map[string]interface{}
	Result     map[string]interface{}
	IPAddress  string
	UserAgent  string
}

// ListAuditLogsRequest represents query parameters for listing audit logs
type ListAuditLogsRequest struct {
	EntityType *EntityType  `form:"entity_type"`
	EntityID   *uuid.UUID   `form:"entity_id"`
	Action     *AuditAction `form:"action"`
	Actor      string       `form:"actor"`
	StartDate  *time.Time   `form:"start_date"`
	EndDate    *time.Time   `form:"end_date"`
	Limit      int          `form:"limit"`
	Offset     int          `form:"offset"`
}

// ToAuditLog converts CreateAuditLogRequest to AuditLog
func (r *CreateAuditLogRequest) ToAuditLog() *AuditLog {
	return &AuditLog{
		ID:         uuid.New(),
		EntityType: r.EntityType,
		EntityID:   r.EntityID,
		Action:     r.Action,
		Actor:      r.Actor,
		Changes:    r.Changes,
		Result:     r.Result,
		Timestamp:  time.Now(),
		IPAddress:  r.IPAddress,
		UserAgent:  r.UserAgent,
	}
}

// MarshalJSON customizes JSON serialization
func (a *AuditLog) MarshalJSON() ([]byte, error) {
	type Alias AuditLog
	return json.Marshal(&struct {
		*Alias
		ID       string  `json:"id"`
		EntityID *string `json:"entity_id,omitempty"`
	}{
		Alias:    (*Alias)(a),
		ID:       a.ID.String(),
		EntityID: uuidPtrToStringPtr(a.EntityID),
	})
}

func uuidPtrToStringPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}