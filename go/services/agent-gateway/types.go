package agent_gateway

import (
	"stratium/pkg/models"
)

// InternalCreateDelegationParams holds parsed parameters for creating a delegation.
// These are extracted from the gRPC request plus the authenticated user context.
type InternalCreateDelegationParams struct {
	UserID                string
	AgentID               string
	ApprovedTools         []string
	ApprovedActions       []models.ActionTier
	MaxActionTier         models.ActionTier
	ClassificationCaps    map[string]string
	ResourceConstraints   map[string]string
	Purpose               string
	TTLSeconds            int
	ConversationID        string
	ParentDelegationToken string
}

// InternalExecuteActionParams holds parsed parameters for executing an action.
type InternalExecuteActionParams struct {
	DelegationToken    string
	TargetService      string
	Method             string
	Action             string
	ActionTier         models.ActionTier
	ToolName           string
	ResourceAttributes map[string]string
	Payload            []byte
	ExecutionMode      models.ExecutionMode
}

// InternalCompoundDecisionResult holds the internal compound authorization decision.
type InternalCompoundDecisionResult struct {
	UserDecision    string
	UserReason      string
	DeniedAtDepth   int
	DeniedPrincipal string
	ChainDecisions  []InternalChainHopDecision
}

// InternalChainHopDecision holds the decision for a single hop in the chain.
type InternalChainHopDecision struct {
	Depth              int
	AgentID            string
	DelegationID       string
	AgentDecision      string
	AgentReason        string
	DelegationDecision string
	DelegationReason   string
}

// InternalPlannedAction represents an action to be validated internally.
type InternalPlannedAction struct {
	ToolName     string
	Action       string
	DeclaredTier models.ActionTier
	Resource     map[string]string
	Parameters   map[string]string
}
