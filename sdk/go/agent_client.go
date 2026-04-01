package stratium

import (
	"context"
	"fmt"
	"time"

	agpb "github.com/stratiumdata/go-sdk/gen/services/agent-gateway"
	"google.golang.org/grpc"
)

// AgentConfig holds configuration for agent authentication.
type AgentConfig struct {
	AgentID            string            // Registered agent ID
	AgentSecret        string            // Agent client secret
	GatewayAddress     string            // Agent Gateway address (e.g., "localhost:50054")
	DefaultPurpose     string            // Default delegation purpose
	DefaultMaxTier     ActionTier        // Default max action tier
	ClassificationCaps map[string]string // Default per-hierarchy caps
}

// ActionTier mirrors the protobuf ActionTier enum for SDK consumers.
type ActionTier int32

const (
	ActionTierReasoning      ActionTier = 0
	ActionTierReadOnly       ActionTier = 1
	ActionTierInternalModify ActionTier = 2
	ActionTierExternalComms  ActionTier = 3
	ActionTierDestructive    ActionTier = 4
)

// Delegation holds the result of a delegation creation.
type Delegation struct {
	Token            string
	DelegationID     string
	Depth            int
	ExpiresAt        time.Time
	RootDelegationID string
}

// AgentAction describes an action to execute through the Agent Gateway.
type AgentAction struct {
	TargetService      string            // "platform", "key-manager", "key-access"
	Method             string            // gRPC method path
	Action             string            // "read", "write", "delete", etc.
	ActionTier         ActionTier        // Sensitivity tier
	ToolName           string            // Tool being invoked
	ResourceAttributes map[string]string // Resource metadata for policy evaluation
	Payload            []byte            // Serialized proto request
}

// ActionResult holds the result of an agent action execution.
type ActionResult struct {
	Authorized bool
	Payload    []byte // Serialized proto response (if authorized)
	Error      string
	Decision   *CompoundDecisionInfo
}

// CompoundDecisionInfo provides the decision breakdown for debugging.
type CompoundDecisionInfo struct {
	DeniedAtDepth   int
	DeniedPrincipal string
}

// DelegationOptions configures a new delegation.
type DelegationOptions struct {
	ApprovedTools       []string
	ApprovedActions     []ActionTier
	MaxActionTier       ActionTier
	ClassificationCaps  map[string]string
	ResourceConstraints map[string]string
	Purpose             string
	TTLSeconds          int
	ConversationID      string
}

// PlannedAgentAction describes an action for validation.
type PlannedAgentAction struct {
	ToolName     string
	Action       string
	DeclaredTier ActionTier
	Resource     map[string]string
	Parameters   map[string]string
}

// ValidationResult holds the result of action plan validation.
type ValidationResult struct {
	Valid   bool
	Results []ActionValidation
}

// ActionValidation holds the result of a single action validation.
type ActionValidation struct {
	ActionIndex  int
	Valid        bool
	Reason       string
	ActualTier   ActionTier
	TierMismatch bool
}

// AgentClient wraps a standard Stratium client with agent delegation capabilities.
type AgentClient struct {
	*Client

	agentConfig    *AgentConfig
	gatewayConn    *grpc.ClientConn
	gatewayClient  agpb.AgentGatewayServiceClient
	activeDelegation *Delegation
}

// NewAgentClient creates a new agent-aware Stratium client.
func NewAgentClient(userConfig *Config, agentConfig *AgentConfig) (*AgentClient, error) {
	if agentConfig == nil {
		return nil, fmt.Errorf("agent config cannot be nil")
	}
	if agentConfig.AgentID == "" {
		return nil, fmt.Errorf("agent_id is required")
	}
	if agentConfig.GatewayAddress == "" {
		return nil, fmt.Errorf("gateway_address is required")
	}

	// Create the base client
	baseClient, err := NewClient(userConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create base client: %w", err)
	}

	// Connect to the Agent Gateway
	dialOpts := baseClient.config.dialOptions()
	gatewayConn, err := grpc.NewClient(agentConfig.GatewayAddress, dialOpts...)
	if err != nil {
		baseClient.Close()
		return nil, fmt.Errorf("failed to connect to agent gateway: %w", err)
	}

	return &AgentClient{
		Client:        baseClient,
		agentConfig:   agentConfig,
		gatewayConn:   gatewayConn,
		gatewayClient: agpb.NewAgentGatewayServiceClient(gatewayConn),
	}, nil
}

// CreateDelegation creates a delegation for this user+agent pair.
func (c *AgentClient) CreateDelegation(ctx context.Context, opts *DelegationOptions) (*Delegation, error) {
	if opts == nil {
		opts = &DelegationOptions{}
	}

	// Apply defaults from agent config
	if opts.Purpose == "" {
		opts.Purpose = c.agentConfig.DefaultPurpose
	}
	if opts.MaxActionTier == 0 && c.agentConfig.DefaultMaxTier > 0 {
		opts.MaxActionTier = c.agentConfig.DefaultMaxTier
	}
	if opts.ClassificationCaps == nil && c.agentConfig.ClassificationCaps != nil {
		opts.ClassificationCaps = c.agentConfig.ClassificationCaps
	}
	if opts.TTLSeconds == 0 {
		opts.TTLSeconds = 900 // 15 min default
	}

	// Convert action tiers to proto enum
	protoActions := make([]agpb.ActionTier, len(opts.ApprovedActions))
	for i, a := range opts.ApprovedActions {
		protoActions[i] = agpb.ActionTier(a)
	}

	ctx, err := c.attachAuth(ctx)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	resp, err := c.gatewayClient.CreateDelegation(ctx, &agpb.CreateDelegationRequest{
		AgentId:             c.agentConfig.AgentID,
		ApprovedTools:       opts.ApprovedTools,
		ApprovedActions:     protoActions,
		MaxActionTier:       agpb.ActionTier(opts.MaxActionTier),
		ClassificationCaps:  opts.ClassificationCaps,
		ResourceConstraints: opts.ResourceConstraints,
		Purpose:             opts.Purpose,
		TtlSeconds:          int32(opts.TTLSeconds),
		ConversationId:      opts.ConversationID,
	})
	if err != nil {
		return nil, fmt.Errorf("create delegation failed: %w", err)
	}

	delegation := &Delegation{
		Token:            resp.DelegationToken,
		DelegationID:     resp.DelegationId,
		Depth:            int(resp.Depth),
		RootDelegationID: resp.RootDelegationId,
	}
	if resp.ExpiresAt != nil {
		delegation.ExpiresAt = resp.ExpiresAt.AsTime()
	}

	c.activeDelegation = delegation
	return delegation, nil
}

// ExecuteAction executes an action through the Agent Gateway with double-hop auth.
func (c *AgentClient) ExecuteAction(ctx context.Context, action *AgentAction) (*ActionResult, error) {
	if c.activeDelegation == nil {
		return nil, fmt.Errorf("no active delegation — call CreateDelegation first")
	}

	resp, err := c.gatewayClient.ExecuteAction(ctx, &agpb.ExecuteActionRequest{
		DelegationToken:    c.activeDelegation.Token,
		TargetService:      action.TargetService,
		Method:             action.Method,
		Action:             action.Action,
		ActionTier:         agpb.ActionTier(action.ActionTier),
		ToolName:           action.ToolName,
		ResourceAttributes: action.ResourceAttributes,
		Payload:            action.Payload,
	})
	if err != nil {
		return nil, fmt.Errorf("execute action failed: %w", err)
	}

	result := &ActionResult{
		Authorized: resp.Authorized,
		Payload:    resp.Payload,
		Error:      resp.Error,
	}
	if resp.Decision != nil {
		result.Decision = &CompoundDecisionInfo{
			DeniedAtDepth:   int(resp.Decision.DeniedAtDepth),
			DeniedPrincipal: resp.Decision.DeniedPrincipal,
		}
	}

	return result, nil
}

// ValidateActionPlan validates a set of planned actions before execution.
func (c *AgentClient) ValidateActionPlan(ctx context.Context, actions []PlannedAgentAction) (*ValidationResult, error) {
	if c.activeDelegation == nil {
		return nil, fmt.Errorf("no active delegation — call CreateDelegation first")
	}

	protoActions := make([]*agpb.PlannedAction, len(actions))
	for i, a := range actions {
		protoActions[i] = &agpb.PlannedAction{
			ToolName:     a.ToolName,
			Action:       a.Action,
			DeclaredTier: agpb.ActionTier(a.DeclaredTier),
			Resource:     a.Resource,
			Parameters:   a.Parameters,
		}
	}

	resp, err := c.gatewayClient.ValidateActionPlan(ctx, &agpb.ValidateActionPlanRequest{
		DelegationId: c.activeDelegation.DelegationID,
		Actions:      protoActions,
	})
	if err != nil {
		return nil, fmt.Errorf("validate action plan failed: %w", err)
	}

	result := &ValidationResult{Valid: resp.Valid}
	for _, r := range resp.Results {
		result.Results = append(result.Results, ActionValidation{
			ActionIndex:  int(r.ActionIndex),
			Valid:        r.Valid,
			Reason:       r.Reason,
			ActualTier:   ActionTier(r.ActualTier),
			TierMismatch: r.TierMismatch,
		})
	}

	return result, nil
}

// RevokeDelegation revokes the active delegation.
func (c *AgentClient) RevokeDelegation(ctx context.Context, reason string) error {
	if c.activeDelegation == nil {
		return fmt.Errorf("no active delegation")
	}

	_, err := c.gatewayClient.RevokeDelegation(ctx, &agpb.RevokeDelegationRequest{
		DelegationId: c.activeDelegation.DelegationID,
		Reason:       reason,
	})
	if err != nil {
		return fmt.Errorf("revoke delegation failed: %w", err)
	}

	c.activeDelegation = nil
	return nil
}

// GetActiveDelegation returns the current active delegation, or nil.
func (c *AgentClient) GetActiveDelegation() *Delegation {
	return c.activeDelegation
}

// Close closes the agent client and all connections.
func (c *AgentClient) Close() error {
	if c.gatewayConn != nil {
		c.gatewayConn.Close()
	}
	return c.Client.Close()
}

// attachAuth adds the OIDC bearer token to the gRPC context.
func (c *AgentClient) attachAuth(ctx context.Context) (context.Context, error) {
	if c.auth == nil {
		return ctx, nil
	}
	token, err := c.auth.GetToken(ctx)
	if err != nil {
		return ctx, err
	}
	return contextWithAuth(ctx, token), nil
}
