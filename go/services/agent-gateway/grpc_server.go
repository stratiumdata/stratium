package agent_gateway

import (
	"context"
	"fmt"

	"stratium/pkg/models"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GRPCServer adapts the business-logic Server to the generated
// AgentGatewayServiceServer gRPC interface.
type GRPCServer struct {
	UnimplementedAgentGatewayServiceServer
	server *Server
}

// NewGRPCServer wraps an existing Server for gRPC registration.
func NewGRPCServer(server *Server) *GRPCServer {
	return &GRPCServer{server: server}
}

// --- Delegation Lifecycle ---

func (g *GRPCServer) CreateDelegation(ctx context.Context, req *CreateDelegationRequest) (*CreateDelegationResponse, error) {
	userID, err := extractUserID(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing user identity: %v", err)
	}

	approvedActions := make([]models.ActionTier, len(req.GetApprovedActions()))
	for i, a := range req.GetApprovedActions() {
		approvedActions[i] = models.ActionTier(a)
	}

	params := &InternalCreateDelegationParams{
		UserID:                userID,
		AgentID:               req.GetAgentId(),
		ApprovedTools:         req.GetApprovedTools(),
		ApprovedActions:       approvedActions,
		MaxActionTier:         models.ActionTier(req.GetMaxActionTier()),
		ClassificationCaps:    req.GetClassificationCaps(),
		ResourceConstraints:   req.GetResourceConstraints(),
		Purpose:               req.GetPurpose(),
		TTLSeconds:            int(req.GetTtlSeconds()),
		ConversationID:        req.GetConversationId(),
		ParentDelegationToken: req.GetParentDelegationToken(),
	}

	resp, err := g.server.CreateDelegation(ctx, params)
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return resp, nil
}

func (g *GRPCServer) RevokeDelegation(ctx context.Context, req *RevokeDelegationRequest) (*RevokeDelegationResponse, error) {
	if _, err := extractUserID(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing user identity: %v", err)
	}
	resp, err := g.server.RevokeDelegation(ctx, req.GetDelegationId(), req.GetReason())
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return resp, nil
}

// --- Action Execution ---

func (g *GRPCServer) ExecuteAction(ctx context.Context, req *ExecuteActionRequest) (*ExecuteActionResponse, error) {
	params := &InternalExecuteActionParams{
		DelegationToken:    req.GetDelegationToken(),
		TargetService:      req.GetTargetService(),
		Method:             req.GetMethod(),
		Action:             req.GetAction(),
		ActionTier:         models.ActionTier(req.GetActionTier()),
		ToolName:           req.GetToolName(),
		ResourceAttributes: req.GetResourceAttributes(),
		Payload:            req.GetPayload(),
		ExecutionMode:      models.ExecutionMode(req.GetExecutionMode()),
	}

	resp, err := g.server.ExecuteAction(ctx, params)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "action execution failed: %v", err)
	}
	return resp, nil
}

func (g *GRPCServer) ValidateActionPlan(ctx context.Context, req *ValidateActionPlanRequest) (*ValidateActionPlanResponse, error) {
	actions := make([]InternalPlannedAction, len(req.GetActions()))
	for i, a := range req.GetActions() {
		actions[i] = InternalPlannedAction{
			ToolName:     a.GetToolName(),
			Action:       a.GetAction(),
			DeclaredTier: models.ActionTier(a.GetDeclaredTier()),
			Resource:     a.GetResource(),
			Parameters:   a.GetParameters(),
		}
	}

	resp, err := g.server.ValidateActionPlan(ctx, req.GetDelegationId(), actions)
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return resp, nil
}

func (g *GRPCServer) GetDelegationChain(ctx context.Context, req *GetDelegationChainRequest) (*GetDelegationChainResponse, error) {
	resp, err := g.server.GetDelegationChain(ctx, req.GetDelegationId())
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return resp, nil
}

// --- Agent Registry ---

func (g *GRPCServer) RegisterAgent(ctx context.Context, req *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	createdBy, err := extractUserID(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing user identity: %v", err)
	}

	// Convert proto metadata map[string]string to model map[string]interface{}
	meta := make(map[string]interface{}, len(req.GetMetadata()))
	for k, v := range req.GetMetadata() {
		meta[k] = v
	}

	allowedActions := make([]models.ActionTier, len(req.GetAllowedActions()))
	for i, a := range req.GetAllowedActions() {
		allowedActions[i] = models.ActionTier(a)
	}

	createReq := &models.CreateAgentRequest{
		Name:            req.GetName(),
		Description:     req.GetDescription(),
		Provider:        req.GetProvider(),
		ModelIdentifier: req.GetModelIdentifier(),
		TrustTier:       models.AgentTrustTier(req.GetTrustTier()),
		AllowedTools:    req.GetAllowedTools(),
		AllowedActions:  allowedActions,
		TenantID:        req.GetTenantId(),
		Metadata:        meta,
	}

	agent, clientSecret, err := g.server.RegisterAgent(ctx, createReq, createdBy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to register agent: %v", err)
	}

	return &RegisterAgentResponse{
		AgentId:      agent.ID.String(),
		ClientId:     agent.ClientID,
		ClientSecret: clientSecret,
		CreatedAt:    timestamppb.New(agent.CreatedAt),
	}, nil
}

func (g *GRPCServer) GetAgent(ctx context.Context, req *GetAgentRequest) (*GetAgentResponse, error) {
	id, err := uuid.Parse(req.GetAgentId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent_id: %v", err)
	}

	agent, err := g.server.repo.Agent.GetByID(ctx, id)
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return &GetAgentResponse{Agent: agentToProto(agent)}, nil
}

func (g *GRPCServer) ListAgents(ctx context.Context, req *ListAgentsRequest) (*ListAgentsResponse, error) {
	listReq := &models.ListAgentsRequest{
		TenantID:    req.GetTenantId(),
		EnabledOnly: req.GetEnabledOnly(),
		Limit:       int(req.GetPageSize()),
	}
	if listReq.Limit <= 0 || listReq.Limit > 100 {
		listReq.Limit = 50
	}

	agents, err := g.server.repo.Agent.List(ctx, listReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list agents: %v", err)
	}
	count, _ := g.server.repo.Agent.Count(ctx, listReq)

	protoAgents := make([]*AgentInfo, len(agents))
	for i, a := range agents {
		protoAgents[i] = agentToProto(a)
	}

	return &ListAgentsResponse{
		Agents:     protoAgents,
		TotalCount: int32(count),
	}, nil
}

func (g *GRPCServer) UpdateAgent(ctx context.Context, req *UpdateAgentRequest) (*UpdateAgentResponse, error) {
	if _, err := extractUserID(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing user identity: %v", err)
	}
	id, err := uuid.Parse(req.GetAgentId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid agent_id: %v", err)
	}

	agent, err := g.server.repo.Agent.GetByID(ctx, id)
	if err != nil {
		return nil, mapBusinessError(err)
	}

	// Proto3 uses zero values — apply all non-zero fields.
	// The caller should send the full desired state for fields they want to change.
	if req.GetName() != "" {
		agent.Name = req.GetName()
	}
	if req.GetDescription() != "" {
		agent.Description = req.GetDescription()
	}
	if req.GetTrustTier() != AgentTrustTier_AGENT_TRUST_TIER_UNVERIFIED {
		agent.TrustTier = models.AgentTrustTier(req.GetTrustTier())
	}
	if len(req.GetAllowedTools()) > 0 {
		agent.AllowedTools = req.GetAllowedTools()
	}
	if len(req.GetAllowedActions()) > 0 {
		actions := make([]models.ActionTier, len(req.GetAllowedActions()))
		for i, a := range req.GetAllowedActions() {
			actions[i] = models.ActionTier(a)
		}
		agent.AllowedActions = actions
	}
	// Enabled is a bool — always applied (proto3 default is false)
	agent.Enabled = req.GetEnabled()

	if err := g.server.repo.Agent.Update(ctx, agent); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update agent: %v", err)
	}

	return &UpdateAgentResponse{Agent: agentToProto(agent)}, nil
}

func (g *GRPCServer) SuspendAgent(ctx context.Context, req *SuspendAgentRequest) (*SuspendAgentResponse, error) {
	if _, err := extractUserID(ctx); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "missing user identity: %v", err)
	}
	revokedCount, err := g.server.SuspendAgent(ctx, req.GetAgentId(), req.GetReason())
	if err != nil {
		return nil, mapBusinessError(err)
	}
	return &SuspendAgentResponse{
		Success:            true,
		RevokedDelegations: int32(revokedCount),
	}, nil
}

// --- Helpers ---

// extractUserID returns the verified caller identity established by the
// IdentityVerificationInterceptor. It never trusts client-supplied metadata
// (e.g. x-user-id) or unverified tokens.
func extractUserID(ctx context.Context) (string, error) {
	if id, ok := identityFromContext(ctx); ok {
		return id, nil
	}
	return "", fmt.Errorf("no verified user identity in request context")
}

func agentToProto(a *models.Agent) *AgentInfo {
	allowedActions := make([]ActionTier, len(a.AllowedActions))
	for i, t := range a.AllowedActions {
		allowedActions[i] = ActionTier(t)
	}

	return &AgentInfo{
		Id:              a.ID.String(),
		Name:            a.Name,
		Description:     a.Description,
		Provider:        a.Provider,
		ModelIdentifier: a.ModelIdentifier,
		TrustTier:       AgentTrustTier(a.TrustTier),
		AllowedTools:    a.AllowedTools,
		AllowedActions:  allowedActions,
		TenantId:        a.TenantID,
		CertStatus:      certStatusToProto(a.CertStatus),
		ClientId:        a.ClientID,
		Enabled:         a.Enabled,
		CreatedAt:       timestamppb.New(a.CreatedAt),
		UpdatedAt:       timestamppb.New(a.UpdatedAt),
		CreatedBy:       a.CreatedBy,
	}
}

func certStatusToProto(s models.AgentCertStatus) AgentCertStatus {
	switch s {
	case models.AgentCertStatusPending:
		return AgentCertStatus_AGENT_CERT_STATUS_PENDING
	case models.AgentCertStatusCertified:
		return AgentCertStatus_AGENT_CERT_STATUS_CERTIFIED
	case models.AgentCertStatusSuspended:
		return AgentCertStatus_AGENT_CERT_STATUS_SUSPENDED
	case models.AgentCertStatusRevoked:
		return AgentCertStatus_AGENT_CERT_STATUS_REVOKED
	default:
		return AgentCertStatus_AGENT_CERT_STATUS_PENDING
	}
}

func mapBusinessError(err error) error {
	switch {
	case err == nil:
		return nil
	case isNotFound(err):
		return status.Errorf(codes.NotFound, "%v", err)
	case isValidation(err):
		return status.Errorf(codes.InvalidArgument, "%v", err)
	case isPermission(err):
		return status.Errorf(codes.PermissionDenied, "%v", err)
	default:
		return status.Errorf(codes.Internal, "%v", err)
	}
}

func isNotFound(err error) bool {
	return err == models.ErrNotFound || err == models.ErrDelegationNotFound || err == models.ErrAgentNotFound
}

func isValidation(err error) bool {
	return err == models.ErrDelegationMaxDepth || err == models.ErrDelegationScopeExceeded || err == models.ErrDelegationInvalidToken
}

func isPermission(err error) bool {
	return err == models.ErrAgentDisabled || err == models.ErrAgentSuspended || err == models.ErrDelegationRevoked || err == models.ErrDelegationExpired
}
