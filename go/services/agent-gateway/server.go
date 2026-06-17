package agent_gateway

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"stratium/config"
	"stratium/logging"
	"stratium/pkg/models"
	"stratium/pkg/repository"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var logger = logging.GetLogger()

// Server implements the Agent Gateway business logic.
// It handles delegation token management, action authorization, and agent registry.
type Server struct {
	config     *config.Config
	repo       *repository.Repository
	signingKey []byte
	proxy      *ServiceProxy
}

// NewServer creates a new Agent Gateway server.
func NewServer(cfg *config.Config, repo *repository.Repository) (*Server, error) {
	signingKey := []byte(cfg.AgentGateway.DelegationSigningKey)
	if len(signingKey) == 0 {
		signingKey = make([]byte, 32)
		if _, err := rand.Read(signingKey); err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		logger.Warn("No delegation signing key configured — using ephemeral key (not suitable for production)")
	}

	return &Server{
		config:     cfg,
		repo:       repo,
		signingKey: signingKey,
		proxy:      NewServiceProxy(cfg),
	}, nil
}

// --- Delegation Token Management ---

// CreateDelegation authenticates a user+agent pair and mints a delegation token.
func (s *Server) CreateDelegation(ctx context.Context, req *InternalCreateDelegationParams) (*CreateDelegationResponse, error) {
	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		return nil, fmt.Errorf("invalid agent_id: %w", err)
	}

	agent, err := s.repo.Agent.GetByID(ctx, agentID)
	if err != nil {
		return nil, fmt.Errorf("agent lookup failed: %w", err)
	}
	if !agent.Enabled {
		return nil, models.ErrAgentDisabled
	}
	if agent.CertStatus == models.AgentCertStatusSuspended {
		return nil, models.ErrAgentSuspended
	}

	ttl := s.config.AgentGateway.DelegationTokenTTL
	if req.TTLSeconds > 0 {
		requested := time.Duration(req.TTLSeconds) * time.Second
		if requested < ttl {
			ttl = requested
		}
	}
	if ttl > s.config.AgentGateway.DelegationMaxTTL {
		ttl = s.config.AgentGateway.DelegationMaxTTL
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	delegationID := uuid.New()

	delegation := &models.Delegation{
		ID:                  delegationID,
		UserID:              req.UserID,
		AgentID:             agentID,
		TenantID:            agent.TenantID,
		ConversationID:      req.ConversationID,
		ApprovedTools:       req.ApprovedTools,
		ApprovedActions:     req.ApprovedActions,
		MaxActionTier:       req.MaxActionTier,
		ClassificationCaps:  req.ClassificationCaps,
		ResourceConstraints: req.ResourceConstraints,
		Purpose:             req.Purpose,
		ExpiresAt:           expiresAt,
		CreatedAt:           now,
		Revoked:             false,
		Depth:               0,
		RootDelegationID:    delegationID,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}

	// Handle child delegation (subagent)
	if req.ParentDelegationToken != "" {
		parentClaims, err := s.validateDelegationToken(req.ParentDelegationToken)
		if err != nil {
			return nil, fmt.Errorf("invalid parent delegation token: %w", err)
		}

		parentDelegationID, err := uuid.Parse(parentClaims.DelegationID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent delegation_id: %w", err)
		}

		parentDelegation, err := s.repo.Delegation.GetByID(ctx, parentDelegationID)
		if err != nil {
			return nil, fmt.Errorf("parent delegation lookup failed: %w", err)
		}

		if !parentDelegation.IsActive() {
			return nil, models.ErrDelegationRevoked
		}

		newDepth := parentDelegation.Depth + 1
		if newDepth > s.config.AgentGateway.DelegationMaxDepth {
			return nil, models.ErrDelegationMaxDepth
		}

		if expiresAt.After(parentDelegation.ExpiresAt) {
			expiresAt = parentDelegation.ExpiresAt
		}

		delegation.ParentDelegationID = &parentDelegationID
		delegation.RootDelegationID = parentDelegation.RootDelegationID
		delegation.Depth = newDepth
		delegation.ChainAgentIDs = append(parentDelegation.ChainAgentIDs, agentID)
		delegation.UserID = parentClaims.Subject
		delegation.TenantID = parentDelegation.TenantID
		delegation.ExpiresAt = expiresAt

		if reason := models.ScopeNarrows(parentDelegation, delegation); reason != "" {
			agentScopeWideningAttempts.Inc()
			return nil, fmt.Errorf("%w: %s", models.ErrDelegationScopeExceeded, reason)
		}
	}

	if err := s.repo.Delegation.Create(ctx, delegation); err != nil {
		return nil, fmt.Errorf("failed to create delegation: %w", err)
	}

	token, err := s.mintDelegationToken(delegation, agent)
	if err != nil {
		return nil, fmt.Errorf("failed to mint delegation token: %w", err)
	}

	logger.Info("Created delegation %s for user=%s agent=%s depth=%d ttl=%v",
		delegationID, delegation.UserID, agentID, delegation.Depth, ttl)

	agentDelegationsCreatedTotal.Inc()
	agentDelegationsActive.Inc()
	agentChainDepth.Observe(float64(delegation.Depth))

	s.recordAudit(ctx, &models.AuditLog{
		EntityType: models.EntityTypeDelegation,
		EntityID:   uuidPtr(delegationID),
		Action:     models.AuditActionCreate,
		Actor:      delegation.UserID,
		Changes: map[string]interface{}{
			"approved_tools":      delegation.ApprovedTools,
			"approved_actions":    delegation.ApprovedActions,
			"max_action_tier":     delegation.MaxActionTier,
			"classification_caps": delegation.ClassificationCaps,
			"purpose":             delegation.Purpose,
			"ttl_seconds":         int(ttl.Seconds()),
		},
		AgentID:          uuidPtr(agentID),
		DelegationID:     uuidPtr(delegationID),
		AgentTrustTier:   int16Ptr(int16(agent.TrustTier)),
		ConversationID:   strPtr(delegation.ConversationID),
		ChainDepth:       int16Ptr(int16(delegation.Depth)),
		ChainAgentIDs:    chainAgentIDsToStrings(delegation.ChainAgentIDs),
		RootDelegationID: uuidPtr(delegation.RootDelegationID),
	})

	return &CreateDelegationResponse{
		DelegationToken:  token,
		DelegationId:     delegationID.String(),
		Depth:            int32(delegation.Depth),
		ExpiresAt:        timestamppb.New(expiresAt),
		RootDelegationId: delegation.RootDelegationID.String(),
	}, nil
}

// RevokeDelegation revokes a delegation and cascades to all children.
func (s *Server) RevokeDelegation(ctx context.Context, delegationID string, reason string) (*RevokeDelegationResponse, error) {
	id, err := uuid.Parse(delegationID)
	if err != nil {
		return nil, fmt.Errorf("invalid delegation_id: %w", err)
	}

	count, revokedIDs, err := s.repo.Delegation.Revoke(ctx, id, reason)
	if err != nil {
		return nil, err
	}

	revokedStrings := make([]string, len(revokedIDs))
	for i, rid := range revokedIDs {
		revokedStrings[i] = rid.String()
	}

	logger.Info("Revoked delegation %s (cascade count: %d, reason: %s)", delegationID, count, reason)

	agentChainRevocationsTotal.Inc()
	agentDelegationsActive.Sub(float64(count))

	actor, _ := extractUserID(ctx)
	s.recordAudit(ctx, &models.AuditLog{
		EntityType: models.EntityTypeDelegation,
		EntityID:   uuidPtr(id),
		Action:     models.AuditActionRevoke,
		Actor:      actor,
		Changes:    map[string]interface{}{"reason": reason},
		Result: map[string]interface{}{
			"revoked_count":          count,
			"revoked_delegation_ids": revokedStrings,
		},
		DelegationID: uuidPtr(id),
	})

	return &RevokeDelegationResponse{
		Success:              true,
		RevokedCount:         int32(count),
		RevokedDelegationIds: revokedStrings,
	}, nil
}

// --- Action Execution ---

// ExecuteAction authorizes and executes an agent action through the double-hop model.
func (s *Server) ExecuteAction(ctx context.Context, req *InternalExecuteActionParams) (*ExecuteActionResponse, error) {
	claims, err := s.validateDelegationToken(req.DelegationToken)
	if err != nil {
		return &ExecuteActionResponse{
			Authorized: false,
			Error:      fmt.Sprintf("invalid delegation token: %v", err),
		}, nil
	}

	delegationID, err := uuid.Parse(claims.DelegationID)
	if err != nil {
		return &ExecuteActionResponse{
			Authorized: false,
			Error:      "invalid delegation_id in token",
		}, nil
	}

	chain, err := s.repo.Delegation.GetChain(ctx, delegationID)
	if err != nil {
		return &ExecuteActionResponse{
			Authorized: false,
			Error:      fmt.Sprintf("failed to resolve delegation chain: %v", err),
		}, nil
	}

	// Validate all tokens in the chain are active
	for _, d := range chain {
		if !d.IsActive() {
			return &ExecuteActionResponse{
				Authorized: false,
				Error:      fmt.Sprintf("delegation %s at depth %d is %s", d.ID, d.Depth, delegationStatusString(d)),
			}, nil
		}
	}

	// Evaluate compound authorization
	startTime := time.Now()
	compound, err := s.evaluateChainAuthorization(ctx, chain, req)
	agentAuthLatency.Observe(time.Since(startTime).Seconds())

	if err != nil {
		agentAuthDecisionsTotal.WithLabelValues("error", "system").Inc()
		return &ExecuteActionResponse{
			Authorized: false,
			Error:      fmt.Sprintf("policy evaluation failed: %v", err),
		}, nil
	}

	if compound.DeniedAtDepth >= 0 {
		agentAuthDecisionsTotal.WithLabelValues("deny", compound.DeniedPrincipal).Inc()
		agentActionsTotal.WithLabelValues(req.ToolName, req.ActionTier.String(), "deny").Inc()
		agentChainDeniedAtDepth.WithLabelValues(strconv.Itoa(compound.DeniedAtDepth)).Inc()

		s.recordExecutionAudit(ctx, chain, claims, req, compound, "deny")

		return &ExecuteActionResponse{
			Authorized: false,
			Decision:   internalToProtoCompound(compound),
			Error:      fmt.Sprintf("denied at depth %d by %s", compound.DeniedAtDepth, compound.DeniedPrincipal),
		}, nil
	}

	agentAuthDecisionsTotal.WithLabelValues("allow", "").Inc()
	agentActionsTotal.WithLabelValues(req.ToolName, req.ActionTier.String(), "allow").Inc()

	logger.Info("Action authorized: user=%s chain_depth=%d tool=%s action=%s",
		claims.Subject, len(chain), req.ToolName, req.Action)

	s.recordExecutionAudit(ctx, chain, claims, req, compound, "allow")

	// Forward the authorized request to the target service
	var responsePayload []byte
	if req.TargetService != "" && req.Method != "" && len(req.Payload) > 0 {
		forwarded, err := s.proxy.Forward(ctx, req.TargetService, req.Method, req.Payload)
		if err != nil {
			return &ExecuteActionResponse{
				Authorized: true,
				Decision:   internalToProtoCompound(compound),
				Error:      fmt.Sprintf("authorized but forwarding failed: %v", err),
			}, nil
		}
		responsePayload = forwarded
	}

	return &ExecuteActionResponse{
		Authorized: true,
		Decision:   internalToProtoCompound(compound),
		Payload:    responsePayload,
	}, nil
}

// ValidateActionPlan validates a set of planned actions against the delegation scope.
func (s *Server) ValidateActionPlan(ctx context.Context, delegationIDStr string, actions []InternalPlannedAction) (*ValidateActionPlanResponse, error) {
	id, err := uuid.Parse(delegationIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid delegation_id: %w", err)
	}

	delegation, err := s.repo.Delegation.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	agent, err := s.repo.Agent.GetByID(ctx, delegation.AgentID)
	if err != nil {
		return nil, fmt.Errorf("agent lookup failed: %w", err)
	}

	results := make([]*ActionValidationResult, len(actions))
	allValid := true

	for i, action := range actions {
		result := &ActionValidationResult{
			ActionIndex: int32(i),
			Valid:       true,
		}

		if !agent.HasTool(action.ToolName) {
			result.Valid = false
			result.Reason = fmt.Sprintf("tool %q not in agent allowed_tools", action.ToolName)
			allValid = false
			agentValidationFailuresTotal.WithLabelValues("tool_not_allowed").Inc()
		}

		if result.Valid && !delegation.HasTool(action.ToolName) {
			result.Valid = false
			result.Reason = fmt.Sprintf("tool %q not in delegation approved_tools", action.ToolName)
			allValid = false
			agentValidationFailuresTotal.WithLabelValues("tool_not_in_scope").Inc()
		}

		actualTier := assessActionTier(action.Action)
		result.ActualTier = ActionTier(actualTier)
		if actualTier != action.DeclaredTier {
			result.TierMismatch = true
			agentValidationFailuresTotal.WithLabelValues("tier_mismatch").Inc()
		}

		if result.Valid && !delegation.HasActionTier(actualTier) {
			result.Valid = false
			result.Reason = fmt.Sprintf("action tier %s exceeds delegation max_action_tier %s",
				actualTier.String(), delegation.MaxActionTier.String())
			allValid = false
			agentValidationFailuresTotal.WithLabelValues("tier_exceeded").Inc()
		}

		results[i] = result
	}

	return &ValidateActionPlanResponse{
		Valid:   allValid,
		Results: results,
	}, nil
}

// GetDelegationChain returns the full chain for inspection.
func (s *Server) GetDelegationChain(ctx context.Context, delegationIDStr string) (*GetDelegationChainResponse, error) {
	id, err := uuid.Parse(delegationIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid delegation_id: %w", err)
	}

	chain, err := s.repo.Delegation.GetChain(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, models.ErrDelegationNotFound
	}

	links := make([]*ChainLink, len(chain))
	for i, d := range chain {
		agent, err := s.repo.Agent.GetByID(ctx, d.AgentID)
		if err != nil {
			return nil, fmt.Errorf("agent lookup for chain hop %d failed: %w", i, err)
		}
		links[i] = &ChainLink{
			DelegationId:       d.ID.String(),
			AgentId:            d.AgentID.String(),
			AgentName:          agent.Name,
			TrustTier:          AgentTrustTier(agent.TrustTier),
			Depth:              int32(d.Depth),
			MaxActionTier:      ActionTier(d.MaxActionTier),
			ClassificationCaps: d.ClassificationCaps,
			ApprovedTools:      d.ApprovedTools,
			ExpiresAt:          timestamppb.New(d.ExpiresAt),
			Revoked:            d.Revoked,
		}
	}

	return &GetDelegationChainResponse{
		RootDelegationId: chain[0].RootDelegationID.String(),
		UserId:           chain[0].UserID,
		Chain:            links,
		TotalDepth:       int32(len(chain)),
	}, nil
}

// --- Agent Registry ---

// RegisterAgent registers a new agent.
func (s *Server) RegisterAgent(ctx context.Context, req *models.CreateAgentRequest, createdBy string) (*models.Agent, string, error) {
	agentID := uuid.New()
	clientID := fmt.Sprintf("agent_%s", agentID.String()[:8])
	clientSecret := generateClientSecret()
	hashedSecret := hashSecret(clientSecret)

	if req.AllowedActions == nil {
		req.AllowedActions = []models.ActionTier{models.ActionTierReasoning, models.ActionTierReadOnly}
	}

	agent := &models.Agent{
		ID:              agentID,
		Name:            req.Name,
		Description:     req.Description,
		Provider:        req.Provider,
		ModelIdentifier: req.ModelIdentifier,
		TrustTier:       req.TrustTier,
		AllowedTools:    req.AllowedTools,
		AllowedActions:  req.AllowedActions,
		TenantID:        req.TenantID,
		CertStatus:      models.AgentCertStatusPending,
		ClientID:        clientID,
		ClientSecret:    hashedSecret,
		Metadata:        req.Metadata,
		Enabled:         true,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
		CreatedBy:       createdBy,
	}

	if err := s.repo.Agent.Create(ctx, agent); err != nil {
		return nil, "", fmt.Errorf("failed to register agent: %w", err)
	}

	logger.Info("Registered agent %s (name=%s, provider=%s, trust_tier=%s)",
		agentID, req.Name, req.Provider, req.TrustTier.String())

	return agent, clientSecret, nil
}

// SuspendAgent suspends an agent and revokes all active delegations.
func (s *Server) SuspendAgent(ctx context.Context, agentID string, reason string) (int, error) {
	id, err := uuid.Parse(agentID)
	if err != nil {
		return 0, fmt.Errorf("invalid agent_id: %w", err)
	}

	agent, err := s.repo.Agent.GetByID(ctx, id)
	if err != nil {
		return 0, err
	}

	agent.CertStatus = models.AgentCertStatusSuspended
	agent.Enabled = false
	if err := s.repo.Agent.Update(ctx, agent); err != nil {
		return 0, fmt.Errorf("failed to suspend agent: %w", err)
	}

	revokedCount, err := s.repo.Delegation.RevokeByAgent(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke agent delegations: %w", err)
	}

	logger.Info("Suspended agent %s (reason: %s, revoked delegations: %d)", agentID, reason, revokedCount)

	actor, _ := extractUserID(ctx)
	s.recordAudit(ctx, &models.AuditLog{
		EntityType: models.EntityTypeAgent,
		EntityID:   uuidPtr(id),
		Action:     models.AuditActionSuspend,
		Actor:      actor,
		Changes:    map[string]interface{}{"reason": reason},
		Result:     map[string]interface{}{"revoked_delegations": revokedCount},
		AgentID:    uuidPtr(id),
	})

	return revokedCount, nil
}

// --- Internal Helpers ---

// recordAudit persists an audit row best-effort. Failures are logged at WARN
// level and do NOT propagate back to the caller — the request that triggered
// the audit attempt has already succeeded (or already failed) by the time we
// reach here. Auditing must never break the request flow.
func (s *Server) recordAudit(ctx context.Context, log *models.AuditLog) {
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	if log.Timestamp.IsZero() {
		log.Timestamp = time.Now()
	}
	if err := s.repo.Audit.Create(ctx, log); err != nil {
		logger.Warn("audit write failed (action=%s entity=%s): %v", log.Action, log.EntityType, err)
	}
}

// strPtr returns a pointer to the given string (helper for optional audit fields).
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// int16Ptr returns a pointer to the given int16 (helper for optional audit fields).
func int16Ptr(v int16) *int16 { return &v }

// uuidPtr returns a pointer to the given UUID, or nil if it's the zero value.
func uuidPtr(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

// executionModeString returns a stable, human-readable name for the execution
// mode. ExecutionMode is an int alias without a String() method.
func executionModeString(m models.ExecutionMode) string {
	switch m {
	case models.ExecutionModeDelegated:
		return "DELEGATED"
	case models.ExecutionModeSystem:
		return "SYSTEM"
	default:
		return ""
	}
}

// chainAgentIDsToStrings converts a delegation's chain_agent_ids to a string slice.
func chainAgentIDsToStrings(ids []uuid.UUID) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// recordExecutionAudit writes a single audit row for an ExecuteAction call.
// outcome is "allow" or "deny".
//
// Chain semantics:
//   - For deny outcomes, the denied hop is at compound.DeniedAtDepth. We mark
//     agent_decision / delegation_decision based on that hop's result.
//   - For allow outcomes, all hops are ALLOW (loop terminates only on denial).
func (s *Server) recordExecutionAudit(
	ctx context.Context,
	chain []*models.Delegation,
	claims *models.DelegationTokenClaims,
	req *InternalExecuteActionParams,
	compound *InternalCompoundDecisionResult,
	outcome string,
) {
	if len(chain) == 0 {
		return
	}
	leaf := chain[len(chain)-1]

	var agentDecision, delegationDecision *string
	if outcome == "allow" {
		a := "allow"
		agentDecision = &a
		delegationDecision = &a
	} else {
		// Find the denied hop and surface its decisions.
		for _, hop := range compound.ChainDecisions {
			if hop.AgentDecision == "DENY" {
				v := "deny"
				agentDecision = &v
			} else if hop.AgentDecision == "ALLOW" {
				v := "allow"
				agentDecision = &v
			}
			if hop.DelegationDecision == "DENY" {
				v := "deny"
				delegationDecision = &v
			} else if hop.DelegationDecision == "ALLOW" {
				v := "allow"
				delegationDecision = &v
			}
			if hop.AgentDecision == "DENY" || hop.DelegationDecision == "DENY" {
				break
			}
		}
	}

	var deniedAtDepth *int16
	var deniedPrincipal *string
	if compound.DeniedAtDepth >= 0 {
		d := int16(compound.DeniedAtDepth)
		deniedAtDepth = &d
		deniedPrincipal = strPtr(compound.DeniedPrincipal)
	}

	s.recordAudit(ctx, &models.AuditLog{
		EntityType: models.EntityTypeDelegation,
		EntityID:   uuidPtr(leaf.ID),
		Action:     models.AuditActionAuthorize,
		Actor:      claims.Subject,
		Changes: map[string]interface{}{
			"target_service": req.TargetService,
			"method":         req.Method,
			"action":         req.Action,
			"resource":       req.ResourceAttributes,
		},
		Result: map[string]interface{}{
			"outcome": outcome,
		},
		AgentID:            uuidPtr(leaf.AgentID),
		DelegationID:       uuidPtr(leaf.ID),
		ToolName:           strPtr(req.ToolName),
		ActionTier:         int16Ptr(int16(req.ActionTier)),
		ExecutionMode:      strPtr(executionModeString(req.ExecutionMode)),
		ConversationID:     strPtr(leaf.ConversationID),
		AgentDecision:      agentDecision,
		DelegationDecision: delegationDecision,
		ChainDepth:         int16Ptr(int16(len(chain))),
		ChainAgentIDs:      chainAgentIDsToStrings(leaf.ChainAgentIDs),
		RootDelegationID:   uuidPtr(leaf.RootDelegationID),
		DeniedAtDepth:      deniedAtDepth,
		DeniedPrincipal:    deniedPrincipal,
	})
}

func (s *Server) mintDelegationToken(delegation *models.Delegation, agent *models.Agent) (string, error) {
	chainAgentStrings := make([]string, len(delegation.ChainAgentIDs))
	for i, id := range delegation.ChainAgentIDs {
		chainAgentStrings[i] = id.String()
	}

	approvedActionsInts := make([]int, len(delegation.ApprovedActions))
	for i, a := range delegation.ApprovedActions {
		approvedActionsInts[i] = int(a)
	}

	parentDelegationID := ""
	if delegation.ParentDelegationID != nil {
		parentDelegationID = delegation.ParentDelegationID.String()
	}

	claims := jwt.MapClaims{
		"sub":                  delegation.UserID,
		"iat":                  delegation.CreatedAt.Unix(),
		"exp":                  delegation.ExpiresAt.Unix(),
		"agent_id":             agent.ID.String(),
		"agent_trust_tier":     int(agent.TrustTier),
		"tenant_id":            delegation.TenantID,
		"delegation_id":        delegation.ID.String(),
		"approved_tools":       delegation.ApprovedTools,
		"approved_actions":     approvedActionsInts,
		"max_action_tier":      int(delegation.MaxActionTier),
		"classification_caps":  delegation.ClassificationCaps,
		"resource_constraints": delegation.ResourceConstraints,
		"purpose":              delegation.Purpose,
		"conversation_id":      delegation.ConversationID,
		"parent_delegation_id": parentDelegationID,
		"root_delegation_id":   delegation.RootDelegationID.String(),
		"depth":                delegation.Depth,
		"chain_agent_ids":      chainAgentStrings,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.signingKey)
}

func (s *Server) validateDelegationToken(tokenString string) (*models.DelegationTokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signingKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, models.ErrDelegationInvalidToken
	}

	claimsJSON, err := json.Marshal(mapClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	var claims models.DelegationTokenClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	return &claims, nil
}

func (s *Server) evaluateChainAuthorization(ctx context.Context, chain []*models.Delegation, req *InternalExecuteActionParams) (*InternalCompoundDecisionResult, error) {
	result := &InternalCompoundDecisionResult{
		DeniedAtDepth:  -1,
		ChainDecisions: make([]InternalChainHopDecision, len(chain)),
	}

	for i, delegation := range chain {
		agent, err := s.repo.Agent.GetByID(ctx, delegation.AgentID)
		if err != nil {
			return nil, fmt.Errorf("agent lookup for depth %d failed: %w", i, err)
		}

		hopResult := InternalChainHopDecision{
			Depth:        delegation.Depth,
			AgentID:      delegation.AgentID.String(),
			DelegationID: delegation.ID.String(),
		}

		agentAllowed, agentReason := s.evaluateAgentAuth(agent, req)
		if agentAllowed {
			hopResult.AgentDecision = "ALLOW"
		} else {
			hopResult.AgentDecision = "DENY"
			hopResult.AgentReason = agentReason
			if result.DeniedAtDepth < 0 {
				result.DeniedAtDepth = delegation.Depth
				result.DeniedPrincipal = fmt.Sprintf("agent:%s", agent.ID)
			}
		}

		delegationAllowed, delegationReason := s.evaluateDelegationScope(delegation, req)
		if delegationAllowed {
			hopResult.DelegationDecision = "ALLOW"
		} else {
			hopResult.DelegationDecision = "DENY"
			hopResult.DelegationReason = delegationReason
			if result.DeniedAtDepth < 0 {
				result.DeniedAtDepth = delegation.Depth
				result.DeniedPrincipal = fmt.Sprintf("delegation:%s", delegation.ID)
			}
		}

		result.ChainDecisions[i] = hopResult

		if result.DeniedAtDepth >= 0 {
			break
		}
	}

	return result, nil
}

func (s *Server) evaluateAgentAuth(agent *models.Agent, req *InternalExecuteActionParams) (bool, string) {
	requiredTier := requiredTrustTier(req.ActionTier)
	if agent.TrustTier < requiredTier {
		return false, fmt.Sprintf("agent trust tier %s insufficient for action tier %s (requires %s)",
			agent.TrustTier.String(), req.ActionTier.String(), requiredTier.String())
	}

	if req.ToolName != "" && !agent.HasTool(req.ToolName) {
		return false, fmt.Sprintf("tool %q not in agent allowed_tools", req.ToolName)
	}

	return true, ""
}

func (s *Server) evaluateDelegationScope(delegation *models.Delegation, req *InternalExecuteActionParams) (bool, string) {
	if req.ActionTier > delegation.MaxActionTier {
		return false, fmt.Sprintf("action tier %s exceeds delegation max_action_tier %s",
			req.ActionTier.String(), delegation.MaxActionTier.String())
	}

	if req.ToolName != "" && !delegation.HasTool(req.ToolName) {
		return false, fmt.Sprintf("tool %q not in delegation approved_tools", req.ToolName)
	}

	if allowed, reason := checkClassificationCap(delegation.ClassificationCaps, req.ResourceAttributes); !allowed {
		return false, reason
	}

	return true, ""
}

// classificationLevels mirrors the canonical hierarchies in pkg/cedar/hierarchy.go
// (NATOHierarchy, CommercialHierarchy). Kept inline to avoid coupling the
// agent-gateway runtime to the cedar policy-construction package. Update both
// in lockstep if levels change.
var classificationLevels = map[string][]string{
	"nato":       {"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP-SECRET"},
	"commercial": {"PUBLIC", "INTERNAL", "CONFIDENTIAL-COMMERCIAL", "RESTRICTED-COMMERCIAL", "HIGHLY-CONFIDENTIAL"},
}

// classificationIndex returns the integer rank of a level within a hierarchy
// (case-insensitive). Returns -1 if the hierarchy or level is unknown.
func classificationIndex(hierarchy, level string) int {
	levels, ok := classificationLevels[strings.ToLower(hierarchy)]
	if !ok {
		return -1
	}
	for i, lvl := range levels {
		if strings.EqualFold(lvl, level) {
			return i
		}
	}
	return -1
}

// checkClassificationCap enforces a delegation's per-hierarchy classification
// caps against the resource being accessed.
//
// Semantics:
//   - No caps on the delegation → allow.
//   - Resource has no classification declared → allow (caller is not making a
//     classification claim).
//   - Classification declared but no hierarchy → DENY (ambiguity = deny; an
//     attacker mustn't bypass caps by omitting the hierarchy attribute).
//   - Cap exists for the resource's hierarchy → enforce
//     resource_level ≤ cap_level using the canonical hierarchy ordering.
//   - No cap for the resource's hierarchy → allow (delegation didn't constrain
//     that hierarchy).
//
// Unknown hierarchy or level names produce a DENY with an explanatory reason
// rather than silently allowing.
func checkClassificationCap(caps map[string]string, resourceAttrs map[string]string) (bool, string) {
	if len(caps) == 0 {
		return true, ""
	}

	resourceLevel, hasLevel := resourceAttrs["classification"]
	resourceHierarchy, hasHierarchy := resourceAttrs["hierarchy"]

	if !hasLevel {
		return true, ""
	}
	if !hasHierarchy {
		return false, "resource classification declared without a hierarchy attribute (ambiguous)"
	}

	capLevel, hasCap := caps[strings.ToLower(resourceHierarchy)]
	if !hasCap {
		// Try original case as fallback (caps are stored as-supplied by caller).
		capLevel, hasCap = caps[resourceHierarchy]
	}
	if !hasCap {
		return true, ""
	}

	resourceIdx := classificationIndex(resourceHierarchy, resourceLevel)
	if resourceIdx < 0 {
		return false, fmt.Sprintf("unknown classification level %q for hierarchy %q",
			resourceLevel, resourceHierarchy)
	}
	capIdx := classificationIndex(resourceHierarchy, capLevel)
	if capIdx < 0 {
		return false, fmt.Sprintf("delegation cap %q is not a known level in hierarchy %q",
			capLevel, resourceHierarchy)
	}

	if resourceIdx > capIdx {
		return false, fmt.Sprintf("resource classification %s exceeds delegation cap %s (hierarchy %q)",
			resourceLevel, capLevel, resourceHierarchy)
	}
	return true, ""
}

// --- Conversion Helpers ---

func internalToProtoCompound(internal *InternalCompoundDecisionResult) *CompoundDecision {
	if internal == nil {
		return nil
	}
	compound := &CompoundDecision{
		UserDecision:    decisionFromString(internal.UserDecision),
		UserReason:      internal.UserReason,
		DeniedAtDepth:   int32(internal.DeniedAtDepth),
		DeniedPrincipal: internal.DeniedPrincipal,
	}
	for _, hop := range internal.ChainDecisions {
		compound.ChainDecisions = append(compound.ChainDecisions, &ChainHopDecision{
			Depth:              int32(hop.Depth),
			AgentId:            hop.AgentID,
			DelegationId:       hop.DelegationID,
			AgentDecision:      decisionFromString(hop.AgentDecision),
			AgentReason:        hop.AgentReason,
			DelegationDecision: decisionFromString(hop.DelegationDecision),
			DelegationReason:   hop.DelegationReason,
		})
	}
	return compound
}

func decisionFromString(s string) Decision {
	switch s {
	case "ALLOW":
		return Decision_DECISION_ALLOW
	case "DENY":
		return Decision_DECISION_DENY
	case "CONDITIONAL":
		return Decision_DECISION_CONDITIONAL
	default:
		return Decision_DECISION_UNSPECIFIED
	}
}

// --- Utility Functions ---

func requiredTrustTier(actionTier models.ActionTier) models.AgentTrustTier {
	switch {
	case actionTier <= models.ActionTierReadOnly:
		return models.TrustTierUnverified
	case actionTier == models.ActionTierInternalModify:
		return models.TrustTierRegistered
	case actionTier == models.ActionTierExternalComms:
		return models.TrustTierCertified
	case actionTier == models.ActionTierDestructive:
		return models.TrustTierPlatformTrusted
	default:
		return models.TrustTierPlatformTrusted
	}
}

func assessActionTier(action string) models.ActionTier {
	switch action {
	case "read", "get", "list", "query", "search":
		return models.ActionTierReadOnly
	case "write", "create", "update", "modify", "patch":
		return models.ActionTierInternalModify
	case "send", "email", "notify", "webhook", "publish":
		return models.ActionTierExternalComms
	case "delete", "destroy", "drop", "revoke", "transfer", "execute":
		return models.ActionTierDestructive
	default:
		return models.ActionTierReasoning
	}
}

func generateClientSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashSecret(secret string) []byte {
	h := hmac.New(sha256.New, []byte("stratium-agent-secret"))
	h.Write([]byte(secret))
	return h.Sum(nil)
}

func delegationStatusString(d *models.Delegation) string {
	if d.Revoked {
		return "revoked"
	}
	if d.IsExpired() {
		return "expired"
	}
	return "active"
}
