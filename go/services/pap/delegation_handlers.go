package pap

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"stratium/features"
	"stratium/pkg/classification"
	"stratium/pkg/models"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// registerDelegationRoutes adds delegation management REST routes to the PAP server.
// These provide HTTP access to delegation operations — used by Codex hooks that
// can't call the Agent Gateway's gRPC directly from sandboxed environments.
func (s *Server) registerDelegationRoutes(v1 *gin.RouterGroup) {
	if !features.ShouldEnableAgentAuth() {
		return
	}

	delegations := v1.Group("/delegations")
	{
		delegations.POST("", s.createDelegation)
		delegations.GET("", s.listDelegations)
		delegations.DELETE("/:id", s.revokeDelegation)
	}

	// Authorization check endpoint — used by PreToolUse hooks
	v1.POST("/actions/check", s.checkAction)
}

// createDelegationRequest is the JSON body for POST /api/v1/delegations
type createDelegationRequest struct {
	AgentID            string            `json:"agent_id" binding:"required"`
	ApprovedTools      []string          `json:"approved_tools" binding:"required"`
	ApprovedActions    []int             `json:"approved_actions"`
	MaxActionTier      int               `json:"max_action_tier"`
	ClassificationCaps map[string]string `json:"classification_caps"`
	Purpose            string            `json:"purpose" binding:"required"`
	TTLSeconds         int               `json:"ttl_seconds"`
	ConversationID     string            `json:"conversation_id"`
}

// createDelegation creates a root delegation token for an agent.
// POST /api/v1/delegations
func (s *Server) createDelegation(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	var req createDelegationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	agentID, err := uuid.Parse(req.AgentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent_id"})
		return
	}

	// Verify agent exists and is active
	agent, err := s.repo.Agent.GetByID(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	if !agent.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "agent is disabled"})
		return
	}

	// Determine TTL
	ttl := 15 * time.Minute // default
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}
	maxTTL := 24 * time.Hour
	if ttl > maxTTL {
		ttl = maxTTL
	}

	now := time.Now()
	expiresAt := now.Add(ttl)
	delegationID := uuid.New()

	// Build approved actions
	approvedActions := req.ApprovedActions
	if len(approvedActions) == 0 {
		// Default: all tiers up to max
		for i := 0; i <= req.MaxActionTier; i++ {
			approvedActions = append(approvedActions, i)
		}
	}

	// Mint delegation JWT (HMAC-SHA256, same signing key as Agent Gateway)
	signingKey := []byte(s.getDelegationSigningKey())
	if len(signingKey) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delegation signing not configured"})
		return
	}

	claims := jwt.MapClaims{
		"sub":                  actor,
		"agent_id":             agentID.String(),
		"agent_trust_tier":     int(agent.TrustTier),
		"tenant_id":            agent.TenantID,
		"delegation_id":        delegationID.String(),
		"approved_tools":       req.ApprovedTools,
		"approved_actions":     approvedActions,
		"max_action_tier":      req.MaxActionTier,
		"classification_caps":  req.ClassificationCaps,
		"resource_constraints": nil,
		"purpose":              req.Purpose,
		"conversation_id":      req.ConversationID,
		"parent_delegation_id": "",
		"root_delegation_id":   delegationID.String(),
		"depth":                0,
		"chain_agent_ids":      []string{agentID.String()},
		"iat":                  now.Unix(),
		"exp":                  expiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to sign delegation token"})
		return
	}

	// Persist delegation to database
	delegation := &models.Delegation{
		ID:                 delegationID,
		UserID:             actor,
		AgentID:            agentID,
		TenantID:           agent.TenantID,
		ConversationID:     req.ConversationID,
		ApprovedTools:      req.ApprovedTools,
		ApprovedActions:    toActionTiers(approvedActions),
		MaxActionTier:      models.ActionTier(req.MaxActionTier),
		ClassificationCaps: req.ClassificationCaps,
		Purpose:            req.Purpose,
		ExpiresAt:          expiresAt,
		RootDelegationID:   delegationID,
		Depth:              0,
		ChainAgentIDs:      []uuid.UUID{agentID},
	}

	if err := s.repo.Delegation.Create(c.Request.Context(), delegation); err != nil {
		logger.Error("Failed to persist delegation: %v", err)
		// Token is still valid even if persistence fails — return it
	}

	c.JSON(http.StatusCreated, gin.H{
		"delegation_token":   tokenString,
		"delegation_id":      delegationID.String(),
		"expires_at":         expiresAt.Format(time.RFC3339),
		"root_delegation_id": delegationID.String(),
		"depth":              0,
	})
}

// checkActionRequest is the JSON body for POST /api/v1/actions/check
type checkActionRequest struct {
	DelegationToken        string `json:"delegation_token" binding:"required"`
	ToolName               string `json:"tool_name" binding:"required"`
	Action                 string `json:"action" binding:"required"`
	ActionTier             int    `json:"action_tier"`
	ResourceID             string `json:"resource_id"`
	ResourceClassification string `json:"resource_classification"`
	ResourceHierarchy      string `json:"resource_hierarchy"`
}

// checkAction validates an action against a delegation's scope.
// POST /api/v1/actions/check
// This is the REST equivalent of ExecuteAction gRPC — used by Codex PreToolUse hooks.
func (s *Server) checkAction(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	var req checkActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"authorized": false, "error": err.Error()})
		return
	}

	// Parse and verify the delegation token
	signingKey := []byte(s.getDelegationSigningKey())
	token, err := jwt.Parse(req.DelegationToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return signingKey, nil
	})
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"error":      fmt.Sprintf("invalid delegation token: %v", err),
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"error":      "invalid token claims",
		})
		return
	}

	// Check if delegation is revoked
	delegationID := getClaimString(claims, "delegation_id")
	if delegationID != "" {
		if delID, err := uuid.Parse(delegationID); err == nil {
			if del, err := s.repo.Delegation.GetByID(c.Request.Context(), delID); err == nil {
				if del.Revoked {
					c.JSON(http.StatusOK, gin.H{
						"authorized": false,
						"error":      "delegation has been revoked",
						"decision": gin.H{
							"delegation_decision": "DENY",
							"delegation_reason":   "delegation revoked",
						},
					})
					return
				}
			}
		}
	}

	// Check tool is in approved list
	approvedTools := getClaimStringSlice(claims, "approved_tools")
	if len(approvedTools) > 0 {
		toolAllowed := false
		for _, t := range approvedTools {
			if t == req.ToolName {
				toolAllowed = true
				break
			}
		}
		if !toolAllowed {
			c.JSON(http.StatusOK, gin.H{
				"authorized": false,
				"decision": gin.H{
					"delegation_decision": "DENY",
					"delegation_reason":   fmt.Sprintf("tool '%s' not in approved_tools %v", req.ToolName, approvedTools),
				},
			})
			return
		}
	}

	// Check action tier is within max
	maxTier := getClaimInt(claims, "max_action_tier")
	if req.ActionTier > maxTier {
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"decision": gin.H{
				"delegation_decision": "DENY",
				"delegation_reason":   fmt.Sprintf("action_tier %d exceeds max_action_tier %d", req.ActionTier, maxTier),
			},
		})
		return
	}

	// Check agent trust tier allows this action tier
	agentTrustTier := getClaimInt(claims, "agent_trust_tier")
	requiredTrust := requiredTrustForAction(req.ActionTier)
	if agentTrustTier < requiredTrust {
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"decision": gin.H{
				"agent_decision": "DENY",
				"agent_reason":   fmt.Sprintf("agent trust_tier %d insufficient for action_tier %d (requires %d)", agentTrustTier, req.ActionTier, requiredTrust),
			},
		})
		return
	}

	// Classification caps — fail-closed, hierarchy-aware (shared canonical logic).
	if allowed, reason := classification.CheckCap(
		getClaimStringMap(claims, "classification_caps"),
		map[string]string{
			"classification": req.ResourceClassification,
			"hierarchy":      req.ResourceHierarchy,
		},
	); !allowed {
		c.JSON(http.StatusOK, gin.H{
			"authorized": false,
			"decision": gin.H{
				"delegation_decision": "DENY",
				"delegation_reason":   reason,
			},
		})
		return
	}

	// All checks passed
	c.JSON(http.StatusOK, gin.H{
		"authorized": true,
		"decision": gin.H{
			"agent_decision":      "ALLOW",
			"delegation_decision": "ALLOW",
		},
	})
}

// listDelegations lists active delegations for the current user.
// GET /api/v1/delegations
func (s *Server) listDelegations(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	actor, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// ListActive requires agentID — use zero UUID to list all for this user
	delegations, err := s.repo.Delegation.ListActive(c.Request.Context(), actor, uuid.Nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list delegations"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"delegations": delegations,
		"total":       len(delegations),
	})
}

// revokeDelegation revokes a delegation and cascades to children.
// DELETE /api/v1/delegations/:id
func (s *Server) revokeDelegation(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid delegation ID"})
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)
	if body.Reason == "" {
		body.Reason = "revoked via REST API"
	}

	count, _, err := s.repo.Delegation.Revoke(c.Request.Context(), id, body.Reason)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "delegation not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"revoked":       true,
		"revoked_count": count,
	})
}

// --- Helpers ---

func (s *Server) getDelegationSigningKey() string {
	// Read from the same config the Agent Gateway uses
	if key := s.getConfigValue("agent_gateway.delegation_signing_key"); key != "" {
		return key
	}
	return ""
}

func (s *Server) getConfigValue(key string) string {
	// Access via environment variable (same as Agent Gateway)
	switch key {
	case "agent_gateway.delegation_signing_key":
		return getEnvOrDefault("STRATIUM_AGENT_GATEWAY_DELEGATION_SIGNING_KEY", "")
	default:
		return ""
	}
}

func getEnvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func requiredTrustForAction(actionTier int) int {
	switch {
	case actionTier <= 1:
		return 0
	case actionTier == 2:
		return 1
	case actionTier == 3:
		return 2
	case actionTier >= 4:
		return 3
	default:
		return 0
	}
}

func toActionTiers(ints []int) []models.ActionTier {
	tiers := make([]models.ActionTier, len(ints))
	for i, v := range ints {
		tiers[i] = models.ActionTier(v)
	}
	return tiers
}

func getClaimString(claims jwt.MapClaims, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func getClaimInt(claims jwt.MapClaims, key string) int {
	if v, ok := claims[key].(float64); ok {
		return int(v)
	}
	return 0
}

func getClaimStringSlice(claims jwt.MapClaims, key string) []string {
	arr, ok := claims[key].([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func getClaimStringMap(claims jwt.MapClaims, key string) map[string]string {
	m, ok := claims[key].(map[string]interface{})
	if !ok {
		return nil
	}
	result := make(map[string]string)
	for k, v := range m {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}
