package pap

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"stratium/features"
	"stratium/pkg/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// registerAgentRoutes adds agent registry routes to the PAP server.
// These are only available when the agent-auth feature is enabled.
func (s *Server) registerAgentRoutes(v1 *gin.RouterGroup) {
	if !features.ShouldEnableAgentAuth() {
		return
	}

	agents := v1.Group("/agents")
	{
		agents.POST("", s.createAgent)
		agents.GET("", s.listAgents)
		agents.GET("/:id", s.getAgent)
		agents.PUT("/:id", s.updateAgent)
		agents.DELETE("/:id", s.deleteAgent)
		agents.POST("/:id/suspend", s.suspendAgent)
		agents.POST("/:id/reinstate", s.reinstateAgent)
	}
}

// createAgent registers a new agent (admin-only)
func (s *Server) createAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	var req models.CreateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	actor, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Generate credentials
	agentID := uuid.New()
	clientID := "agent_" + agentID.String()[:8]
	clientSecret := generateSecureToken()
	hashedSecret := hashClientSecret(clientSecret)

	if req.AllowedActions == nil {
		req.AllowedActions = []models.ActionTier{models.ActionTierReasoning, models.ActionTierReadOnly}
	}
	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
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
		CreatedBy:       actor,
	}

	if err := s.repo.Agent.Create(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create agent"})
		return
	}

	// Log audit
	s.logAgentAudit(c, models.AuditActionCreate, &agentID, actor)

	c.JSON(http.StatusCreated, gin.H{
		"agent_id":      agent.ID.String(),
		"client_id":     clientID,
		"client_secret": clientSecret, // Only shown once
		"created_at":    agent.CreatedAt,
	})
}

// getAgent retrieves an agent by ID
func (s *Server) getAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	agent, err := s.repo.Agent.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	c.JSON(http.StatusOK, agent)
}

// listAgents retrieves agents with optional filtering
func (s *Server) listAgents(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	var req models.ListAgentsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Limit <= 0 || req.Limit > 100 {
		req.Limit = 50
	}

	agents, err := s.repo.Agent.List(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list agents"})
		return
	}

	count, _ := s.repo.Agent.Count(c.Request.Context(), &req)

	c.JSON(http.StatusOK, gin.H{
		"agents":      agents,
		"total_count": count,
	})
}

// updateAgent updates an existing agent
func (s *Server) updateAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	agent, err := s.repo.Agent.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var req models.UpdateAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil {
		agent.Name = *req.Name
	}
	if req.Description != nil {
		agent.Description = *req.Description
	}
	if req.TrustTier != nil {
		agent.TrustTier = *req.TrustTier
	}
	if req.AllowedTools != nil {
		agent.AllowedTools = req.AllowedTools
	}
	if req.AllowedActions != nil {
		agent.AllowedActions = req.AllowedActions
	}
	if req.Metadata != nil {
		agent.Metadata = req.Metadata
	}
	if req.Enabled != nil {
		agent.Enabled = *req.Enabled
	}

	if err := s.repo.Agent.Update(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update agent"})
		return
	}

	actor, _ := s.getUserFromContext(c)
	s.logAgentAudit(c, models.AuditActionUpdate, &id, actor)

	c.JSON(http.StatusOK, agent)
}

// deleteAgent removes an agent
func (s *Server) deleteAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	if err := s.repo.Agent.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	actor, _ := s.getUserFromContext(c)
	s.logAgentAudit(c, models.AuditActionDelete, &id, actor)

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// suspendAgent suspends an agent and revokes all active delegations
func (s *Server) suspendAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.ShouldBindJSON(&body)

	agent, err := s.repo.Agent.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	agent.CertStatus = models.AgentCertStatusSuspended
	agent.Enabled = false
	if err := s.repo.Agent.Update(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to suspend agent"})
		return
	}

	revokedCount, err := s.repo.Delegation.RevokeByAgent(c.Request.Context(), id)
	if err != nil {
		logger.Error("Failed to revoke delegations for suspended agent %s: %v", id, err)
	}

	actor, _ := s.getUserFromContext(c)
	s.logAgentAudit(c, models.AuditActionUpdate, &id, actor)

	c.JSON(http.StatusOK, gin.H{
		"success":              true,
		"revoked_delegations": revokedCount,
	})
}

// reinstateAgent reinstates a suspended agent
func (s *Server) reinstateAgent(c *gin.Context) {
	if !features.ShouldEnableAgentAuth() {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "agent authorization is not enabled"})
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent ID"})
		return
	}

	agent, err := s.repo.Agent.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	if agent.CertStatus != models.AgentCertStatusSuspended {
		c.JSON(http.StatusBadRequest, gin.H{"error": "agent is not suspended"})
		return
	}

	agent.CertStatus = models.AgentCertStatusPending
	agent.Enabled = true
	if err := s.repo.Agent.Update(c.Request.Context(), agent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reinstate agent"})
		return
	}

	actor, _ := s.getUserFromContext(c)
	s.logAgentAudit(c, models.AuditActionUpdate, &id, actor)

	c.JSON(http.StatusOK, gin.H{"success": true})
}

// --- Helpers ---

func (s *Server) logAgentAudit(c *gin.Context, action models.AuditAction, agentID *uuid.UUID, actor string) {
	entityType := models.EntityType("agent")
	auditReq := &models.CreateAuditLogRequest{
		EntityType: entityType,
		EntityID:   agentID,
		Action:     action,
		Actor:      actor,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
	}
	_ = s.repo.Audit.Create(c.Request.Context(), auditReq.ToAuditLog())
}

func generateSecureToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func hashClientSecret(secret string) []byte {
	h := hmac.New(sha256.New, []byte("stratium-agent-secret"))
	h.Write([]byte(secret))
	return h.Sum(nil)
}
