package pap

import (
	"fmt"
	"net/http"

	"stratium/pkg/models"
	"stratium/pkg/policy_engine"

	"github.com/gin-gonic/gin"
)

// createPolicy creates a new policy
func (s *Server) createPolicy(c *gin.Context) {
	var req models.CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get authenticated user
	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Validate policy syntax
	engine, err := s.engineFactory.GetEngine(req.Language)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported policy language: %s", req.Language)})
		return
	}

	if err := engine.ValidatePolicy(c.Request.Context(), req.PolicyContent, req.Language); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("policy validation failed: %v", err)})
		return
	}

	// Create policy
	policy := req.ToPolicy(user)
	if err := s.repo.Policy.Create(c.Request.Context(), policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create policy: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypePolicy, &policy.ID, models.AuditActionCreate, user, map[string]interface{}{
		"policy_name": policy.Name,
		"language":    policy.Language,
		"effect":      policy.Effect,
	}, nil, c)

	// Invalidate cache (clear all policies since a new one was added)
	if err := s.cacheInvalidator.InvalidateAllPolicies(c.Request.Context()); err != nil {
		// Log error but don't fail the request
		c.Request.Context().Value("logger")
	}

	c.JSON(http.StatusCreated, policy)
}

// listPolicies lists policies with optional filtering
func (s *Server) listPolicies(c *gin.Context) {
	var req models.ListPoliciesRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 50
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	policies, err := s.repo.Policy.List(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list policies: %v", err)})
		return
	}

	count, err := s.repo.Policy.Count(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to count policies: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"policies": policies,
		"total":    count,
		"limit":    req.Limit,
		"offset":   req.Offset,
	})
}

// getPolicy retrieves a policy by ID
func (s *Server) getPolicy(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	policy, err := s.repo.Policy.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrPolicyNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get policy: %v", err)})
		return
	}

	c.JSON(http.StatusOK, policy)
}

// updatePolicy updates an existing policy
func (s *Server) updatePolicy(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	var req models.UpdatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Get existing policy
	policy, err := s.repo.Policy.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrPolicyNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get policy: %v", err)})
		return
	}

	// Validate policy syntax if policy content is being updated
	if req.PolicyContent != nil {
		language := policy.Language
		if req.Language != nil {
			language = *req.Language
		}

		engine, err := s.engineFactory.GetEngine(language)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported policy language: %s", language)})
			return
		}

		if err := engine.ValidatePolicy(c.Request.Context(), *req.PolicyContent, language); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("policy validation failed: %v", err)})
			return
		}
	}

	// Track changes for audit
	changes := make(map[string]interface{})
	if req.Name != nil && *req.Name != policy.Name {
		changes["name"] = map[string]string{"old": policy.Name, "new": *req.Name}
	}
	if req.Enabled != nil && *req.Enabled != policy.Enabled {
		changes["enabled"] = map[string]bool{"old": policy.Enabled, "new": *req.Enabled}
	}

	// Apply updates
	policy.ApplyUpdate(&req, user)

	// Update policy
	if err := s.repo.Policy.Update(c.Request.Context(), policy); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update policy: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypePolicy, &policy.ID, models.AuditActionUpdate, user, changes, nil, c)

	// Invalidate cache for this policy
	if err := s.cacheInvalidator.InvalidatePolicy(c.Request.Context(), policy.ID.String()); err != nil {
		// Log error but don't fail the request
		fmt.Printf("Warning: failed to invalidate cache for policy %s: %v\n", policy.ID, err)
	}
	// Also invalidate all policies cache to ensure list is fresh
	if err := s.cacheInvalidator.InvalidateAllPolicies(c.Request.Context()); err != nil {
		fmt.Printf("Warning: failed to invalidate all policies cache: %v\n", err)
	}

	c.JSON(http.StatusOK, policy)
}

// deletePolicy deletes a policy
func (s *Server) deletePolicy(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid policy ID"})
		return
	}

	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Get policy for audit log
	policy, err := s.repo.Policy.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrPolicyNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "policy not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get policy: %v", err)})
		return
	}

	// Delete policy
	if err := s.repo.Policy.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete policy: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypePolicy, &policy.ID, models.AuditActionDelete, user, map[string]interface{}{
		"policy_name": policy.Name,
	}, nil, c)

	// Invalidate cache for this policy
	if err := s.cacheInvalidator.InvalidatePolicy(c.Request.Context(), policy.ID.String()); err != nil {
		fmt.Printf("Warning: failed to invalidate cache for policy %s: %v\n", policy.ID, err)
	}
	// Also invalidate all policies cache to ensure list is fresh
	if err := s.cacheInvalidator.InvalidateAllPolicies(c.Request.Context()); err != nil {
		fmt.Printf("Warning: failed to invalidate all policies cache: %v\n", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted successfully"})
}

// validatePolicy validates a policy without creating it
func (s *Server) validatePolicy(c *gin.Context) {
	var req struct {
		Language      models.PolicyLanguage `json:"language" binding:"required,oneof=xacml opa json"`
		PolicyContent string                `json:"policy_content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	engine, err := s.engineFactory.GetEngine(req.Language)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported policy language: %s", req.Language)})
		return
	}

	if err := engine.ValidatePolicy(c.Request.Context(), req.PolicyContent, req.Language); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"valid":  false,
			"error":  err.Error(),
			"syntax": "invalid",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":  true,
		"syntax": "valid",
	})
}

// testPolicy tests a policy against sample input without persisting it
func (s *Server) testPolicy(c *gin.Context) {
	var req struct {
		Language           models.PolicyLanguage  `json:"language" binding:"required,oneof=xacml opa json"`
		PolicyContent      string                 `json:"policy_content" binding:"required"`
		SubjectAttributes  map[string]interface{} `json:"subject_attributes" binding:"required"`
		ResourceAttributes map[string]interface{} `json:"resource_attributes" binding:"required"`
		Action             string                 `json:"action" binding:"required"`
		Environment        map[string]interface{} `json:"environment"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, _ := s.getUserFromContext(c)

	engine, err := s.engineFactory.GetEngine(req.Language)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("unsupported policy language: %s", req.Language)})
		return
	}

	// Build evaluation input
	input := &policy_engine.EvaluationInput{
		Subject:     req.SubjectAttributes,
		Resource:    req.ResourceAttributes,
		Action:      req.Action,
		Environment: req.Environment,
	}

	// Test the policy
	result, err := engine.TestPolicy(c.Request.Context(), req.PolicyContent, req.Language, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("policy test failed: %v", err)})
		return
	}

	// Create audit log for policy testing
	s.createAuditLog(c.Request.Context(), models.EntityTypePolicy, nil, models.AuditActionTest, user, map[string]interface{}{
		"language": req.Language,
		"action":   req.Action,
	}, map[string]interface{}{
		"allow":  result.Allow,
		"reason": result.Reason,
	}, c)

	c.JSON(http.StatusOK, gin.H{
		"test_result": result,
		"input":       input,
	})
}
