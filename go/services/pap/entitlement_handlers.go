package pap

import (
	"fmt"
	"net/http"

	"stratium/pkg/models"

	"github.com/gin-gonic/gin"
)

// createEntitlement creates a new entitlement
func (s *Server) createEntitlement(c *gin.Context) {
	var req models.CreateEntitlementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Create entitlement
	entitlement := req.ToEntitlement(user)
	if err := entitlement.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("validation failed: %v", err)})
		return
	}

	if err := s.repo.Entitlement.Create(c.Request.Context(), entitlement); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create entitlement: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypeEntitlement, &entitlement.ID, models.AuditActionCreate, user, map[string]interface{}{
		"entitlement_name": entitlement.Name,
		"actions":          entitlement.Actions,
	}, nil, c)

	c.JSON(http.StatusCreated, entitlement)
}

// listEntitlements lists entitlements with optional filtering
func (s *Server) listEntitlements(c *gin.Context) {
	var req models.ListEntitlementsRequest
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

	entitlements, err := s.repo.Entitlement.List(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list entitlements: %v", err)})
		return
	}

	count, err := s.repo.Entitlement.Count(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to count entitlements: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entitlements": entitlements,
		"total":        count,
		"limit":        req.Limit,
		"offset":       req.Offset,
	})
}

// getEntitlement retrieves an entitlement by ID
func (s *Server) getEntitlement(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid entitlement ID"})
		return
	}

	entitlement, err := s.repo.Entitlement.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrEntitlementNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "entitlement not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get entitlement: %v", err)})
		return
	}

	c.JSON(http.StatusOK, entitlement)
}

// updateEntitlement updates an existing entitlement
func (s *Server) updateEntitlement(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid entitlement ID"})
		return
	}

	var req models.UpdateEntitlementRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Get existing entitlement
	entitlement, err := s.repo.Entitlement.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrEntitlementNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "entitlement not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get entitlement: %v", err)})
		return
	}

	// Track changes for audit
	changes := make(map[string]interface{})
	if req.Name != nil && *req.Name != entitlement.Name {
		changes["name"] = map[string]string{"old": entitlement.Name, "new": *req.Name}
	}
	if req.Enabled != nil && *req.Enabled != entitlement.Enabled {
		changes["enabled"] = map[string]bool{"old": entitlement.Enabled, "new": *req.Enabled}
	}

	// Apply updates
	entitlement.ApplyUpdate(&req, user)

	if err := entitlement.Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("validation failed: %v", err)})
		return
	}

	// Update entitlement
	if err := s.repo.Entitlement.Update(c.Request.Context(), entitlement); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update entitlement: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypeEntitlement, &entitlement.ID, models.AuditActionUpdate, user, changes, nil, c)

	c.JSON(http.StatusOK, entitlement)
}

// deleteEntitlement deletes an entitlement
func (s *Server) deleteEntitlement(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid entitlement ID"})
		return
	}

	user, err := s.getUserFromContext(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	// Get entitlement for audit log
	entitlement, err := s.repo.Entitlement.GetByID(c.Request.Context(), id)
	if err != nil {
		if err == models.ErrEntitlementNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "entitlement not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get entitlement: %v", err)})
		return
	}

	// Delete entitlement
	if err := s.repo.Entitlement.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete entitlement: %v", err)})
		return
	}

	// Create audit log
	s.createAuditLog(c.Request.Context(), models.EntityTypeEntitlement, &entitlement.ID, models.AuditActionDelete, user, map[string]interface{}{
		"entitlement_name": entitlement.Name,
	}, nil, c)

	c.JSON(http.StatusOK, gin.H{"message": "entitlement deleted successfully"})
}

// findMatchingEntitlements finds entitlements matching the given criteria
func (s *Server) findMatchingEntitlements(c *gin.Context) {
	var req models.EntitlementMatchRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	entitlements, err := s.repo.Entitlement.FindMatching(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to find matching entitlements: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entitlements": entitlements,
		"total":        len(entitlements),
	})
}
