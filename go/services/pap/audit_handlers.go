package pap

import (
	"fmt"
	"net/http"

	"stratium/pkg/models"

	"github.com/gin-gonic/gin"
)

// listAuditLogs lists audit logs with optional filtering
func (s *Server) listAuditLogs(c *gin.Context) {
	var req models.ListAuditLogsRequest
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

	auditLogs, err := s.repo.Audit.List(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list audit logs: %v", err)})
		return
	}

	count, err := s.repo.Audit.Count(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to count audit logs: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"audit_logs": auditLogs,
		"total":      count,
		"limit":      req.Limit,
		"offset":     req.Offset,
	})
}

// getAuditLog retrieves an audit log by ID
func (s *Server) getAuditLog(c *gin.Context) {
	id, err := s.parseUUID(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid audit log ID"})
		return
	}

	auditLog, err := s.repo.Audit.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "audit log not found"})
		return
	}

	c.JSON(http.StatusOK, auditLog)
}
