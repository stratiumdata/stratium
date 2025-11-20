package pap

import (
	"context"
	"fmt"
	"net/http"
	"stratium/config"
	"time"

	"stratium/pkg/cache"
	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// Server represents the PAP API server
type Server struct {
	router           *gin.Engine
	repo             *repository.Repository
	engineFactory    *policy_engine.EngineFactory
	authService      *AuthService
	cacheInvalidator cache.CacheInvalidator
}

// NewServer creates a new PAP server instance
func NewServer(repo *repository.Repository, authService *AuthService, corsConfig config.CORSConfig) *Server {
	s := &Server{
		router:           gin.Default(),
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      authService,
		cacheInvalidator: cache.NewNoOpCacheInvalidator(), // Default to no-op
	}

	s.setupRoutes(corsConfig)
	return s
}

// NewServerWithCacheInvalidator creates a new PAP server instance with cache invalidation
func NewServerWithCacheInvalidator(repo *repository.Repository, authService *AuthService, cacheInvalidator cache.CacheInvalidator, corsConfig config.CORSConfig) *Server {
	s := &Server{
		router:           gin.Default(),
		repo:             repo,
		engineFactory:    policy_engine.NewEngineFactory(),
		authService:      authService,
		cacheInvalidator: cacheInvalidator,
	}

	s.setupRoutes(corsConfig)
	return s
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes(config config.CORSConfig) {
	// Configure CORS - must be first middleware to handle preflight
	s.router.Use(cors.New(cors.Config{
		AllowOrigins:     config.AllowedOrigins,
		AllowMethods:     config.AllowedMethods,
		AllowHeaders:     config.AllowedHeaders,
		ExposeHeaders:    []string{"Content-Length", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Health check (no auth required)
	s.router.GET("/health", s.healthCheck)

	// Register explicit OPTIONS handlers for CORS preflight (before auth middleware)
	optionsHandler := func(c *gin.Context) {
		c.Status(204)
	}
	s.router.OPTIONS("/api/v1/policies", optionsHandler)
	s.router.OPTIONS("/api/v1/policies/*path", optionsHandler)
	s.router.OPTIONS("/api/v1/entitlements", optionsHandler)
	s.router.OPTIONS("/api/v1/entitlements/*path", optionsHandler)
	s.router.OPTIONS("/api/v1/audit-logs", optionsHandler)
	s.router.OPTIONS("/api/v1/audit-logs/*path", optionsHandler)

	// API v1 routes
	v1 := s.router.Group("/api/v1")

	{
		// Apply authentication middleware to all routes except OPTIONS
		// Use mock auth if in mock mode
		if s.authService.IsMock() {
			v1.Use(s.mockAuthMiddleware())
		} else {
			v1.Use(s.authMiddleware())
		}

		// Policy routes
		policies := v1.Group("/policies")
		{
			policies.POST("", s.createPolicy)
			policies.GET("", s.listPolicies)
			policies.GET("/:id", s.getPolicy)
			policies.PUT("/:id", s.updatePolicy)
			policies.DELETE("/:id", s.deletePolicy)
			policies.POST("/validate", s.validatePolicy)
			policies.POST("/test", s.testPolicy)
		}

		// Entitlement routes
		entitlements := v1.Group("/entitlements")
		{
			entitlements.POST("", s.createEntitlement)
			entitlements.GET("", s.listEntitlements)
			entitlements.GET("/:id", s.getEntitlement)
			entitlements.PUT("/:id", s.updateEntitlement)
			entitlements.DELETE("/:id", s.deleteEntitlement)
			entitlements.POST("/match", s.findMatchingEntitlements)
		}

		// Audit log routes
		auditLogs := v1.Group("/audit-logs")
		{
			auditLogs.GET("", s.listAuditLogs)
			auditLogs.GET("/:id", s.getAuditLog)
		}
	}
}

// Start starts the HTTP server
func (s *Server) Start(addr string) error {
	logger.Startup("Starting PAP API server on %s", addr)
	return s.router.Run(addr)
}

// healthCheck returns the server health status
func (s *Server) healthCheck(c *gin.Context) {
	// Check database connection
	if err := s.repo.Ping(context.Background()); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":  "unhealthy",
			"message": "database connection failed",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "pap-api",
		"version": "1.0.0",
	})
}

// Helper methods

func (s *Server) getUserFromContext(c *gin.Context) (string, error) {
	user, exists := c.Get("user")
	if !exists {
		return "", fmt.Errorf("user not found in context")
	}

	userStr, ok := user.(string)
	if !ok {
		return "", fmt.Errorf("invalid user type in context")
	}

	return userStr, nil
}

func (s *Server) createAuditLog(ctx context.Context, entityType models.EntityType, entityID *uuid.UUID, action models.AuditAction, actor string, changes, result map[string]interface{}, c *gin.Context) {
	auditLog := &models.CreateAuditLogRequest{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     action,
		Actor:      actor,
		Changes:    changes,
		Result:     result,
		IPAddress:  c.ClientIP(),
		UserAgent:  c.Request.UserAgent(),
	}

	if err := s.repo.Audit.Create(ctx, auditLog.ToAuditLog()); err != nil {
		logger.Error("failed to create audit log: %v", err)
	}
}

func (s *Server) parseUUID(id string) (uuid.UUID, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid UUID format")
	}
	return parsedID, nil
}
