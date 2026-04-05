package pap

import (
	"errors"
	"fmt"
	"net/http"

	"stratium/pkg/cedar"
	"stratium/pkg/models"
	"stratium/pkg/policy_engine"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// maxBatchSize is the maximum number of requests allowed in a batch test.
const maxBatchSize = 50

// CedarHandlers provides HTTP handlers for Cedar-specific PAP operations.
type CedarHandlers struct {
	schemaManager    *cedar.SchemaManager
	namespaceManager *cedar.NamespaceManager
	engineFactory    *policy_engine.EngineFactory
}

// NewCedarHandlers creates Cedar handlers with the given schema store.
func NewCedarHandlers(store cedar.SchemaStore, engineFactory *policy_engine.EngineFactory) *CedarHandlers {
	return &CedarHandlers{
		schemaManager:    cedar.NewSchemaManager(store),
		namespaceManager: cedar.NewNamespaceManager("Stratium"),
		engineFactory:    engineFactory,
	}
}

// registerCedarRoutes registers Cedar-specific routes on the PAP server.
func (s *Server) registerCedarRoutes(parent *gin.RouterGroup) {
	handlers := NewCedarHandlers(s.cedarSchemaStore, s.engineFactory)

	cedarGroup := parent.Group("/cedar")
	{
		// Schema management
		schemas := cedarGroup.Group("/schemas")
		{
			schemas.POST("", handlers.createSchema)
			schemas.GET("", handlers.listSchemas)
			schemas.GET("/:id", handlers.getSchema)
			schemas.PUT("/:id", handlers.updateSchema)
			schemas.DELETE("/:id", handlers.deleteSchema)
			schemas.POST("/:id/validate", handlers.validatePoliciesAgainstSchema)
		}

		// Template management
		s.registerCedarTemplateRoutes(cedarGroup)

		// Policy testing (stateless — no persistence needed)
		cedarGroup.POST("/test", handlers.testCedarPolicy)
		cedarGroup.POST("/batch-test", handlers.batchTestCedarPolicy)

		// Not yet implemented
		cedarGroup.POST("/analyze", handlers.analyzePolicies)
	}
}

// getUserIdentity extracts and validates the user identity from the request context.
func getUserIdentity(c *gin.Context) (string, bool) {
	userVal, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "missing user context"})
		return "", false
	}
	identity, ok := userVal.(string)
	if !ok || identity == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user context"})
		return "", false
	}
	return identity, true
}

// --- Schema Handlers ---

func (h *CedarHandlers) createSchema(c *gin.Context) {
	createdBy, ok := getUserIdentity(c)
	if !ok {
		return
	}

	var req models.CreateCedarSchemaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	schema, err := h.schemaManager.CreateSchema(c.Request.Context(), &req, createdBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, schema)
}

func (h *CedarHandlers) listSchemas(c *gin.Context) {
	namespace := c.Query("namespace")

	schemas, err := h.schemaManager.ListSchemas(c.Request.Context(), namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list schemas"})
		return
	}

	if schemas == nil {
		schemas = []*models.CedarSchema{}
	}

	c.JSON(http.StatusOK, gin.H{
		"schemas": schemas,
		"total":   len(schemas),
	})
}

func (h *CedarHandlers) getSchema(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schema ID"})
		return
	}

	schema, err := h.schemaManager.GetSchema(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "schema not found"})
		return
	}

	c.JSON(http.StatusOK, schema)
}

func (h *CedarHandlers) updateSchema(c *gin.Context) {
	updatedBy, ok := getUserIdentity(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schema ID"})
		return
	}

	var req models.UpdateCedarSchemaRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	schema, err := h.schemaManager.UpdateSchema(c.Request.Context(), id, &req, updatedBy)
	if err != nil {
		if errors.Is(err, models.ErrCedarSchemaNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "schema not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update schema"})
		return
	}

	c.JSON(http.StatusOK, schema)
}

func (h *CedarHandlers) deleteSchema(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schema ID"})
		return
	}

	if err := h.schemaManager.DeleteSchema(c.Request.Context(), id); err != nil {
		if errors.Is(err, models.ErrCedarSchemaNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "schema not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete schema"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "schema deleted"})
}

func (h *CedarHandlers) validatePoliciesAgainstSchema(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid schema ID"})
		return
	}

	// Verify the schema exists
	_, err = h.schemaManager.GetSchema(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "schema not found"})
		return
	}

	var req struct {
		PolicyContent string `json:"policy_content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	engine, err := h.engineFactory.GetEngine(models.PolicyLanguageCedar)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cedar engine not available"})
		return
	}

	if err := engine.ValidatePolicy(c.Request.Context(), req.PolicyContent, models.PolicyLanguageCedar); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"valid":     true,
		"schema_id": id.String(),
	})
}

// --- Testing and Analysis Handlers ---

func (h *CedarHandlers) testCedarPolicy(c *gin.Context) {
	var req models.CedarTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.PolicyContent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy_content is required"})
		return
	}
	if req.Action == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "action is required"})
		return
	}

	engine, err := h.engineFactory.GetEngine(models.PolicyLanguageCedar)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cedar engine not available"})
		return
	}

	env := req.Environment
	if env == nil {
		env = make(map[string]interface{})
	}
	// Pass namespace to the engine; empty means un-namespaced entity types
	if _, ok := env["namespace"]; !ok {
		env["namespace"] = req.Namespace
	}

	input := &policy_engine.EvaluationInput{
		Subject:     req.SubjectAttributes,
		Resource:    req.ResourceAttributes,
		Action:      req.Action,
		Environment: env,
	}

	result, err := engine.TestPolicy(c.Request.Context(), req.PolicyContent, models.PolicyLanguageCedar, input)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"decision": boolToDecision(result.Allow),
		"reason":   result.Reason,
		"details":  result.Details,
	})
}

func (h *CedarHandlers) analyzePolicies(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error": "policy analysis is not yet implemented",
	})
}

func (h *CedarHandlers) batchTestCedarPolicy(c *gin.Context) {
	var req struct {
		PolicyContent string                    `json:"policy_content"`
		Requests      []models.CedarTestRequest `json:"requests"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if req.PolicyContent == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "policy_content is required"})
		return
	}
	if len(req.Requests) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one request is required"})
		return
	}
	if len(req.Requests) > maxBatchSize {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("batch size %d exceeds maximum of %d", len(req.Requests), maxBatchSize),
		})
		return
	}

	engine, err := h.engineFactory.GetEngine(models.PolicyLanguageCedar)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Cedar engine not available"})
		return
	}

	results := make([]gin.H, 0, len(req.Requests))
	for _, testReq := range req.Requests {
		env := testReq.Environment
		if env == nil {
			env = make(map[string]interface{})
		}
		if _, ok := env["namespace"]; !ok {
			env["namespace"] = testReq.Namespace
		}

		input := &policy_engine.EvaluationInput{
			Subject:     testReq.SubjectAttributes,
			Resource:    testReq.ResourceAttributes,
			Action:      testReq.Action,
			Environment: env,
		}

		result, err := engine.TestPolicy(c.Request.Context(), req.PolicyContent, models.PolicyLanguageCedar, input)
		if err != nil {
			results = append(results, gin.H{
				"decision": "error",
				"error":    err.Error(),
			})
			continue
		}

		results = append(results, gin.H{
			"decision": boolToDecision(result.Allow),
			"reason":   result.Reason,
			"details":  result.Details,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"results": results,
		"total":   len(results),
	})
}

func boolToDecision(allow bool) string {
	if allow {
		return "allow"
	}
	return "deny"
}
