package pap

import (
	"errors"
	"net/http"

	"stratium/pkg/cedar"
	"stratium/pkg/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CedarTemplateHandlers provides HTTP handlers for Cedar template operations.
type CedarTemplateHandlers struct {
	templateManager *cedar.TemplateManager
}

// NewCedarTemplateHandlers creates template handlers with the given store.
func NewCedarTemplateHandlers(store cedar.TemplateStore) *CedarTemplateHandlers {
	return &CedarTemplateHandlers{
		templateManager: cedar.NewTemplateManager(store),
	}
}

// registerCedarTemplateRoutes registers Cedar template routes.
func (s *Server) registerCedarTemplateRoutes(parent *gin.RouterGroup) {
	handlers := NewCedarTemplateHandlers(s.cedarTemplateStore)

	templates := parent.Group("/templates")
	{
		templates.POST("", handlers.createTemplate)
		templates.GET("", handlers.listTemplates)
		templates.GET("/:id", handlers.getTemplate)
		templates.DELETE("/:id", handlers.deleteTemplate)
		templates.POST("/:id/instantiate", handlers.instantiateTemplate)
		templates.GET("/:id/linked", handlers.listLinkedPolicies)
	}
}

func (h *CedarTemplateHandlers) createTemplate(c *gin.Context) {
	createdBy, ok := getUserIdentity(c)
	if !ok {
		return
	}

	var req models.CreateCedarTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	template, err := h.templateManager.CreateTemplate(c.Request.Context(), &req, createdBy)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, template)
}

func (h *CedarTemplateHandlers) listTemplates(c *gin.Context) {
	namespace := c.Query("namespace")

	templates, err := h.templateManager.ListTemplates(c.Request.Context(), namespace)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list templates"})
		return
	}

	if templates == nil {
		templates = []*models.CedarTemplate{}
	}

	c.JSON(http.StatusOK, gin.H{
		"templates": templates,
		"total":     len(templates),
	})
}

func (h *CedarTemplateHandlers) getTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template ID"})
		return
	}

	template, err := h.templateManager.GetTemplate(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
		return
	}

	c.JSON(http.StatusOK, template)
}

func (h *CedarTemplateHandlers) deleteTemplate(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template ID"})
		return
	}

	if err := h.templateManager.DeleteTemplate(c.Request.Context(), id); err != nil {
		if errors.Is(err, models.ErrCedarTemplateNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "template deleted"})
}

func (h *CedarTemplateHandlers) instantiateTemplate(c *gin.Context) {
	createdBy, ok := getUserIdentity(c)
	if !ok {
		return
	}

	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template ID"})
		return
	}

	var req models.InstantiateTemplateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	// Validate entity UID format before substitution
	if req.PrincipalEntity != "" {
		if err := cedar.ValidateEntityUID(req.PrincipalEntity); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid principal_entity: " + err.Error()})
			return
		}
	}
	if req.ResourceEntity != "" {
		if err := cedar.ValidateEntityUID(req.ResourceEntity); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource_entity: " + err.Error()})
			return
		}
	}

	link, policy, err := h.templateManager.InstantiateTemplate(c.Request.Context(), id, &req, createdBy)
	if err != nil {
		if errors.Is(err, models.ErrCedarTemplateNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "template not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"linked_policy": link,
		"policy":        policy,
	})
}

func (h *CedarTemplateHandlers) listLinkedPolicies(c *gin.Context) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid template ID"})
		return
	}

	links, err := h.templateManager.ListLinkedPolicies(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list linked policies"})
		return
	}

	if links == nil {
		links = []*models.CedarLinkedPolicy{}
	}

	c.JSON(http.StatusOK, gin.H{
		"linked_policies": links,
		"total":           len(links),
	})
}
