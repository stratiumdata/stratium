package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stratium/samples/micro-research-api/internal/middleware"
	"github.com/stratium/samples/micro-research-api/internal/models"
	"github.com/stratium/samples/micro-research-api/internal/platform"
	"github.com/stratium/samples/micro-research-api/internal/repository"
)

// DatasetHandler handles dataset-related HTTP requests
type DatasetHandler struct {
	repo           *repository.DatasetRepository
	platformClient *platform.Client
}

// NewDatasetHandler creates a new dataset handler
func NewDatasetHandler(repo *repository.DatasetRepository, platformClient *platform.Client) *DatasetHandler {
	return &DatasetHandler{
		repo:           repo,
		platformClient: platformClient,
	}
}

// List returns all datasets with pagination
func (h *DatasetHandler) List(c *gin.Context) {
	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	// Get pagination parameters
	limit := 20
	offset := 0

	if l, ok := c.GetQuery("limit"); ok {
		if _, err := fmt.Sscanf(l, "%d", &limit); err == nil {
			if limit > 100 {
				limit = 100
			}
		}
	}

	if o, ok := c.GetQuery("offset"); ok {
		fmt.Sscanf(o, "%d", &offset)
	}

	datasets, _, err := h.repo.List(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list datasets"})
		return
	}

	department, exists := c.Get("department")
	if !exists {
		department = ""
	}
	role, exists := c.Get("role")
	if !exists {
		role = ""
	}

	var allowedDatasets []models.DatasetWithOwner
	for _, dataset := range datasets {
		// Check ABAC access using Platform service
		req := platform.DecisionRequest{
			SubjectID:    user.ID.String(),
			SubjectEmail: user.Email,
			Department:   department.(string),
			Role:         role.(string),
			ResourceType: "dataset",
			ResourceID:   dataset.ID.String(),
			OwnerID:      dataset.OwnerID.String(),
			ResourceDept: dataset.Department,
			Action:       "read",
		}

		allowed, _, err := h.platformClient.CheckAccessSimple(c.Request.Context(), req)
		if err != nil {
			fmt.Printf("failed to check dataset access: %v\n", err)
			continue
		}

		if !allowed {
			continue
		}

		allowedDatasets = append(allowedDatasets, dataset)
	}

	c.JSON(http.StatusOK, models.ListDatasetsResponse{
		Datasets: allowedDatasets,
		Total:    len(allowedDatasets),
		Limit:    limit,
		Offset:   offset,
		HasMore:  offset+limit < len(allowedDatasets),
	})
}

// Search searches datasets with filters
func (h *DatasetHandler) Search(c *gin.Context) {
	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.SearchDatasetsRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set defaults
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Limit > 100 {
		req.Limit = 100
	}

	datasets, _, err := h.repo.Search(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to search datasets"})
		return
	}

	department, exists := c.Get("department")
	if !exists {
		department = ""
	}
	role, exists := c.Get("role")
	if !exists {
		role = ""
	}

	var allowedDatasets []models.DatasetWithOwner
	for _, dataset := range datasets {
		// Check ABAC access using Platform service
		req := platform.DecisionRequest{
			SubjectID:    user.ID.String(),
			SubjectEmail: user.Email,
			Department:   department.(string),
			Role:         role.(string),
			ResourceType: "dataset",
			ResourceID:   dataset.ID.String(),
			OwnerID:      dataset.OwnerID.String(),
			ResourceDept: dataset.Department,
			Action:       "read",
		}

		allowed, _, err := h.platformClient.CheckAccessSimple(c.Request.Context(), req)
		if err != nil {
			fmt.Printf("failed to check dataset access: %v\n", err)
			continue
		}

		if !allowed {
			continue
		}

		allowedDatasets = append(allowedDatasets, dataset)
	}

	c.JSON(http.StatusOK, models.ListDatasetsResponse{
		Datasets: allowedDatasets,
		Total:    len(allowedDatasets),
		Limit:    req.Limit,
		Offset:   req.Offset,
		HasMore:  req.Offset+req.Limit < len(allowedDatasets),
	})
}

// Get returns a specific dataset by ID
func (h *DatasetHandler) Get(c *gin.Context) {
	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dataset ID"})
		return
	}

	dataset, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dataset not found"})
		return
	}

	department, exists := c.Get("department")
	if !exists {
		department = ""
	}
	role, exists := c.Get("role")
	if !exists {
		role = ""
	}

	// Check ABAC access using Platform service
	req := platform.DecisionRequest{
		SubjectID:    user.ID.String(),
		SubjectEmail: user.Email,
		Department:   department.(string),
		Role:         role.(string),
		ResourceType: "dataset",
		ResourceID:   dataset.ID.String(),
		OwnerID:      dataset.OwnerID.String(),
		ResourceDept: dataset.Department,
		Action:       "read",
	}

	allowed, reason, err := h.platformClient.CheckAccessSimple(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to check access",
			"details": err.Error(),
		})
		return
	}

	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "access denied",
			"reason": reason,
		})
		return
	}

	c.JSON(http.StatusOK, dataset)
}

// Create creates a new dataset
func (h *DatasetHandler) Create(c *gin.Context) {
	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req models.CreateDatasetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	dataset := &models.Dataset{
		ID:          uuid.New(),
		Title:       req.Title,
		Description: req.Description,
		OwnerID:     user.ID,
		DataURL:     req.DataURL,
		Department:  req.Department,
		Tags:        pq.StringArray(req.Tags),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.repo.Create(c.Request.Context(), dataset); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create dataset"})
		return
	}

	c.JSON(http.StatusCreated, dataset)
}

// Update updates a dataset
func (h *DatasetHandler) Update(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dataset ID"})
		return
	}

	datasetWithOwner, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dataset not found"})
		return
	}

	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	department, exists := c.Get("department")
	if !exists {
		department = ""
	}
	role, exists := c.Get("role")
	if !exists {
		role = ""
	}

	// Check ABAC access using Platform service
	abacReq := platform.DecisionRequest{
		SubjectID:    user.ID.String(),
		SubjectEmail: user.Email,
		Department:   department.(string),
		Role:         role.(string),
		ResourceType: "dataset",
		ResourceID:   datasetWithOwner.ID.String(),
		OwnerID:      datasetWithOwner.OwnerID.String(),
		ResourceDept: datasetWithOwner.Department,
		Action:       "update",
	}

	allowed, reason, err := h.platformClient.CheckAccessSimple(c.Request.Context(), abacReq)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to check access",
			"details": err.Error(),
		})
		return
	}

	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "access denied",
			"reason": reason,
		})
		return
	}

	var req models.UpdateDatasetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create dataset model from datasetWithOwner
	dataset := &models.Dataset{
		ID:          datasetWithOwner.ID,
		Title:       datasetWithOwner.Title,
		Description: datasetWithOwner.Description,
		OwnerID:     datasetWithOwner.OwnerID,
		DataURL:     datasetWithOwner.DataURL,
		Department:  datasetWithOwner.Department,
		Tags:        datasetWithOwner.Tags,
		CreatedAt:   datasetWithOwner.CreatedAt,
		UpdatedAt:   datasetWithOwner.UpdatedAt,
	}

	// Update fields if provided
	if req.Title != nil {
		dataset.Title = *req.Title
	}
	if req.Description != nil {
		dataset.Description = *req.Description
	}
	if req.DataURL != nil {
		dataset.DataURL = *req.DataURL
	}
	if req.Department != nil {
		dataset.Department = *req.Department
	}
	if req.Tags != nil {
		dataset.Tags = pq.StringArray(req.Tags)
	}

	if err := h.repo.Update(c.Request.Context(), dataset); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update dataset"})
		return
	}

	c.JSON(http.StatusOK, dataset)
}

// Delete deletes a dataset
func (h *DatasetHandler) Delete(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dataset ID"})
		return
	}

	// Get dataset to check ownership for ABAC
	dataset, err := h.repo.GetByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dataset not found"})
		return
	}

	user, err := middleware.GetUser(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	department, exists := c.Get("department")
	if !exists {
		department = ""
	}
	role, exists := c.Get("role")
	if !exists {
		role = ""
	}

	// Check ABAC access using Platform service
	req := platform.DecisionRequest{
		SubjectID:    user.ID.String(),
		SubjectEmail: user.Email,
		Department:   department.(string),
		Role:         role.(string),
		ResourceType: "dataset",
		ResourceID:   dataset.ID.String(),
		OwnerID:      dataset.OwnerID.String(),
		ResourceDept: dataset.Department,
		Action:       "delete",
	}

	allowed, reason, err := h.platformClient.CheckAccessSimple(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to check access",
			"details": err.Error(),
		})
		return
	}

	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "access denied",
			"reason": reason,
		})
		return
	}

	if err := h.repo.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete dataset"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "dataset deleted successfully"})
}
