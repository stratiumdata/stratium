package models

import (
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Dataset represents a research dataset
type Dataset struct {
	ID          uuid.UUID      `json:"id" db:"id"`
	Title       string         `json:"title" db:"title"`
	Description string         `json:"description" db:"description"`
	OwnerID     uuid.UUID      `json:"owner_id" db:"owner_id"`
	DataURL     string         `json:"data_url" db:"data_url"`
	Department  string         `json:"department" db:"department"`
	Tags        pq.StringArray `json:"tags" db:"tags"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// DatasetWithOwner includes owner information
type DatasetWithOwner struct {
	Dataset
	OwnerName  string `json:"owner_name" db:"owner_name"`
	OwnerEmail string `json:"owner_email" db:"owner_email"`
}

// CreateDatasetRequest represents the request to create a new dataset
type CreateDatasetRequest struct {
	Title       string   `json:"title" binding:"required"`
	Description string   `json:"description"`
	DataURL     string   `json:"data_url" binding:"required,url"`
	Department  string   `json:"department" binding:"required"`
	Tags        []string `json:"tags"`
}

// UpdateDatasetRequest represents the request to update a dataset
type UpdateDatasetRequest struct {
	Title       *string  `json:"title"`
	Description *string  `json:"description"`
	DataURL     *string  `json:"data_url"`
	Department  *string  `json:"department"`
	Tags        []string `json:"tags"`
}

// SearchDatasetsRequest represents search parameters
type SearchDatasetsRequest struct {
	Query      string   `form:"q"`
	Department string   `form:"department"`
	Tags       []string `form:"tags"`
	OwnerID    string   `form:"owner_id"`
	Limit      int      `form:"limit"`
	Offset     int      `form:"offset"`
}

// ListDatasetsResponse represents paginated dataset list
type ListDatasetsResponse struct {
	Datasets   []DatasetWithOwner `json:"datasets"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
	HasMore    bool               `json:"has_more"`
}