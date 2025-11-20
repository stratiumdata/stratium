package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Entitlement represents what users/subjects can access
type Entitlement struct {
	ID                 uuid.UUID              `json:"id" db:"id"`
	Name               string                 `json:"name" db:"name"`
	Description        string                 `json:"description" db:"description"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes" db:"subject_attributes"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes" db:"resource_attributes"`
	Actions            []string               `json:"actions" db:"actions"`
	Conditions         map[string]interface{} `json:"conditions" db:"conditions"`
	Enabled            bool                   `json:"enabled" db:"enabled"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	CreatedBy          sql.NullString         `json:"created_by" db:"created_by"`
	UpdatedBy          sql.NullString         `json:"updated_by" db:"updated_by"`
	ExpiresAt          *time.Time             `json:"expires_at,omitempty" db:"expires_at"`
}

// CreateEntitlementRequest represents a request to create a new entitlement
type CreateEntitlementRequest struct {
	Name               string                 `json:"name" binding:"required"`
	Description        string                 `json:"description"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes" binding:"required"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes"`
	Actions            []string               `json:"actions" binding:"required,min=1"`
	Conditions         map[string]interface{} `json:"conditions"`
	Enabled            bool                   `json:"enabled"`
	ExpiresAt          *time.Time             `json:"expires_at,omitempty"`
}

// UpdateEntitlementRequest represents a request to update an existing entitlement
type UpdateEntitlementRequest struct {
	Name               *string                 `json:"name"`
	Description        *string                 `json:"description"`
	SubjectAttributes  *map[string]interface{} `json:"subject_attributes"`
	ResourceAttributes *map[string]interface{} `json:"resource_attributes"`
	Actions            *[]string               `json:"actions"`
	Conditions         *map[string]interface{} `json:"conditions"`
	Enabled            *bool                   `json:"enabled"`
	ExpiresAt          *time.Time              `json:"expires_at"`
}

// ListEntitlementsRequest represents query parameters for listing entitlements
type ListEntitlementsRequest struct {
	Enabled *bool  `form:"enabled"`
	Action  string `form:"action"`
	Limit   int    `form:"limit"`
	Offset  int    `form:"offset"`
}

// EntitlementMatchRequest represents a request to find matching entitlements
type EntitlementMatchRequest struct {
	SubjectAttributes  map[string]interface{} `json:"subject_attributes" binding:"required"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes"`
	Action             string                 `json:"action" binding:"required"`
}

// ToEntitlement converts CreateEntitlementRequest to Entitlement
func (r *CreateEntitlementRequest) ToEntitlement(createdBy string) *Entitlement {
	now := time.Now()
	return &Entitlement{
		ID:                 uuid.New(),
		Name:               r.Name,
		Description:        r.Description,
		SubjectAttributes:  r.SubjectAttributes,
		ResourceAttributes: r.ResourceAttributes,
		Actions:            r.Actions,
		Conditions:         r.Conditions,
		Enabled:            r.Enabled,
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedBy:          sql.NullString{String: createdBy, Valid: createdBy != ""},
		UpdatedBy:          sql.NullString{String: createdBy, Valid: createdBy != ""},
		ExpiresAt:          r.ExpiresAt,
	}
}

// ApplyUpdate applies UpdateEntitlementRequest changes to an Entitlement
func (e *Entitlement) ApplyUpdate(req *UpdateEntitlementRequest, updatedBy string) {
	if req.Name != nil {
		e.Name = *req.Name
	}
	if req.Description != nil {
		e.Description = *req.Description
	}
	if req.SubjectAttributes != nil {
		e.SubjectAttributes = *req.SubjectAttributes
	}
	if req.ResourceAttributes != nil {
		e.ResourceAttributes = *req.ResourceAttributes
	}
	if req.Actions != nil {
		e.Actions = *req.Actions
	}
	if req.Conditions != nil {
		e.Conditions = *req.Conditions
	}
	if req.Enabled != nil {
		e.Enabled = *req.Enabled
	}
	if req.ExpiresAt != nil {
		e.ExpiresAt = req.ExpiresAt
	}
	e.UpdatedBy = sql.NullString{String: updatedBy, Valid: updatedBy != ""}
	e.UpdatedAt = time.Now()
}

// IsExpired checks if the entitlement has expired
func (e *Entitlement) IsExpired() bool {
	if e.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*e.ExpiresAt)
}

// IsActive checks if the entitlement is active (enabled and not expired)
func (e *Entitlement) IsActive() bool {
	return e.Enabled && !e.IsExpired()
}

// Validate checks if the entitlement is valid
func (e *Entitlement) Validate() error {
	if e.Name == "" {
		return ErrInvalidEntitlementName
	}
	if len(e.SubjectAttributes) == 0 {
		return ErrInvalidSubjectAttributes
	}
	if len(e.Actions) == 0 {
		return ErrInvalidActions
	}
	return nil
}

// MarshalJSON customizes JSON serialization
func (e *Entitlement) MarshalJSON() ([]byte, error) {
	type Alias Entitlement

	createdBy := ""
	if e.CreatedBy.Valid {
		createdBy = e.CreatedBy.String
	}

	updatedBy := ""
	if e.UpdatedBy.Valid {
		updatedBy = e.UpdatedBy.String
	}

	return json.Marshal(&struct {
		*Alias
		ID        string `json:"id"`
		CreatedBy string `json:"created_by"`
		UpdatedBy string `json:"updated_by"`
	}{
		Alias:     (*Alias)(e),
		ID:        e.ID.String(),
		CreatedBy: createdBy,
		UpdatedBy: updatedBy,
	})
}