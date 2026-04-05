package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// CedarSchema represents an admin-managed Cedar schema for policy validation.
type CedarSchema struct {
	ID            uuid.UUID `json:"id" db:"id"`
	Namespace     string    `json:"namespace" db:"namespace"`
	Name          string    `json:"name" db:"name"`
	Description   string    `json:"description" db:"description"`
	SchemaContent string    `json:"schema_content" db:"schema_content"`
	SchemaFormat  string    `json:"schema_format" db:"schema_format"` // "json" or "cedar"
	Version       string    `json:"version" db:"version"`
	IsActive      bool      `json:"is_active" db:"is_active"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
	CreatedBy     string    `json:"created_by" db:"created_by"`
	UpdatedBy     string    `json:"updated_by" db:"updated_by"`
}

// CreateCedarSchemaRequest is the request body to create a Cedar schema.
type CreateCedarSchemaRequest struct {
	Namespace     string `json:"namespace"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	SchemaContent string `json:"schema_content"`
	SchemaFormat  string `json:"schema_format"`
	Version       string `json:"version"`
}

// UpdateCedarSchemaRequest is the request body to update a Cedar schema.
type UpdateCedarSchemaRequest struct {
	Name          *string `json:"name"`
	Description   *string `json:"description"`
	SchemaContent *string `json:"schema_content"`
	SchemaFormat  *string `json:"schema_format"`
	Version       *string `json:"version"`
	IsActive      *bool   `json:"is_active"`
}

// Validate checks if the Cedar schema creation request is valid.
func (r *CreateCedarSchemaRequest) Validate() error {
	if r.Namespace == "" {
		return ErrInvalidInput
	}
	if r.Name == "" {
		return ErrInvalidInput
	}
	if r.SchemaContent == "" {
		return ErrInvalidInput
	}
	if r.SchemaFormat != "json" && r.SchemaFormat != "cedar" {
		return ErrInvalidInput
	}
	if r.Version == "" {
		return ErrInvalidInput
	}
	return nil
}

// ToSchema converts a creation request to a CedarSchema.
func (r *CreateCedarSchemaRequest) ToSchema(createdBy string) *CedarSchema {
	now := time.Now()
	return &CedarSchema{
		ID:            uuid.New(),
		Namespace:     r.Namespace,
		Name:          r.Name,
		Description:   r.Description,
		SchemaContent: r.SchemaContent,
		SchemaFormat:  r.SchemaFormat,
		Version:       r.Version,
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     createdBy,
		UpdatedBy:     createdBy,
	}
}

// CedarTemplate represents a reusable Cedar policy template with placeholders.
type CedarTemplate struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	Name            string     `json:"name" db:"name"`
	Description     string     `json:"description" db:"description"`
	TemplateContent string     `json:"template_content" db:"template_content"`
	SchemaID        *uuid.UUID `json:"schema_id,omitempty" db:"schema_id"`
	Namespace       string     `json:"namespace" db:"namespace"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at" db:"updated_at"`
	CreatedBy       string     `json:"created_by" db:"created_by"`
	UpdatedBy       string     `json:"updated_by" db:"updated_by"`
}

// CreateCedarTemplateRequest is the request body to create a Cedar template.
type CreateCedarTemplateRequest struct {
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	TemplateContent string     `json:"template_content"`
	SchemaID        *uuid.UUID `json:"schema_id,omitempty"`
	Namespace       string     `json:"namespace"`
}

// Validate checks if the Cedar template creation request is valid.
func (r *CreateCedarTemplateRequest) Validate() error {
	if r.Name == "" {
		return ErrInvalidInput
	}
	if r.TemplateContent == "" {
		return ErrInvalidInput
	}
	if r.Namespace == "" {
		return ErrInvalidInput
	}
	return nil
}

// ToTemplate converts a creation request to a CedarTemplate.
func (r *CreateCedarTemplateRequest) ToTemplate(createdBy string) *CedarTemplate {
	now := time.Now()
	return &CedarTemplate{
		ID:              uuid.New(),
		Name:            r.Name,
		Description:     r.Description,
		TemplateContent: r.TemplateContent,
		SchemaID:        r.SchemaID,
		Namespace:       r.Namespace,
		CreatedAt:       now,
		UpdatedAt:       now,
		CreatedBy:       createdBy,
		UpdatedBy:       createdBy,
	}
}

// CedarLinkedPolicy represents a policy instantiated from a template.
type CedarLinkedPolicy struct {
	ID              uuid.UUID `json:"id" db:"id"`
	TemplateID      uuid.UUID `json:"template_id" db:"template_id"`
	PolicyID        uuid.UUID `json:"policy_id" db:"policy_id"`
	PrincipalEntity string    `json:"principal_entity" db:"principal_entity"`
	ResourceEntity  string    `json:"resource_entity" db:"resource_entity"`
	CreatedAt       time.Time `json:"created_at" db:"created_at"`
	CreatedBy       string    `json:"created_by" db:"created_by"`
}

// InstantiateTemplateRequest is the request body to create a linked policy from a template.
type InstantiateTemplateRequest struct {
	PrincipalEntity string `json:"principal_entity"`
	ResourceEntity  string `json:"resource_entity"`
}

// CedarEntity represents a cached Cedar entity stored in the database.
type CedarEntity struct {
	ID         uuid.UUID       `json:"id" db:"id"`
	EntityUID  string          `json:"entity_uid" db:"entity_uid"`
	EntityType string          `json:"entity_type" db:"entity_type"`
	Namespace  string          `json:"namespace" db:"namespace"`
	Attributes json.RawMessage `json:"attributes" db:"attributes"`
	Parents    json.RawMessage `json:"parents" db:"parents"`
	CreatedAt  time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at" db:"updated_at"`
}

// CedarTestRequest is the request body for testing a Cedar policy.
type CedarTestRequest struct {
	PolicyContent      string                 `json:"policy_content"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes"`
	Action             string                 `json:"action"`
	Environment        map[string]interface{} `json:"environment"`
	Namespace          string                 `json:"namespace,omitempty"`
}

// CedarAnalyzeRequest is the request body for analyzing which policies apply.
type CedarAnalyzeRequest struct {
	PrincipalEntity string `json:"principal_entity"`
	ResourceEntity  string `json:"resource_entity"`
	Action          string `json:"action"`
	Namespace       string `json:"namespace,omitempty"`
}
