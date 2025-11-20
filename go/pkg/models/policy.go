package models

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// PolicyLanguage represents the policy definition language
type PolicyLanguage string

const (
	PolicyLanguageXACML PolicyLanguage = "xacml"
	PolicyLanguageOPA   PolicyLanguage = "opa"
	PolicyLanguageJSON  PolicyLanguage = "json"
)

// PolicyEffect represents whether a policy allows or denies access
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// Policy represents an ABAC policy
type Policy struct {
	ID            uuid.UUID        `json:"id" db:"id"`
	Name          string           `json:"name" db:"name"`
	Description   string           `json:"description" db:"description"`
	Language      PolicyLanguage   `json:"language" db:"language"`
	PolicyContent string           `json:"policy_content" db:"policy_content"`
	Effect        PolicyEffect     `json:"effect" db:"effect"`
	Priority      int              `json:"priority" db:"priority"`
	Enabled       bool             `json:"enabled" db:"enabled"`
	CreatedAt     time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time        `json:"updated_at" db:"updated_at"`
	CreatedBy     sql.NullString   `json:"created_by" db:"created_by"`
	UpdatedBy     sql.NullString   `json:"updated_by" db:"updated_by"`
}

// CreatePolicyRequest represents a request to create a new policy
type CreatePolicyRequest struct {
	Name          string         `json:"name" binding:"required"`
	Description   string         `json:"description"`
	Language      PolicyLanguage `json:"language" binding:"required,oneof=xacml opa json"`
	PolicyContent string         `json:"policy_content" binding:"required"`
	Effect        PolicyEffect   `json:"effect" binding:"required,oneof=allow deny"`
	Priority      int            `json:"priority"`
	Enabled       bool           `json:"enabled"`
}

// UpdatePolicyRequest represents a request to update an existing policy
type UpdatePolicyRequest struct {
	Name          *string         `json:"name"`
	Description   *string         `json:"description"`
	Language      *PolicyLanguage `json:"language"`
	PolicyContent *string         `json:"policy_content"`
	Effect        *PolicyEffect   `json:"effect"`
	Priority      *int            `json:"priority"`
	Enabled       *bool           `json:"enabled"`
}

// PolicyEvaluationRequest represents a request to evaluate or test a policy
type PolicyEvaluationRequest struct {
	PolicyID           *uuid.UUID             `json:"policy_id,omitempty"`
	PolicyContent      *string                `json:"policy_content,omitempty"`
	Language           PolicyLanguage         `json:"language" binding:"required,oneof=xacml opa json"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes" binding:"required"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes" binding:"required"`
	Action             string                 `json:"action" binding:"required"`
	Environment        map[string]interface{} `json:"environment"`
}

// PolicyEvaluationResult represents the result of a policy evaluation
type PolicyEvaluationResult struct {
	Decision   string                 `json:"decision"`
	PolicyID   *uuid.UUID             `json:"policy_id,omitempty"`
	PolicyName string                 `json:"policy_name,omitempty"`
	Reason     string                 `json:"reason"`
	Details    map[string]interface{} `json:"details"`
	EvaluatedAt time.Time             `json:"evaluated_at"`
}

// ListPoliciesRequest represents query parameters for listing policies
type ListPoliciesRequest struct {
	Language *PolicyLanguage `form:"language"`
	Enabled  *bool           `form:"enabled"`
	Effect   *PolicyEffect   `form:"effect"`
	Limit    int             `form:"limit"`
	Offset   int             `form:"offset"`
}

// ToPolicy converts CreatePolicyRequest to Policy
func (r *CreatePolicyRequest) ToPolicy(createdBy string) *Policy {
	now := time.Now()
	return &Policy{
		ID:            uuid.New(),
		Name:          r.Name,
		Description:   r.Description,
		Language:      r.Language,
		PolicyContent: r.PolicyContent,
		Effect:        r.Effect,
		Priority:      r.Priority,
		Enabled:       r.Enabled,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     sql.NullString{String: createdBy, Valid: createdBy != ""},
		UpdatedBy:     sql.NullString{String: createdBy, Valid: createdBy != ""},
	}
}

// ApplyUpdate applies UpdatePolicyRequest changes to a Policy
func (p *Policy) ApplyUpdate(req *UpdatePolicyRequest, updatedBy string) {
	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.Description != nil {
		p.Description = *req.Description
	}
	if req.Language != nil {
		p.Language = *req.Language
	}
	if req.PolicyContent != nil {
		p.PolicyContent = *req.PolicyContent
	}
	if req.Effect != nil {
		p.Effect = *req.Effect
	}
	if req.Priority != nil {
		p.Priority = *req.Priority
	}
	if req.Enabled != nil {
		p.Enabled = *req.Enabled
	}
	p.UpdatedBy = sql.NullString{String: updatedBy, Valid: updatedBy != ""}
	p.UpdatedAt = time.Now()
}

// Validate checks if the policy is valid
func (p *Policy) Validate() error {
	if p.Name == "" {
		return ErrInvalidPolicyName
	}
	if p.PolicyContent == "" {
		return ErrInvalidPolicyContent
	}
	if p.Language != PolicyLanguageXACML && p.Language != PolicyLanguageOPA && p.Language != PolicyLanguageJSON {
		return ErrInvalidPolicyLanguage
	}
	if p.Effect != PolicyEffectAllow && p.Effect != PolicyEffectDeny {
		return ErrInvalidPolicyEffect
	}
	return nil
}

// MarshalJSON customizes JSON serialization
func (p *Policy) MarshalJSON() ([]byte, error) {
	type Alias Policy

	createdBy := ""
	if p.CreatedBy.Valid {
		createdBy = p.CreatedBy.String
	}

	updatedBy := ""
	if p.UpdatedBy.Valid {
		updatedBy = p.UpdatedBy.String
	}

	return json.Marshal(&struct {
		*Alias
		ID        string `json:"id"`
		CreatedBy string `json:"created_by"`
		UpdatedBy string `json:"updated_by"`
	}{
		Alias:     (*Alias)(p),
		ID:        p.ID.String(),
		CreatedBy: createdBy,
		UpdatedBy: updatedBy,
	})
}