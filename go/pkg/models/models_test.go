package models

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *Policy
		wantErr error
	}{
		{
			name: "Valid OPA policy",
			policy: &Policy{
				ID:            uuid.New(),
				Name:          "test-policy",
				Description:   "Test policy",
				Language:      PolicyLanguageOPA,
				PolicyContent: "package test\nallow { true }",
				Effect:        PolicyEffectAllow,
				Priority:      50,
				Enabled:       true,
			},
			wantErr: nil,
		},
		{
			name: "Valid XACML policy",
			policy: &Policy{
				ID:            uuid.New(),
				Name:          "test-xacml-policy",
				Description:   "Test XACML policy",
				Language:      PolicyLanguageXACML,
				PolicyContent: "<Policy>...</Policy>",
				Effect:        PolicyEffectDeny,
				Priority:      10,
				Enabled:       false,
			},
			wantErr: nil,
		},
		{
			name: "Invalid - empty name",
			policy: &Policy{
				Name:          "",
				PolicyContent: "package test",
				Language:      PolicyLanguageOPA,
				Effect:        PolicyEffectAllow,
			},
			wantErr: ErrInvalidPolicyName,
		},
		{
			name: "Invalid - empty policy content",
			policy: &Policy{
				Name:          "test",
				PolicyContent: "",
				Language:      PolicyLanguageOPA,
				Effect:        PolicyEffectAllow,
			},
			wantErr: ErrInvalidPolicyContent,
		},
		{
			name: "Invalid - invalid language",
			policy: &Policy{
				Name:          "test",
				PolicyContent: "content",
				Language:      PolicyLanguage("invalid"),
				Effect:        PolicyEffectAllow,
			},
			wantErr: ErrInvalidPolicyLanguage,
		},
		{
			name: "Invalid - invalid effect",
			policy: &Policy{
				Name:          "test",
				PolicyContent: "content",
				Language:      PolicyLanguageOPA,
				Effect:        PolicyEffect("invalid"),
			},
			wantErr: ErrInvalidPolicyEffect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreatePolicyRequest_ToPolicy(t *testing.T) {
	req := &CreatePolicyRequest{
		Name:          "test-policy",
		Description:   "Test description",
		Language:      PolicyLanguageOPA,
		PolicyContent: "package test\nallow { true }",
		Effect:        PolicyEffectAllow,
		Priority:      50,
		Enabled:       true,
	}

	createdBy := "test-user"
	policy := req.ToPolicy(createdBy)

	if policy.Name != req.Name {
		t.Errorf("Expected name %s, got %s", req.Name, policy.Name)
	}

	if policy.Description != req.Description {
		t.Errorf("Expected description %s, got %s", req.Description, policy.Description)
	}

	if policy.Language != req.Language {
		t.Errorf("Expected language %s, got %s", req.Language, policy.Language)
	}

	if policy.PolicyContent != req.PolicyContent {
		t.Errorf("Expected policy content %s, got %s", req.PolicyContent, policy.PolicyContent)
	}

	if policy.Effect != req.Effect {
		t.Errorf("Expected effect %s, got %s", req.Effect, policy.Effect)
	}

	if policy.Priority != req.Priority {
		t.Errorf("Expected priority %d, got %d", req.Priority, policy.Priority)
	}

	if policy.Enabled != req.Enabled {
		t.Errorf("Expected enabled %v, got %v", req.Enabled, policy.Enabled)
	}

	if !policy.CreatedBy.Valid || policy.CreatedBy.String != createdBy {
		t.Errorf("Expected created_by %s, got %v", createdBy, policy.CreatedBy)
	}

	if !policy.UpdatedBy.Valid || policy.UpdatedBy.String != createdBy {
		t.Errorf("Expected updated_by %s, got %v", createdBy, policy.UpdatedBy)
	}

	if policy.ID == uuid.Nil {
		t.Error("Expected non-nil UUID")
	}

	if policy.CreatedAt.IsZero() {
		t.Error("Expected non-zero CreatedAt")
	}

	if policy.UpdatedAt.IsZero() {
		t.Error("Expected non-zero UpdatedAt")
	}
}

func TestPolicy_ApplyUpdate(t *testing.T) {
	now := time.Now()
	policy := &Policy{
		ID:            uuid.New(),
		Name:          "original-name",
		Description:   "original-description",
		Language:      PolicyLanguageOPA,
		PolicyContent: "original-content",
		Effect:        PolicyEffectAllow,
		Priority:      50,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     sql.NullString{String: "creator", Valid: true},
		UpdatedBy:     sql.NullString{String: "creator", Valid: true},
	}

	newName := "updated-name"
	newDescription := "updated-description"
	newLanguage := PolicyLanguageXACML
	newContent := "updated-content"
	newEffect := PolicyEffectDeny
	newPriority := 100
	newEnabled := false

	updateReq := &UpdatePolicyRequest{
		Name:          &newName,
		Description:   &newDescription,
		Language:      &newLanguage,
		PolicyContent: &newContent,
		Effect:        &newEffect,
		Priority:      &newPriority,
		Enabled:       &newEnabled,
	}

	updatedBy := "updater"
	policy.ApplyUpdate(updateReq, updatedBy)

	if policy.Name != newName {
		t.Errorf("Expected name %s, got %s", newName, policy.Name)
	}

	if policy.Description != newDescription {
		t.Errorf("Expected description %s, got %s", newDescription, policy.Description)
	}

	if policy.Language != newLanguage {
		t.Errorf("Expected language %s, got %s", newLanguage, policy.Language)
	}

	if policy.PolicyContent != newContent {
		t.Errorf("Expected content %s, got %s", newContent, policy.PolicyContent)
	}

	if policy.Effect != newEffect {
		t.Errorf("Expected effect %s, got %s", newEffect, policy.Effect)
	}

	if policy.Priority != newPriority {
		t.Errorf("Expected priority %d, got %d", newPriority, policy.Priority)
	}

	if policy.Enabled != newEnabled {
		t.Errorf("Expected enabled %v, got %v", newEnabled, policy.Enabled)
	}

	if !policy.UpdatedBy.Valid || policy.UpdatedBy.String != updatedBy {
		t.Errorf("Expected updated_by %s, got %v", updatedBy, policy.UpdatedBy)
	}

	if policy.UpdatedAt.Before(now) || policy.UpdatedAt.Equal(now) {
		t.Error("Expected UpdatedAt to be after original time")
	}

	// Verify CreatedBy didn't change
	if !policy.CreatedBy.Valid || policy.CreatedBy.String != "creator" {
		t.Errorf("Expected created_by to remain 'creator', got %v", policy.CreatedBy)
	}
}

func TestPolicy_ApplyUpdate_PartialUpdate(t *testing.T) {
	policy := &Policy{
		ID:            uuid.New(),
		Name:          "original-name",
		Description:   "original-description",
		Language:      PolicyLanguageOPA,
		PolicyContent: "original-content",
		Effect:        PolicyEffectAllow,
		Priority:      50,
		Enabled:       true,
	}

	newName := "updated-name"
	updateReq := &UpdatePolicyRequest{
		Name: &newName,
		// Only updating name, other fields should remain unchanged
	}

	policy.ApplyUpdate(updateReq, "updater")

	if policy.Name != newName {
		t.Errorf("Expected name %s, got %s", newName, policy.Name)
	}

	// Verify other fields unchanged
	if policy.Description != "original-description" {
		t.Errorf("Expected description unchanged, got %s", policy.Description)
	}

	if policy.Language != PolicyLanguageOPA {
		t.Errorf("Expected language unchanged, got %s", policy.Language)
	}

	if policy.PolicyContent != "original-content" {
		t.Errorf("Expected content unchanged, got %s", policy.PolicyContent)
	}
}

func TestPolicy_MarshalJSON(t *testing.T) {
	policyID := uuid.New()
	policy := &Policy{
		ID:            policyID,
		Name:          "test-policy",
		Description:   "Test description",
		Language:      PolicyLanguageOPA,
		PolicyContent: "package test",
		Effect:        PolicyEffectAllow,
		Priority:      50,
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		CreatedBy:     sql.NullString{String: "creator", Valid: true},
		UpdatedBy:     sql.NullString{String: "updater", Valid: true},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal policy: %v", err)
	}

	if result["id"] != policyID.String() {
		t.Errorf("Expected id %s, got %v", policyID.String(), result["id"])
	}

	if result["created_by"] != "creator" {
		t.Errorf("Expected created_by 'creator', got %v", result["created_by"])
	}

	if result["updated_by"] != "updater" {
		t.Errorf("Expected updated_by 'updater', got %v", result["updated_by"])
	}
}

func TestPolicy_MarshalJSON_NullStrings(t *testing.T) {
	policy := &Policy{
		ID:            uuid.New(),
		Name:          "test-policy",
		Language:      PolicyLanguageOPA,
		PolicyContent: "package test",
		Effect:        PolicyEffectAllow,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		CreatedBy:     sql.NullString{Valid: false},
		UpdatedBy:     sql.NullString{Valid: false},
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal policy: %v", err)
	}

	if result["created_by"] != "" {
		t.Errorf("Expected empty created_by, got %v", result["created_by"])
	}

	if result["updated_by"] != "" {
		t.Errorf("Expected empty updated_by, got %v", result["updated_by"])
	}
}

func TestEntitlement_Validate(t *testing.T) {
	tests := []struct {
		name        string
		entitlement *Entitlement
		wantErr     error
	}{
		{
			name: "Valid entitlement",
			entitlement: &Entitlement{
				ID:                 uuid.New(),
				Name:               "test-entitlement",
				SubjectAttributes:  map[string]interface{}{"role": "user"},
				ResourceAttributes: map[string]interface{}{"type": "document"},
				Actions:            []string{"read", "write"},
				Enabled:            true,
			},
			wantErr: nil,
		},
		{
			name: "Invalid - empty name",
			entitlement: &Entitlement{
				Name:              "",
				SubjectAttributes: map[string]interface{}{"role": "user"},
				Actions:           []string{"read"},
			},
			wantErr: ErrInvalidEntitlementName,
		},
		{
			name: "Invalid - empty subject attributes",
			entitlement: &Entitlement{
				Name:              "test",
				SubjectAttributes: map[string]interface{}{},
				Actions:           []string{"read"},
			},
			wantErr: ErrInvalidSubjectAttributes,
		},
		{
			name: "Invalid - empty actions",
			entitlement: &Entitlement{
				Name:              "test",
				SubjectAttributes: map[string]interface{}{"role": "user"},
				Actions:           []string{},
			},
			wantErr: ErrInvalidActions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entitlement.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEntitlement_IsExpired(t *testing.T) {
	tests := []struct {
		name        string
		expiresAt   *time.Time
		wantExpired bool
	}{
		{
			name:        "Not expired - nil expiration",
			expiresAt:   nil,
			wantExpired: false,
		},
		{
			name:        "Not expired - future date",
			expiresAt:   func() *time.Time { t := time.Now().Add(24 * time.Hour); return &t }(),
			wantExpired: false,
		},
		{
			name:        "Expired - past date",
			expiresAt:   func() *time.Time { t := time.Now().Add(-24 * time.Hour); return &t }(),
			wantExpired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &Entitlement{
				ExpiresAt: tt.expiresAt,
			}

			if got := ent.IsExpired(); got != tt.wantExpired {
				t.Errorf("IsExpired() = %v, want %v", got, tt.wantExpired)
			}
		})
	}
}

func TestEntitlement_IsActive(t *testing.T) {
	futureTime := time.Now().Add(24 * time.Hour)
	pastTime := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		name       string
		enabled    bool
		expiresAt  *time.Time
		wantActive bool
	}{
		{
			name:       "Active - enabled and not expired",
			enabled:    true,
			expiresAt:  nil,
			wantActive: true,
		},
		{
			name:       "Active - enabled with future expiration",
			enabled:    true,
			expiresAt:  &futureTime,
			wantActive: true,
		},
		{
			name:       "Inactive - disabled",
			enabled:    false,
			expiresAt:  nil,
			wantActive: false,
		},
		{
			name:       "Inactive - expired",
			enabled:    true,
			expiresAt:  &pastTime,
			wantActive: false,
		},
		{
			name:       "Inactive - disabled and expired",
			enabled:    false,
			expiresAt:  &pastTime,
			wantActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ent := &Entitlement{
				Enabled:   tt.enabled,
				ExpiresAt: tt.expiresAt,
			}

			if got := ent.IsActive(); got != tt.wantActive {
				t.Errorf("IsActive() = %v, want %v", got, tt.wantActive)
			}
		})
	}
}

func TestErrors(t *testing.T) {
	// Test that all errors are defined
	errors := []error{
		ErrPolicyNotFound,
		ErrPolicyAlreadyExists,
		ErrInvalidPolicyName,
		ErrInvalidPolicyContent,
		ErrInvalidPolicyLanguage,
		ErrInvalidPolicyEffect,
		ErrPolicyEvaluationFailed,
		ErrEntitlementNotFound,
		ErrEntitlementAlreadyExists,
		ErrInvalidEntitlementName,
		ErrInvalidSubjectAttributes,
		ErrInvalidResourceAttributes,
		ErrInvalidActions,
		ErrEntitlementExpired,
		ErrEntitlementEvaluationFailed,
		ErrDatabaseConnection,
		ErrDatabaseQuery,
		ErrDatabaseInsert,
		ErrDatabaseUpdate,
		ErrDatabaseDelete,
		ErrInvalidInput,
		ErrUnauthorized,
		ErrForbidden,
		ErrInternalServer,
		ErrNotImplemented,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("Found nil error")
		}
		if err.Error() == "" {
			t.Errorf("Error has empty message: %v", err)
		}
	}
}
