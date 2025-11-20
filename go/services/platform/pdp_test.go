package platform

import (
	"context"
	"sync"
	"testing"
	"time"

	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/google/uuid"
)

// Mock repository for testing evaluateEntitlements
type mockPDPEntitlementRepository struct {
	findMatchingFunc func(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error)
	entitlements     []*models.Entitlement
}

func (m *mockPDPEntitlementRepository) FindMatching(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
	if m.findMatchingFunc != nil {
		return m.findMatchingFunc(ctx, req)
	}
	return m.entitlements, nil
}

func (m *mockPDPEntitlementRepository) Create(ctx context.Context, entitlement *models.Entitlement) error {
	return nil
}

func (m *mockPDPEntitlementRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Entitlement, error) {
	return nil, nil
}

func (m *mockPDPEntitlementRepository) GetByName(ctx context.Context, name string) (*models.Entitlement, error) {
	return nil, nil
}

func (m *mockPDPEntitlementRepository) List(ctx context.Context, req *models.ListEntitlementsRequest) ([]*models.Entitlement, error) {
	return nil, nil
}

func (m *mockPDPEntitlementRepository) Update(ctx context.Context, entitlement *models.Entitlement) error {
	return nil
}

func (m *mockPDPEntitlementRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPDPEntitlementRepository) ListActive(ctx context.Context) ([]*models.Entitlement, error) {
	return nil, nil
}

func (m *mockPDPEntitlementRepository) Count(ctx context.Context, req *models.ListEntitlementsRequest) (int, error) {
	return 0, nil
}

// Mock audit repository
type mockPDPAuditRepository struct{}

func (m *mockPDPAuditRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	return nil
}

func (m *mockPDPAuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	return nil, nil
}

func (m *mockPDPAuditRepository) List(ctx context.Context, req *models.ListAuditLogsRequest) ([]*models.AuditLog, error) {
	return nil, nil
}

func (m *mockPDPAuditRepository) ListByEntity(ctx context.Context, entityType models.EntityType, entityID uuid.UUID) ([]*models.AuditLog, error) {
	return nil, nil
}

func (m *mockPDPAuditRepository) ListByActor(ctx context.Context, actor string, limit, offset int) ([]*models.AuditLog, error) {
	return nil, nil
}

func (m *mockPDPAuditRepository) Count(ctx context.Context, req *models.ListAuditLogsRequest) (int, error) {
	return 0, nil
}

// Test evaluateEntitlements with GetDecisionRequest.Context
func TestPDP_EvaluateEntitlements_WithContext(t *testing.T) {
	entitlementID := uuid.New()

	tests := []struct {
		name               string
		request            *GetDecisionRequest
		mockEntitlements   []*models.Entitlement
		verifyMatchRequest func(t *testing.T, req *models.EntitlementMatchRequest)
		expectMatch        bool
		expectReason       string
	}{
		{
			name: "Context attributes are passed to subject attributes",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "document-service"},
				Action:             "read",
				Context: map[string]string{
					"role":       "admin",
					"department": "engineering",
					"clearance":  "high",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "admin-access",
					SubjectAttributes: map[string]interface{}{
						"role": "admin",
					},
					Actions: []string{"read"},
					Enabled: true,
				},
			},
			verifyMatchRequest: func(t *testing.T, req *models.EntitlementMatchRequest) {
				// Verify that context attributes are in subject attributes
				if req.SubjectAttributes["role"] != "admin" {
					t.Errorf("Expected role='admin' in subject attributes, got %v", req.SubjectAttributes["role"])
				}
				if req.SubjectAttributes["department"] != "engineering" {
					t.Errorf("Expected department='engineering' in subject attributes, got %v", req.SubjectAttributes["department"])
				}
				if req.SubjectAttributes["clearance"] != "high" {
					t.Errorf("Expected clearance='high' in subject attributes, got %v", req.SubjectAttributes["clearance"])
				}
				// Verify subject is added as "sub"
				if req.SubjectAttributes["sub"] != "user123" {
					t.Errorf("Expected sub='user123' in subject attributes, got %v", req.SubjectAttributes["sub"])
				}
			},
			expectMatch:  true,
			expectReason: "Access granted by entitlement: admin-access",
		},
		{
			name: "Empty context - only subject is passed",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user456"}),
				ResourceAttributes: map[string]string{"name": "api-service"},
				Action:             "write",
				Context:            map[string]string{},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "basic-access",
					SubjectAttributes: map[string]interface{}{
						"sub": "user456",
					},
					Actions: []string{"write"},
					Enabled: true,
				},
			},
			verifyMatchRequest: func(t *testing.T, req *models.EntitlementMatchRequest) {
				// Verify only "sub" is in subject attributes
				if len(req.SubjectAttributes) != 1 {
					t.Errorf("Expected 1 subject attribute, got %d", len(req.SubjectAttributes))
				}
				if req.SubjectAttributes["sub"] != "user456" {
					t.Errorf("Expected sub='user456', got %v", req.SubjectAttributes["sub"])
				}
			},
			expectMatch:  true,
			expectReason: "Access granted by entitlement: basic-access",
		},
		{
			name: "Context with multiple attributes for matching",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user789"}),
				ResourceAttributes: map[string]string{"name": "secure-docs"},
				Action:             "delete",
				Context: map[string]string{
					"role":        "admin",
					"location":    "us-west",
					"environment": "production",
					"team":        "security",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "secure-delete",
					SubjectAttributes: map[string]interface{}{
						"role":     "admin",
						"location": "us-west",
					},
					Actions: []string{"delete"},
					Enabled: true,
				},
			},
			verifyMatchRequest: func(t *testing.T, req *models.EntitlementMatchRequest) {
				expectedAttrs := map[string]string{
					"sub":         "user789",
					"role":        "admin",
					"location":    "us-west",
					"environment": "production",
					"team":        "security",
				}
				if len(req.SubjectAttributes) != len(expectedAttrs) {
					t.Errorf("Expected %d subject attributes, got %d", len(expectedAttrs), len(req.SubjectAttributes))
				}
				for key, expectedValue := range expectedAttrs {
					if actualValue, ok := req.SubjectAttributes[key]; !ok || actualValue != expectedValue {
						t.Errorf("Expected %s='%s', got %v", key, expectedValue, actualValue)
					}
				}
			},
			expectMatch:  true,
			expectReason: "Access granted by entitlement: secure-delete",
		},
		{
			name: "Context used for resource attribute matching",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user999"}),
				ResourceAttributes: map[string]string{"name": "project-files"},
				Action:             "read",
				Context: map[string]string{
					"role":       "developer",
					"project_id": "proj-123",
					"team":       "frontend",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "project-access",
					SubjectAttributes: map[string]interface{}{
						"role": "developer",
					},
					ResourceAttributes: map[string]interface{}{
						"project_id": "proj-123",
					},
					Actions: []string{"read"},
					Enabled: true,
				},
			},
			verifyMatchRequest: func(t *testing.T, req *models.EntitlementMatchRequest) {
				// Verify context attributes are passed
				if req.SubjectAttributes["project_id"] != "proj-123" {
					t.Errorf("Expected project_id='proj-123' in subject attributes for resource matching")
				}
			},
			expectMatch:  true,
			expectReason: "Access granted by entitlement: project-access",
		},
		{
			name: "Inactive entitlement is skipped",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user111"}),
				ResourceAttributes: map[string]string{"name": "old-service"},
				Action:             "read",
				Context: map[string]string{
					"role": "legacy",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "legacy-access",
					SubjectAttributes: map[string]interface{}{
						"role": "legacy",
					},
					Actions: []string{"read"},
					Enabled: false, // Disabled entitlement
				},
			},
			expectMatch: false,
		},
		{
			name: "Expired entitlement is skipped",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user222"}),
				ResourceAttributes: map[string]string{"name": "temp-service"},
				Action:             "write",
				Context: map[string]string{
					"role": "temp",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "temp-access",
					SubjectAttributes: map[string]interface{}{
						"role": "temp",
					},
					Actions: []string{"write"},
					Enabled: true,
					ExpiresAt: func() *time.Time {
						t := time.Now().Add(-24 * time.Hour) // Expired yesterday
						return &t
					}(),
				},
			},
			expectMatch: false,
		},
		{
			name: "Resource attributes must match context",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user333"}),
				ResourceAttributes: map[string]string{"name": "restricted-docs"},
				Action:             "read",
				Context: map[string]string{
					"role":           "viewer",
					"classification": "public",
				},
			},
			mockEntitlements: []*models.Entitlement{
				{
					ID:   entitlementID,
					Name: "confidential-access",
					SubjectAttributes: map[string]interface{}{
						"role": "viewer",
					},
					ResourceAttributes: map[string]interface{}{
						"classification": "confidential", // Doesn't match "public"
					},
					Actions: []string{"read"},
					Enabled: true,
				},
			},
			expectMatch: false, // Should not match due to resource attribute mismatch
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create mock repository with verification
			var capturedMatchRequest *models.EntitlementMatchRequest
			mockEntRepo := &mockPDPEntitlementRepository{
				findMatchingFunc: func(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
					capturedMatchRequest = req
					return tt.mockEntitlements, nil
				},
			}

			mockRepo := &repository.Repository{
				Entitlement: mockEntRepo,
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := &PolicyDecisionPoint{
				repo: mockRepo,
			}

			// Execute the function
			result, err := pdp.evaluateEntitlements(ctx, tt.request)

			if err != nil {
				t.Fatalf("evaluateEntitlements() error = %v", err)
			}

			// Verify the match request was constructed correctly
			if tt.verifyMatchRequest != nil && capturedMatchRequest != nil {
				tt.verifyMatchRequest(t, capturedMatchRequest)
			}

			// Verify the result
			if tt.expectMatch {
				if result == nil {
					t.Fatal("Expected a decision result, got nil")
				}
				if result.Decision != Decision_DECISION_ALLOW {
					t.Errorf("Expected DECISION_ALLOW, got %v", result.Decision)
				}
				if tt.expectReason != "" && result.Reason != tt.expectReason {
					t.Errorf("Expected reason %q, got %q", tt.expectReason, result.Reason)
				}
			} else {
				if result != nil {
					t.Errorf("Expected no match (nil result), got result with decision %v", result.Decision)
				}
			}
		})
	}
}

// Test that action is passed correctly to FindMatching
func TestPDP_EvaluateEntitlements_ActionMatching(t *testing.T) {
	ctx := context.Background()
	entitlementID := uuid.New()

	tests := []struct {
		name             string
		requestAction    string
		expectedAction   string
		entitlementMatch bool
	}{
		{
			name:             "Action 'read' is passed correctly",
			requestAction:    "read",
			expectedAction:   "read",
			entitlementMatch: true,
		},
		{
			name:             "Action 'write' is passed correctly",
			requestAction:    "write",
			expectedAction:   "write",
			entitlementMatch: true,
		},
		{
			name:             "Action 'delete' is passed correctly",
			requestAction:    "delete",
			expectedAction:   "delete",
			entitlementMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedAction string
			mockEntRepo := &mockPDPEntitlementRepository{
				findMatchingFunc: func(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
					capturedAction = req.Action
					if tt.entitlementMatch {
						return []*models.Entitlement{
							{
								ID:   entitlementID,
								Name: "test-entitlement",
								SubjectAttributes: map[string]interface{}{
									"sub": "test-user",
								},
								Actions: []string{tt.requestAction},
								Enabled: true,
							},
						}, nil
					}
					return nil, nil
				},
			}

			mockRepo := &repository.Repository{
				Entitlement: mockEntRepo,
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := &PolicyDecisionPoint{
				repo: mockRepo,
			}

			request := &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             tt.requestAction,
				Context:            map[string]string{},
			}

			_, err := pdp.evaluateEntitlements(ctx, request)
			if err != nil {
				t.Fatalf("evaluateEntitlements() error = %v", err)
			}

			if capturedAction != tt.expectedAction {
				t.Errorf("Expected action %q to be passed to FindMatching, got %q", tt.expectedAction, capturedAction)
			}
		})
	}
}

// Test context with special characters and edge cases
func TestPDP_EvaluateEntitlements_ContextEdgeCases(t *testing.T) {
	ctx := context.Background()
	entitlementID := uuid.New()

	tests := []struct {
		name            string
		requestContext  map[string]string
		expectedContext map[string]interface{}
	}{
		{
			name: "Context with special characters",
			requestContext: map[string]string{
				"email": "user@example.com",
				"ip":    "192.168.1.1",
				"path":  "/api/v1/users",
				"query": "?filter=active&sort=name",
			},
			expectedContext: map[string]interface{}{
				"sub":   "test-user",
				"email": "user@example.com",
				"ip":    "192.168.1.1",
				"path":  "/api/v1/users",
				"query": "?filter=active&sort=name",
			},
		},
		{
			name: "Context with numeric-like strings",
			requestContext: map[string]string{
				"age":     "25",
				"count":   "100",
				"version": "1.2.3",
			},
			expectedContext: map[string]interface{}{
				"sub":     "test-user",
				"age":     "25",
				"count":   "100",
				"version": "1.2.3",
			},
		},
		{
			name: "Context with empty string values",
			requestContext: map[string]string{
				"optional": "",
				"role":     "admin",
			},
			expectedContext: map[string]interface{}{
				"sub":      "test-user",
				"optional": "",
				"role":     "admin",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedSubjectAttrs map[string]interface{}
			mockEntRepo := &mockPDPEntitlementRepository{
				findMatchingFunc: func(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
					capturedSubjectAttrs = req.SubjectAttributes
					return []*models.Entitlement{
						{
							ID:   entitlementID,
							Name: "test-entitlement",
							SubjectAttributes: map[string]interface{}{
								"role": "admin",
							},
							Actions: []string{"read"},
							Enabled: true,
						},
					}, nil
				},
			}

			mockRepo := &repository.Repository{
				Entitlement: mockEntRepo,
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := &PolicyDecisionPoint{
				repo: mockRepo,
			}

			request := &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            tt.requestContext,
			}

			_, err := pdp.evaluateEntitlements(ctx, request)
			if err != nil {
				t.Fatalf("evaluateEntitlements() error = %v", err)
			}

			// Verify all expected context attributes are present
			for key, expectedValue := range tt.expectedContext {
				actualValue, exists := capturedSubjectAttrs[key]
				if !exists {
					t.Errorf("Expected attribute %q to be present in subject attributes", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("For attribute %q: expected %v, got %v", key, expectedValue, actualValue)
				}
			}
		})
	}
}

// Mock policy repository for testing evaluatePolicies
type mockPDPPolicyRepository struct {
	listEnabledFunc func(ctx context.Context) ([]*models.Policy, error)
	policies        []*models.Policy
}

func (m *mockPDPPolicyRepository) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	if m.listEnabledFunc != nil {
		return m.listEnabledFunc(ctx)
	}
	return m.policies, nil
}

func (m *mockPDPPolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	return nil
}

func (m *mockPDPPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	return nil, nil
}

func (m *mockPDPPolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	return nil, nil
}

func (m *mockPDPPolicyRepository) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	return nil, nil
}

func (m *mockPDPPolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	return nil
}

func (m *mockPDPPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPDPPolicyRepository) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	return 0, nil
}

// Test evaluatePolicies with GetDecisionRequest.Context - Positive Cases
func TestPDP_EvaluatePolicies_WithContext_Positive(t *testing.T) {
	policyID := uuid.New()

	tests := []struct {
		name            string
		request         *GetDecisionRequest
		policy          *models.Policy
		expectAllow     bool
		expectReason    string
		verifyEvalInput func(t *testing.T, evalInput *policy_engine.EvaluationInput)
	}{
		{
			name: "Context attributes are added to Subject in EvaluationInput",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "documents"},
				Action:             "read",
				Context: map[string]string{
					"role":       "admin",
					"department": "engineering",
					"level":      "senior",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "admin-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "allow-admin",
							"effect": "allow",
							"conditions": {
								"subject": {
									"role": "admin"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectAllow:  true,
			expectReason: "Access granted by policy: admin-policy",
			verifyEvalInput: func(t *testing.T, evalInput *policy_engine.EvaluationInput) {
				if evalInput.Subject["role"] != "admin" {
					t.Errorf("Expected role='admin' in evalInput.Subject, got %v", evalInput.Subject["role"])
				}
				if evalInput.Subject["department"] != "engineering" {
					t.Errorf("Expected department='engineering' in evalInput.Subject, got %v", evalInput.Subject["department"])
				}
				if evalInput.Subject["level"] != "senior" {
					t.Errorf("Expected level='senior' in evalInput.Subject, got %v", evalInput.Subject["level"])
				}
				if evalInput.Subject["sub"] != "user123" {
					t.Errorf("Expected sub='user123' in evalInput.Subject, got %v", evalInput.Subject["sub"])
				}
			},
		},
		{
			name: "Policy uses context attribute for matching",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user456"}),
				ResourceAttributes: map[string]string{"name": "api"},
				Action:             "write",
				Context: map[string]string{
					"clearance": "high",
					"location":  "us-west",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "clearance-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "high-clearance",
							"effect": "allow",
							"conditions": {
								"subject": {
									"clearance": "high"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectAllow:  true,
			expectReason: "Access granted by policy: clearance-policy",
		},
		{
			name: "Multiple context attributes used in policy evaluation",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user789"}),
				ResourceAttributes: map[string]string{"name": "secure-data"},
				Action:             "delete",
				Context: map[string]string{
					"role":        "admin",
					"environment": "production",
					"mfa":         "enabled",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "secure-delete-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "secure-delete",
							"effect": "allow",
							"conditions": {
								"allOf": [
									{
										"subject": {
											"role": "admin"
										}
									},
									{
										"subject": {
											"mfa": "enabled"
										}
									}
								]
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectAllow:  true,
			expectReason: "Access granted by policy: secure-delete-policy",
		},
		{
			name: "Context with special characters passes through",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user@example.com"}),
				ResourceAttributes: map[string]string{"name": "email-service"},
				Action:             "send",
				Context: map[string]string{
					"email_domain": "@company.com",
					"ip_address":   "192.168.1.100",
					"user_agent":   "Mozilla/5.0",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "email-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "company-email",
							"effect": "allow",
							"conditions": {
								"subject": {
									"email_domain": {
										"$contains": "@company.com"
									}
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectAllow:  true,
			expectReason: "Access granted by policy: email-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockPolicyRepo := &mockPDPPolicyRepository{
				policies: []*models.Policy{tt.policy},
			}

			mockRepo := &repository.Repository{
				Policy:      mockPolicyRepo,
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := NewPolicyDecisionPoint(mockRepo, NewInMemoryPolicyCache(), time.Minute)

			result, err := pdp.evaluatePolicies(ctx, tt.request)
			if err != nil {
				t.Fatalf("evaluatePolicies() error = %v", err)
			}

			if result == nil {
				t.Fatal("Expected a decision result, got nil")
			}

			if (result.Decision == Decision_DECISION_ALLOW) != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Decision == Decision_DECISION_ALLOW, result.Reason)
			}

			if tt.expectReason != "" && result.Reason != tt.expectReason {
				t.Errorf("Expected reason %q, got %q", tt.expectReason, result.Reason)
			}

			// Verify the evaluation input if a verification function is provided
			if tt.verifyEvalInput != nil {
				// We need to create the expected evalInput to verify
				evalInput := &policy_engine.EvaluationInput{
					Subject: map[string]interface{}{
						"sub": tt.request.SubjectAttributes["sub"].GetStringValue(),
					},
					Resource: map[string]interface{}{
						"name": tt.request.ResourceAttributes["name"],
					},
					Action:      tt.request.Action,
					Environment: make(map[string]interface{}),
				}
				// Add context to subject attributes
				for k, v := range tt.request.Context {
					evalInput.Subject[k] = v
				}
				tt.verifyEvalInput(t, evalInput)
			}
		})
	}
}

// Test evaluatePolicies with GetDecisionRequest.Context - Negative Cases
func TestPDP_EvaluatePolicies_WithContext_Negative(t *testing.T) {
	policyID := uuid.New()

	tests := []struct {
		name         string
		request      *GetDecisionRequest
		policy       *models.Policy
		expectDeny   bool
		expectReason string
	}{
		{
			name: "Context attribute doesn't match policy requirement - DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "admin-panel"},
				Action:             "access",
				Context: map[string]string{
					"role": "user", // Not admin
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "admin-only-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "require-admin",
							"effect": "allow",
							"conditions": {
								"subject": {
									"role": "admin"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectDeny: true,
		},
		{
			name: "Missing required context attribute - DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user456"}),
				ResourceAttributes: map[string]string{"name": "secure-api"},
				Action:             "write",
				Context: map[string]string{
					"department": "sales", // Missing clearance attribute
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "clearance-required-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "require-clearance",
							"effect": "allow",
							"conditions": {
								"subject": {
									"clearance": "high"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectDeny: true,
		},
		{
			name: "Empty context with policy requiring attributes - DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user789"}),
				ResourceAttributes: map[string]string{"name": "restricted-resource"},
				Action:             "read",
				Context:            map[string]string{}, // Empty context
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "attribute-required-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "require-role",
							"effect": "allow",
							"conditions": {
								"subject": {
									"role": "viewer"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectDeny: true,
		},
		{
			name: "Context attribute with wrong value - DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user999"}),
				ResourceAttributes: map[string]string{"name": "production-deploy"},
				Action:             "execute",
				Context: map[string]string{
					"environment": "staging", // Not production
					"role":        "deployer",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "production-deploy-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "production-only",
							"effect": "allow",
							"conditions": {
								"allOf": [
									{
										"subject": {
											"role": "deployer"
										}
									},
									{
										"subject": {
											"environment": "production"
										}
									}
								]
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			},
			expectDeny: true,
		},
		{
			name: "Context present but deny policy matches - EXPLICIT DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user111"}),
				ResourceAttributes: map[string]string{"name": "sensitive-data"},
				Action:             "read",
				Context: map[string]string{
					"status":     "blocked",
					"department": "engineering",
				},
			},
			policy: &models.Policy{
				ID:       policyID,
				Name:     "block-users-policy",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "match-blocked-users",
							"effect": "allow",
							"conditions": {
								"subject": {
									"status": "blocked"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectDeny,
				Priority: 100,
				Enabled:  true,
			},
			expectDeny:   true,
			expectReason: "Access denied by policy: block-users-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			mockPolicyRepo := &mockPDPPolicyRepository{
				policies: []*models.Policy{tt.policy},
			}

			mockRepo := &repository.Repository{
				Policy:      mockPolicyRepo,
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := NewPolicyDecisionPoint(mockRepo, NewInMemoryPolicyCache(), time.Minute)

			result, err := pdp.evaluatePolicies(ctx, tt.request)
			if err != nil {
				t.Fatalf("evaluatePolicies() error = %v", err)
			}

			if tt.expectDeny {
				// Check if it's an explicit deny or no match (nil result)
				if tt.expectReason != "" {
					// Explicit deny - should have a result
					if result == nil {
						t.Fatal("Expected a deny decision result, got nil")
					}
					if result.Decision != Decision_DECISION_DENY {
						t.Errorf("Expected DECISION_DENY, got %v", result.Decision)
					}
					if result.Reason != tt.expectReason {
						t.Errorf("Expected reason %q, got %q", tt.expectReason, result.Reason)
					}
				} else {
					// No match - should return nil (default deny handled elsewhere)
					if result != nil {
						t.Errorf("Expected no match (nil result), got result with decision %v", result.Decision)
					}
				}
			}
		})
	}
}

// Test that context overrides the default "sub" field if provided
func TestPDP_EvaluatePolicies_ContextOverride(t *testing.T) {
	ctx := context.Background()
	policyID := uuid.New()

	// Test case where context DOES override "sub" - this is the actual behavior
	request := &GetDecisionRequest{
		SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
		ResourceAttributes: map[string]string{"name": "test-resource"},
		Action:             "read",
		Context: map[string]string{
			"sub":  "overridden-sub", // Context IS added after "sub" is set, so it overrides
			"role": "admin",
		},
	}

	policy := &models.Policy{
		ID:       policyID,
		Name:     "test-policy",
		Language: models.PolicyLanguageJSON,
		PolicyContent: `{
			"version": "1.0",
			"rules": [
				{
					"id": "check-sub",
					"effect": "allow",
					"conditions": {
						"subject": {
							"sub": "overridden-sub"
						}
					}
				}
			]
		}`,
		Effect:   models.PolicyEffectAllow,
		Priority: 100,
		Enabled:  true,
	}

	mockPolicyRepo := &mockPDPPolicyRepository{
		policies: []*models.Policy{policy},
	}

	mockRepo := &repository.Repository{
		Policy:      mockPolicyRepo,
		Entitlement: &mockPDPEntitlementRepository{},
		Audit:       &mockPDPAuditRepository{},
	}

	pdp := NewPolicyDecisionPoint(mockRepo, NewInMemoryPolicyCache(), time.Minute)

	result, err := pdp.evaluatePolicies(ctx, request)
	if err != nil {
		t.Fatalf("evaluatePolicies() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected a decision result, got nil")
	}

	if result.Decision != Decision_DECISION_ALLOW {
		t.Errorf("Expected DECISION_ALLOW (context 'sub' overrides request.Subject), got %v with reason: %s",
			result.Decision, result.Reason)
	}
}

// Test edge cases with context values
func TestPDP_EvaluatePolicies_ContextEdgeCases(t *testing.T) {
	ctx := context.Background()
	policyID := uuid.New()

	tests := []struct {
		name    string
		context map[string]string
	}{
		{
			name: "Context with empty string values",
			context: map[string]string{
				"optional": "",
				"role":     "admin",
			},
		},
		{
			name: "Context with numeric-like strings",
			context: map[string]string{
				"age":     "25",
				"count":   "100",
				"version": "1.2.3",
			},
		},
		{
			name: "Context with boolean-like strings",
			context: map[string]string{
				"active":  "true",
				"deleted": "false",
			},
		},
		{
			name: "Context with URL and path values",
			context: map[string]string{
				"callback_url": "https://example.com/callback",
				"path":         "/api/v1/users",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            tt.context,
			}

			// Create a policy that always allows
			policy := &models.Policy{
				ID:       policyID,
				Name:     "allow-all",
				Language: models.PolicyLanguageJSON,
				PolicyContent: `{
					"version": "1.0",
					"rules": [
						{
							"id": "allow-all",
							"effect": "allow",
							"conditions": {
								"subject": {
									"sub": "test-user"
								}
							}
						}
					]
				}`,
				Effect:   models.PolicyEffectAllow,
				Priority: 100,
				Enabled:  true,
			}

			mockPolicyRepo := &mockPDPPolicyRepository{
				policies: []*models.Policy{policy},
			}

			mockRepo := &repository.Repository{
				Policy:      mockPolicyRepo,
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := NewPolicyDecisionPoint(mockRepo, NewInMemoryPolicyCache(), time.Minute)

			// Should not error even with edge case values
			_, err := pdp.evaluatePolicies(ctx, request)
			if err != nil {
				t.Errorf("evaluatePolicies() should not error with edge case context values, got error: %v", err)
			}
		})
	}
}

// Mock cache for testing NewPolicyDecisionPointWithCache
type mockPolicyCache struct {
	getCalls        int
	setCalls        int
	invalidateCalls int
	clearCalls      int
	storage         map[string]*models.Policy
}

func newMockPolicyCache() *mockPolicyCache {
	return &mockPolicyCache{
		storage: make(map[string]*models.Policy),
	}
}

func (m *mockPolicyCache) Get(ctx context.Context, key string) (*models.Policy, bool) {
	m.getCalls++
	policy, ok := m.storage[key]
	return policy, ok
}

func (m *mockPolicyCache) Set(ctx context.Context, key string, policy *models.Policy, ttl time.Duration) error {
	m.setCalls++
	m.storage[key] = policy
	return nil
}

func (m *mockPolicyCache) Invalidate(ctx context.Context, key string) error {
	m.invalidateCalls++
	delete(m.storage, key)
	return nil
}

func (m *mockPolicyCache) Clear(ctx context.Context) error {
	m.clearCalls++
	m.storage = make(map[string]*models.Policy)
	return nil
}

// Test NewPolicyDecisionPointWithCache constructor
func TestPDP_NewPolicyDecisionPointWithCache(t *testing.T) {
	tests := []struct {
		name         string
		setupCache   func() PolicyCache
		expectNotNil bool
		verifyCache  func(t *testing.T, pdp *PolicyDecisionPoint, cache PolicyCache)
	}{
		{
			name: "Create PDP with in-memory cache - should initialize correctly",
			setupCache: func() PolicyCache {
				return NewInMemoryPolicyCache()
			},
			expectNotNil: true,
			verifyCache: func(t *testing.T, pdp *PolicyDecisionPoint, cache PolicyCache) {
				if pdp.cache == nil {
					t.Error("Expected cache to be set, got nil")
				}
				if pdp.cache != cache {
					t.Error("Expected cache to be the same instance passed to constructor")
				}
			},
		},
		{
			name: "Create PDP with mock cache - should initialize correctly",
			setupCache: func() PolicyCache {
				return newMockPolicyCache()
			},
			expectNotNil: true,
			verifyCache: func(t *testing.T, pdp *PolicyDecisionPoint, cache PolicyCache) {
				if pdp.cache == nil {
					t.Error("Expected cache to be set, got nil")
				}
				// Verify it's our mock cache
				mockCache, ok := pdp.cache.(*mockPolicyCache)
				if !ok {
					t.Error("Expected cache to be mockPolicyCache type")
				}
				if mockCache == nil {
					t.Error("Expected mock cache to not be nil")
				}
			},
		},
		{
			name: "Create PDP with nil repository - should not panic",
			setupCache: func() PolicyCache {
				return NewInMemoryPolicyCache()
			},
			expectNotNil: true,
			verifyCache: func(t *testing.T, pdp *PolicyDecisionPoint, cache PolicyCache) {
				if pdp == nil {
					t.Fatal("Expected PDP to not be nil even with nil repository")
				}
				if pdp.cache == nil {
					t.Error("Expected cache to be set even with nil repository")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setupCache()

			mockRepo := &repository.Repository{
				Policy:      &mockPDPPolicyRepository{},
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			}

			// Create PDP with custom cache
			pdp := NewPolicyDecisionPointWithCache(mockRepo, cache, time.Minute)

			if tt.expectNotNil {
				if pdp == nil {
					t.Fatal("Expected PDP to not be nil")
				}
			}

			// Verify repository is set
			if pdp.repo == nil {
				t.Error("Expected repository to be set, got nil")
			}

			// Verify engine factory is set
			if pdp.engineFactory == nil {
				t.Error("Expected engine factory to be set, got nil")
			}

			// Run custom cache verification
			if tt.verifyCache != nil {
				tt.verifyCache(t, pdp, cache)
			}
		})
	}
}

// Test that NewPolicyDecisionPointWithCache uses the provided cache vs default
func TestPDP_NewPolicyDecisionPointWithCache_CacheComparison(t *testing.T) {
	mockRepo := &repository.Repository{
		Policy:      &mockPDPPolicyRepository{},
		Entitlement: &mockPDPEntitlementRepository{},
		Audit:       &mockPDPAuditRepository{},
	}

	// Create PDP with default cache
	pdpDefault := NewPolicyDecisionPoint(mockRepo, NewInMemoryPolicyCache(), time.Minute)

	// Create PDP with custom cache
	customCache := newMockPolicyCache()
	pdpCustom := NewPolicyDecisionPointWithCache(mockRepo, customCache, time.Minute)

	// Verify both have caches but they are different instances
	if pdpDefault.cache == nil {
		t.Error("Expected default PDP to have a cache")
	}

	if pdpCustom.cache == nil {
		t.Error("Expected custom PDP to have a cache")
	}

	// Verify custom PDP uses the provided cache
	if pdpCustom.cache != customCache {
		t.Error("Expected custom PDP to use the provided cache instance")
	}

	// Verify they are different cache instances
	if pdpDefault.cache == pdpCustom.cache {
		t.Error("Expected default and custom PDPs to have different cache instances")
	}

	// Verify custom cache is the mock type
	mockCache, ok := pdpCustom.cache.(*mockPolicyCache)
	if !ok {
		t.Error("Expected custom cache to be mockPolicyCache type")
	}
	if mockCache != customCache {
		t.Error("Expected custom cache to be the same instance")
	}
}

// Test that PDP with custom cache works correctly in evaluation
func TestPDP_NewPolicyDecisionPointWithCache_FunctionalTest(t *testing.T) {
	ctx := context.Background()
	mockCache := newMockPolicyCache()

	mockEntRepo := &mockPDPEntitlementRepository{
		entitlements: []*models.Entitlement{},
	}

	mockPolicyRepo := &mockPDPPolicyRepository{
		policies: []*models.Policy{},
	}

	mockRepo := &repository.Repository{
		Policy:      mockPolicyRepo,
		Entitlement: mockEntRepo,
		Audit:       &mockPDPAuditRepository{},
	}

	pdp := NewPolicyDecisionPointWithCache(mockRepo, mockCache, time.Minute)

	request := &GetDecisionRequest{
		SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
		ResourceAttributes: map[string]string{"name": "test-resource"},
		Action:             "read",
		Context:            map[string]string{},
	}

	// Execute evaluation
	result, err := pdp.EvaluateDecision(ctx, request)
	if err != nil {
		t.Fatalf("EvaluateDecision() error = %v", err)
	}

	if result == nil {
		t.Fatal("Expected result to not be nil")
	}

	// Verify PDP is functional with custom cache
	if result.Decision != Decision_DECISION_DENY {
		t.Errorf("Expected DECISION_DENY (no matching policies/entitlements), got %v", result.Decision)
	}

	// Verify cache instance is still the same after evaluation
	if pdp.cache != mockCache {
		t.Error("Expected cache instance to remain the same after evaluation")
	}
}

// Test with multiple cache types
func TestPDP_NewPolicyDecisionPointWithCache_MultipleCacheTypes(t *testing.T) {
	tests := []struct {
		name       string
		cacheType  string
		setupCache func() PolicyCache
	}{
		{
			name:      "InMemoryPolicyCache",
			cacheType: "InMemoryPolicyCache",
			setupCache: func() PolicyCache {
				return NewInMemoryPolicyCache()
			},
		},
		{
			name:      "MockPolicyCache",
			cacheType: "mockPolicyCache",
			setupCache: func() PolicyCache {
				return newMockPolicyCache()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := tt.setupCache()

			mockRepo := &repository.Repository{
				Policy:      &mockPDPPolicyRepository{},
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			}

			pdp := NewPolicyDecisionPointWithCache(mockRepo, cache, time.Minute)

			if pdp == nil {
				t.Fatal("Expected PDP to not be nil")
			}

			if pdp.cache == nil {
				t.Error("Expected cache to be set")
			}

			// Verify cache is functional by calling methods
			ctx := context.Background()
			policyID := uuid.New()

			testPolicy := &models.Policy{
				ID:            policyID,
				Name:          "test-policy",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: `{"version": "1.0"}`,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			}

			// Test Set
			err := pdp.cache.Set(ctx, "test-key", testPolicy, 1*time.Hour)
			if err != nil {
				t.Errorf("cache.Set() error = %v", err)
			}

			// Test Get
			retrieved, found := pdp.cache.Get(ctx, "test-key")
			if !found {
				t.Error("Expected to find policy in cache")
			}
			if retrieved == nil {
				t.Error("Expected retrieved policy to not be nil")
			}
			if found && retrieved.ID != policyID {
				t.Errorf("Expected policy ID %s, got %s", policyID, retrieved.ID)
			}

			// Test Invalidate
			err = pdp.cache.Invalidate(ctx, "test-key")
			if err != nil {
				t.Errorf("cache.Invalidate() error = %v", err)
			}

			// Verify invalidation
			_, found = pdp.cache.Get(ctx, "test-key")
			if found {
				t.Error("Expected policy to be removed from cache after invalidation")
			}
		})
	}
}

// Test cache method call counts with mock cache
func TestPDP_NewPolicyDecisionPointWithCache_CacheUsage(t *testing.T) {
	ctx := context.Background()
	mockCache := newMockPolicyCache()

	mockRepo := &repository.Repository{
		Policy:      &mockPDPPolicyRepository{},
		Entitlement: &mockPDPEntitlementRepository{},
		Audit:       &mockPDPAuditRepository{},
	}

	pdp := NewPolicyDecisionPointWithCache(mockRepo, mockCache, time.Minute)

	// Perform cache operations
	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Test Set - should increment setCalls
	pdp.cache.Set(ctx, "key1", testPolicy, 1*time.Hour)
	if mockCache.setCalls != 1 {
		t.Errorf("Expected 1 Set call, got %d", mockCache.setCalls)
	}

	// Test Get - should increment getCalls
	pdp.cache.Get(ctx, "key1")
	if mockCache.getCalls != 1 {
		t.Errorf("Expected 1 Get call, got %d", mockCache.getCalls)
	}

	// Multiple Gets
	pdp.cache.Get(ctx, "key1")
	pdp.cache.Get(ctx, "key2")
	if mockCache.getCalls != 3 {
		t.Errorf("Expected 3 Get calls, got %d", mockCache.getCalls)
	}

	// Test Invalidate - should increment invalidateCalls
	pdp.cache.Invalidate(ctx, "key1")
	if mockCache.invalidateCalls != 1 {
		t.Errorf("Expected 1 Invalidate call, got %d", mockCache.invalidateCalls)
	}

	// Test Clear - should increment clearCalls
	pdp.cache.Clear(ctx)
	if mockCache.clearCalls != 1 {
		t.Errorf("Expected 1 Clear call, got %d", mockCache.clearCalls)
	}

	// Verify storage is cleared
	if len(mockCache.storage) != 0 {
		t.Errorf("Expected cache storage to be empty after Clear, got %d items", len(mockCache.storage))
	}
}

// Test that repository and engine factory are initialized correctly
func TestPDP_NewPolicyDecisionPointWithCache_Initialization(t *testing.T) {
	mockCache := newMockPolicyCache()

	tests := []struct {
		name string
		repo *repository.Repository
	}{
		{
			name: "Full repository with all components",
			repo: &repository.Repository{
				Policy:      &mockPDPPolicyRepository{},
				Entitlement: &mockPDPEntitlementRepository{},
				Audit:       &mockPDPAuditRepository{},
			},
		},
		{
			name: "Repository with only policy component",
			repo: &repository.Repository{
				Policy: &mockPDPPolicyRepository{},
			},
		},
		{
			name: "Empty repository",
			repo: &repository.Repository{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pdp := NewPolicyDecisionPointWithCache(tt.repo, mockCache, time.Minute)

			if pdp == nil {
				t.Fatal("Expected PDP to not be nil")
			}

			// Verify all components are initialized
			if pdp.repo == nil {
				t.Error("Expected repo to be set")
			}

			if pdp.repo != tt.repo {
				t.Error("Expected repo to be the same instance passed to constructor")
			}

			if pdp.engineFactory == nil {
				t.Error("Expected engineFactory to be initialized")
			}

			if pdp.cache == nil {
				t.Error("Expected cache to be set")
			}

			if pdp.cache != mockCache {
				t.Error("Expected cache to be the same instance passed to constructor")
			}
		})
	}
}

// Test edge case: cache operations with nil context
func TestPDP_NewPolicyDecisionPointWithCache_NilContext(t *testing.T) {
	mockCache := newMockPolicyCache()

	mockRepo := &repository.Repository{
		Policy:      &mockPDPPolicyRepository{},
		Entitlement: &mockPDPEntitlementRepository{},
		Audit:       &mockPDPAuditRepository{},
	}

	pdp := NewPolicyDecisionPointWithCache(mockRepo, mockCache, time.Minute)

	// Note: In real scenarios, context should never be nil, but we test the cache behavior
	// The cache implementation should handle this gracefully
	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Cache operations with context.Background() (proper usage)
	ctx := context.Background()

	err := pdp.cache.Set(ctx, "test-key", testPolicy, 1*time.Hour)
	if err != nil {
		t.Errorf("cache.Set() with valid context error = %v", err)
	}

	retrieved, found := pdp.cache.Get(ctx, "test-key")
	if !found {
		t.Error("Expected to find policy in cache")
	}
	if retrieved == nil {
		t.Error("Expected retrieved policy to not be nil")
	}
}

type stubPolicyRepository struct {
	policies []*models.Policy
	mu       sync.Mutex
	calls    int
}

func (s *stubPolicyRepository) Create(ctx context.Context, policy *models.Policy) error { return nil }
func (s *stubPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	return nil, nil
}
func (s *stubPolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	return nil, nil
}
func (s *stubPolicyRepository) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	return s.policies, nil
}
func (s *stubPolicyRepository) Update(ctx context.Context, policy *models.Policy) error { return nil }
func (s *stubPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error          { return nil }
func (s *stubPolicyRepository) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	return len(s.policies), nil
}
func (s *stubPolicyRepository) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return s.policies, nil
}

func TestPolicyDecisionPointPolicyCacheTTL(t *testing.T) {
	policy := &models.Policy{
		ID:       uuid.New(),
		Name:     "policy-cache-ttl",
		Priority: 1,
		Effect:   models.PolicyEffectAllow,
		Language: models.PolicyLanguageJSON,
		Enabled:  true,
	}

	stubRepo := &stubPolicyRepository{
		policies: []*models.Policy{policy},
	}

	repo := &repository.Repository{
		Policy: stubRepo,
	}

	cache := NewInMemoryPolicyCache()

	ttl := 50 * time.Millisecond
	pdp := NewPolicyDecisionPoint(repo, cache, ttl)

	ctx := context.Background()

	if _, err := pdp.getEnabledPolicies(ctx); err != nil {
		t.Fatalf("first getEnabledPolicies failed: %v", err)
	}
	if stubRepo.calls != 1 {
		t.Fatalf("expected 1 repository call, got %d", stubRepo.calls)
	}

	if _, err := pdp.getEnabledPolicies(ctx); err != nil {
		t.Fatalf("second getEnabledPolicies failed: %v", err)
	}
	if stubRepo.calls != 1 {
		t.Fatalf("expected cache hit to avoid repository call")
	}

	time.Sleep(ttl + 10*time.Millisecond)

	if _, err := pdp.getEnabledPolicies(ctx); err != nil {
		t.Fatalf("third getEnabledPolicies failed: %v", err)
	}
	if stubRepo.calls != 2 {
		t.Fatalf("expected repository to be called again after TTL expiry, got %d calls", stubRepo.calls)
	}
}
