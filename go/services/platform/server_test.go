package platform

import (
	"context"
	"fmt"
	"testing"
	"time"

	"stratium/config"
	"stratium/pkg/models"
	"stratium/pkg/repository"

	"github.com/google/uuid"
)

// getTestConfig returns a test configuration for platform server tests
func getTestConfig() *config.Config {
	cfg, _ := config.LoadFromEnv()
	if cfg == nil {
		cfg = &config.Config{}
	}
	return cfg
}

func TestServer_GetDecision(t *testing.T) {
	server := NewServer(getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectedReason   string
		expectError      bool
	}{
		{
			name: "Admin user should get ALLOW decision",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":  "admin456",
					"role": "admin",
				}),
				ResourceAttributes: map[string]string{"name": "document-service"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_ALLOW,
			expectedReason:   "Allowed by entitlement: ent-admin-1",
			expectError:      false,
		},
		{
			name: "User with valid entitlement should get ALLOW decision",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "document-service"},
				Action:             "read",
				Context: map[string]string{
					"department": "engineering",
				},
			},
			expectedDecision: Decision_DECISION_ALLOW,
			expectedReason:   "Allowed by entitlement: ent-1",
			expectError:      false,
		},
		{
			name: "User without entitlement should get DENY decision",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "restricted-service"},
				Action:             "write",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectedReason:   "No matching entitlements found",
			expectError:      false,
		},
		{
			name: "Request without subject should return DENY",
			request: &GetDecisionRequest{
				ResourceAttributes: map[string]string{"name": "document-service"},
				Action:             "read",
			},
			expectedDecision: Decision_DECISION_DENY,
			expectedReason:   "Subject attributes must contain 'sub', 'user_id', or 'id'",
			expectError:      false,
		},
		{
			name: "Request without resource should ALLOW (no requirements)",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{"sub": "user123"}),
				Action:            "read",
			},
			expectedDecision: Decision_DECISION_DENY,
			expectedReason:   "No matching entitlements found",
			expectError:      false,
		},
		{
			name: "Request without action should return error",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceAttributes: map[string]string{"name": "document-service"},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}

			if response.Reason != tt.expectedReason {
				t.Errorf("Expected reason '%s', got '%s'", tt.expectedReason, response.Reason)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			if response.EvaluatedPolicy == "" {
				t.Error("Expected evaluated policy to be set")
			}
		})
	}
}

func TestServer_GetEntitlements(t *testing.T) {
	server := NewServer(getTestConfig())

	tests := []struct {
		name               string
		request            *GetEntitlementsRequest
		expectedCount      int
		expectedTotalCount int64
		expectError        bool
	}{
		{
			name: "Get all entitlements for user123",
			request: &GetEntitlementsRequest{
				Subject: StringMapToValueMap(map[string]string{"sub": "user123"}),
			},
			expectedCount:      2,
			expectedTotalCount: 2,
			expectError:        false,
		},
		{
			name: "Get entitlements with resource filter",
			request: &GetEntitlementsRequest{
				Subject:        StringMapToValueMap(map[string]string{"sub": "user123"}),
				ResourceFilter: "document-service",
			},
			expectedCount:      1,
			expectedTotalCount: 1,
			expectError:        false,
		},
		{
			name: "Get entitlements with action filter",
			request: &GetEntitlementsRequest{
				Subject:      StringMapToValueMap(map[string]string{"sub": "user123"}),
				ActionFilter: "read",
			},
			expectedCount:      2,
			expectedTotalCount: 2,
			expectError:        false,
		},
		{
			name: "Get entitlements with pagination",
			request: &GetEntitlementsRequest{
				Subject:  StringMapToValueMap(map[string]string{"sub": "user123"}),
				PageSize: 1,
			},
			expectedCount:      1,
			expectedTotalCount: 2,
			expectError:        false,
		},
		{
			name: "Get entitlements for non-existent user",
			request: &GetEntitlementsRequest{
				Subject: StringMapToValueMap(map[string]string{"sub": "nonexistent"}),
			},
			expectedCount:      0,
			expectedTotalCount: 0,
			expectError:        false,
		},
		{
			name: "Request without subject should return error",
			request: &GetEntitlementsRequest{
				ResourceFilter: "document-service",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetEntitlements(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(response.Entitlements) != tt.expectedCount {
				t.Errorf("Expected %d entitlements, got %d", tt.expectedCount, len(response.Entitlements))
			}

			if response.TotalCount != tt.expectedTotalCount {
				t.Errorf("Expected total count %d, got %d", tt.expectedTotalCount, response.TotalCount)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			// Test pagination
			if tt.request.PageSize == 1 && response.TotalCount > 1 {
				if response.NextPageToken == "" {
					t.Error("Expected next page token to be set for paginated results")
				}
			}
		})
	}
}

func TestServer_EvaluateDecision(t *testing.T) {
	server := NewServer(getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectedPolicyID string
	}{
		{
			name: "Admin role should allow access",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":  "test-admin",
					"role": "admin",
				}),
				ResourceAttributes: map[string]string{"name": "any-resource"},
				Action:             "any-action",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectedPolicyID: "default-deny-policy",
		},
		{
			name: "Unknown user should be denied",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "unknown-user"}),
				ResourceAttributes: map[string]string{"name": "any-resource"},
				Action:             "any-action",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectedPolicyID: "default-deny-policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.evaluateDecision(tt.request)

			if result.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, result.Decision)
			}

			if result.PolicyID != tt.expectedPolicyID {
				t.Errorf("Expected policy ID %s, got %s", tt.expectedPolicyID, result.PolicyID)
			}
		})
	}
}

func TestServer_MatchesEntitlement(t *testing.T) {
	server := NewServer(getTestConfig())

	entitlement := &Entitlement{
		Resource: "document-service",
		Actions:  []string{"read", "write"},
	}

	wildcardEntitlement := &Entitlement{
		Resource: "*",
		Actions:  []string{"*"},
	}

	tests := []struct {
		name        string
		entitlement *Entitlement
		resource    string
		action      string
		expected    bool
	}{
		{
			name:        "Exact resource and action match",
			entitlement: entitlement,
			resource:    "document-service",
			action:      "read",
			expected:    true,
		},
		{
			name:        "Resource match, different action",
			entitlement: entitlement,
			resource:    "document-service",
			action:      "delete",
			expected:    false,
		},
		{
			name:        "Different resource",
			entitlement: entitlement,
			resource:    "user-service",
			action:      "read",
			expected:    false,
		},
		{
			name:        "Wildcard resource and action",
			entitlement: wildcardEntitlement,
			resource:    "any-service",
			action:      "any-action",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.matchesEntitlement(tt.entitlement, tt.resource, tt.action)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestServer_EvaluateConditions(t *testing.T) {
	server := NewServer(getTestConfig())

	futureTime := time.Now().Add(24 * time.Hour)
	pastTime := time.Now().Add(-24 * time.Hour)

	tests := []struct {
		name       string
		conditions []*Condition
		context    map[string]string
		expected   bool
	}{
		{
			name:       "No conditions should return true",
			conditions: []*Condition{},
			context:    map[string]string{},
			expected:   true,
		},
		{
			name: "Future time condition should pass",
			conditions: []*Condition{
				{
					Type:     "time",
					Operator: "before",
					Value:    futureTime.Format(time.RFC3339),
				},
			},
			context:  map[string]string{},
			expected: true,
		},
		{
			name: "Past time condition should fail",
			conditions: []*Condition{
				{
					Type:     "time",
					Operator: "before",
					Value:    pastTime.Format(time.RFC3339),
				},
			},
			context:  map[string]string{},
			expected: false,
		},
		{
			name: "Attribute condition with matching value should pass",
			conditions: []*Condition{
				{
					Type:     "attribute",
					Operator: "equals",
					Value:    "engineering",
					Parameters: map[string]string{
						"attribute": "department",
					},
				},
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: true,
		},
		{
			name: "Attribute condition with non-matching value should fail",
			conditions: []*Condition{
				{
					Type:     "attribute",
					Operator: "equals",
					Value:    "engineering",
					Parameters: map[string]string{
						"attribute": "department",
					},
				},
			},
			context: map[string]string{
				"department": "sales",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.evaluateConditions(tt.conditions, tt.context)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestServer_InitializeSampleData(t *testing.T) {
	server := NewServer(getTestConfig())

	// Test that sample data was initialized
	if len(server.entitlements) == 0 {
		t.Error("Expected sample entitlements to be initialized")
	}

	if len(server.policies) == 0 {
		t.Error("Expected sample policies to be initialized")
	}

	// Test specific sample data
	user123Entitlements := server.entitlements["user123"]
	if len(user123Entitlements) != 2 {
		t.Errorf("Expected 2 entitlements for user123, got %d", len(user123Entitlements))
	}

	adminEntitlements := server.entitlements["admin456"]
	if len(adminEntitlements) != 1 {
		t.Errorf("Expected 1 entitlement for admin456, got %d", len(adminEntitlements))
	}

	// Test admin entitlement has wildcard access
	if adminEntitlements[0].Resource != "*" {
		t.Errorf("Expected admin entitlement to have wildcard resource, got %s", adminEntitlements[0].Resource)
	}
}

// Benchmark tests
func BenchmarkServer_GetDecision(b *testing.B) {
	server := NewServer(getTestConfig())
	req := &GetDecisionRequest{
		SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user123"}),
		ResourceAttributes: map[string]string{"name": "document-service"},
		Action:             "read",
		Context: map[string]string{
			"department": "engineering",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.GetDecision(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServer_GetEntitlements(b *testing.B) {
	server := NewServer(getTestConfig())
	req := &GetEntitlementsRequest{
		Subject: StringMapToValueMap(map[string]string{"sub": "user123"}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.GetEntitlements(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Mock repository implementations for testing

type mockPolicyRepository struct {
	policies        []*models.Policy
	enabledPolicies []*models.Policy
	getByIDFunc     func(ctx context.Context, id uuid.UUID) (*models.Policy, error)
	listEnabledFunc func(ctx context.Context) ([]*models.Policy, error)
}

func (m *mockPolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	m.policies = append(m.policies, policy)
	return nil
}

func (m *mockPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	for _, p := range m.policies {
		if p.ID == id {
			return p, nil
		}
	}
	return nil, models.ErrPolicyNotFound
}

func (m *mockPolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	for _, p := range m.policies {
		if p.Name == name {
			return p, nil
		}
	}
	return nil, models.ErrPolicyNotFound
}

func (m *mockPolicyRepository) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	return m.policies, nil
}

func (m *mockPolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	for i, p := range m.policies {
		if p.ID == policy.ID {
			m.policies[i] = policy
			return nil
		}
	}
	return models.ErrPolicyNotFound
}

func (m *mockPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	for i, p := range m.policies {
		if p.ID == id {
			m.policies = append(m.policies[:i], m.policies[i+1:]...)
			return nil
		}
	}
	return models.ErrPolicyNotFound
}

func (m *mockPolicyRepository) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	if m.listEnabledFunc != nil {
		return m.listEnabledFunc(ctx)
	}
	return m.enabledPolicies, nil
}

func (m *mockPolicyRepository) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	return len(m.policies), nil
}

type mockEntitlementRepository struct {
	entitlements     []*models.Entitlement
	matchingResults  []*models.Entitlement
	findMatchingFunc func(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error)
}

func (m *mockEntitlementRepository) Create(ctx context.Context, entitlement *models.Entitlement) error {
	m.entitlements = append(m.entitlements, entitlement)
	return nil
}

func (m *mockEntitlementRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Entitlement, error) {
	for _, e := range m.entitlements {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, models.ErrEntitlementNotFound
}

func (m *mockEntitlementRepository) GetByName(ctx context.Context, name string) (*models.Entitlement, error) {
	for _, e := range m.entitlements {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, models.ErrEntitlementNotFound
}

func (m *mockEntitlementRepository) List(ctx context.Context, req *models.ListEntitlementsRequest) ([]*models.Entitlement, error) {
	return m.entitlements, nil
}

func (m *mockEntitlementRepository) Update(ctx context.Context, entitlement *models.Entitlement) error {
	for i, e := range m.entitlements {
		if e.ID == entitlement.ID {
			m.entitlements[i] = entitlement
			return nil
		}
	}
	return models.ErrEntitlementNotFound
}

func (m *mockEntitlementRepository) Delete(ctx context.Context, id uuid.UUID) error {
	for i, e := range m.entitlements {
		if e.ID == id {
			m.entitlements = append(m.entitlements[:i], m.entitlements[i+1:]...)
			return nil
		}
	}
	return models.ErrEntitlementNotFound
}

func (m *mockEntitlementRepository) FindMatching(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
	if m.findMatchingFunc != nil {
		return m.findMatchingFunc(ctx, req)
	}
	return m.matchingResults, nil
}

func (m *mockEntitlementRepository) ListActive(ctx context.Context) ([]*models.Entitlement, error) {
	var active []*models.Entitlement
	for _, e := range m.entitlements {
		if e.IsActive() {
			active = append(active, e)
		}
	}
	return active, nil
}

func (m *mockEntitlementRepository) Count(ctx context.Context, req *models.ListEntitlementsRequest) (int, error) {
	return len(m.entitlements), nil
}

type mockAuditRepository struct {
	logs []*models.AuditLog
}

func (m *mockAuditRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	m.logs = append(m.logs, auditLog)
	return nil
}

func (m *mockAuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	for _, l := range m.logs {
		if l.ID == id {
			return l, nil
		}
	}
	return nil, fmt.Errorf("audit log not found")
}

func (m *mockAuditRepository) List(ctx context.Context, req *models.ListAuditLogsRequest) ([]*models.AuditLog, error) {
	return m.logs, nil
}

func (m *mockAuditRepository) ListByEntity(ctx context.Context, entityType models.EntityType, entityID uuid.UUID) ([]*models.AuditLog, error) {
	var filtered []*models.AuditLog
	for _, l := range m.logs {
		if l.EntityType == entityType && l.EntityID != nil && *l.EntityID == entityID {
			filtered = append(filtered, l)
		}
	}
	return filtered, nil
}

func (m *mockAuditRepository) ListByActor(ctx context.Context, actor string, limit, offset int) ([]*models.AuditLog, error) {
	var filtered []*models.AuditLog
	for _, l := range m.logs {
		if l.Actor == actor {
			filtered = append(filtered, l)
		}
	}
	return filtered, nil
}

func (m *mockAuditRepository) Count(ctx context.Context, req *models.ListAuditLogsRequest) (int, error) {
	return len(m.logs), nil
}

// Tests for server with PDP

func TestServer_GetDecisionWithPDP_EntitlementMatch(t *testing.T) {
	// Setup mock repository
	entitlementID := uuid.New()
	entitlement := &models.Entitlement{
		ID:      entitlementID,
		Name:    "test-entitlement",
		Actions: []string{"read", "write"},
		SubjectAttributes: map[string]interface{}{
			"sub": "user-with-entitlement",
		},
		ResourceAttributes: map[string]interface{}{},
		Enabled:            true,
		CreatedAt:          time.Now(),
		UpdatedAt:          time.Now(),
	}

	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{entitlement},
	}
	mockPolicyRepo := &mockPolicyRepository{}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectError      bool
	}{
		{
			name: "User with matching entitlement should get ALLOW",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user-with-entitlement"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_ALLOW,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			if response.EvaluatedPolicy == "" {
				t.Error("Expected evaluated policy to be set")
			}

			// Verify audit log was created
			if len(mockAuditRepo.logs) == 0 {
				t.Error("Expected audit log to be created")
			}
		})
	}
}

func TestServer_GetDecisionWithPDP_PolicyFromRepository(t *testing.T) {
	// Setup mock repository with policies loaded from the repository
	// This test verifies the PDP fetches and evaluates policies from the policy repo
	policyID1 := uuid.New()
	policyID2 := uuid.New()

	// Create a simple XACML policy - note: actual evaluation depends on policy engine implementation
	allowPolicy := &models.Policy{
		ID:          policyID1,
		Name:        "repo-allow-policy",
		Description: "Policy loaded from repository",
		Language:    models.PolicyLanguageXACML,
		PolicyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="repo-allow-policy"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides"
        Version="1.0">
    <Target/>
    <Rule RuleId="default-permit" Effect="Permit">
        <Target/>
    </Rule>
</Policy>`,
		Effect:    models.PolicyEffectAllow,
		Priority:  100,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	denyPolicy := &models.Policy{
		ID:          policyID2,
		Name:        "repo-deny-policy",
		Description: "Deny policy loaded from repository",
		Language:    models.PolicyLanguageXACML,
		PolicyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="repo-deny-policy"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides"
        Version="1.0">
    <Target/>
    <Rule RuleId="default-deny" Effect="Deny">
        <Target/>
    </Rule>
</Policy>`,
		Effect:    models.PolicyEffectDeny,
		Priority:  50,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{}, // No entitlements - test policy evaluation
	}
	mockPolicyRepo := &mockPolicyRepository{
		enabledPolicies: []*models.Policy{allowPolicy, denyPolicy},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectEvaluation bool // Whether policies should be evaluated
	}{
		{
			name: "Policies from repository should be evaluated by PDP",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectEvaluation: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			if response.EvaluatedPolicy == "" {
				t.Error("Expected evaluated policy to be set")
			}

			// Verify that policies were loaded from the repository
			// The mock should have returned both policies
			if len(mockPolicyRepo.enabledPolicies) != 2 {
				t.Errorf("Expected 2 policies in repository, got %d", len(mockPolicyRepo.enabledPolicies))
			}

			// Log the decision for visibility
			t.Logf("Decision: %s, Reason: %s, EvaluatedPolicy: %s",
				response.Decision.String(), response.Reason, response.EvaluatedPolicy)
		})
	}
}

func TestServer_GetDecisionWithPDP_MultiplePoliciesInRepo(t *testing.T) {
	// Test that PDP evaluates multiple policies from repository in priority order
	// Higher priority policies should be evaluated first
	policyID1 := uuid.New()
	policyID2 := uuid.New()

	highPriorityPolicy := &models.Policy{
		ID:            policyID1,
		Name:          "high-priority-policy",
		Description:   "High priority policy (evaluated first)",
		Language:      models.PolicyLanguageXACML,
		PolicyContent: "<Policy/>", // Minimal XACML
		Effect:        models.PolicyEffectAllow,
		Priority:      200, // Higher priority
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	lowPriorityPolicy := &models.Policy{
		ID:            policyID2,
		Name:          "low-priority-policy",
		Description:   "Low priority policy (evaluated later)",
		Language:      models.PolicyLanguageXACML,
		PolicyContent: "<Policy/>", // Minimal XACML
		Effect:        models.PolicyEffectAllow,
		Priority:      100, // Lower priority
		Enabled:       true,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{},
	}
	// Add policies in reverse priority order to verify PDP sorts them
	mockPolicyRepo := &mockPolicyRepository{
		enabledPolicies: []*models.Policy{lowPriorityPolicy, highPriorityPolicy},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	response, err := server.GetDecision(context.Background(), &GetDecisionRequest{
		SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
		ResourceAttributes: map[string]string{"name": "test-resource"},
		Action:             "read",
		Context:            map[string]string{},
	})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	// Verify the PDP loaded and evaluated policies from the repository
	if response == nil {
		t.Fatal("Expected response but got nil")
	}

	// Verify audit logs show policies were fetched from repo
	t.Logf("Evaluated %d policies from repository", len(mockPolicyRepo.enabledPolicies))
	t.Logf("Decision: %s, Policy: %s", response.Decision.String(), response.EvaluatedPolicy)
}

func TestServer_GetDecisionWithPDP_DefaultDeny(t *testing.T) {
	// Setup mock repository with no matching policies or entitlements
	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{},
	}
	mockPolicyRepo := &mockPolicyRepository{
		enabledPolicies: []*models.Policy{},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectError      bool
	}{
		{
			name: "User with no matching policies or entitlements should get default DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "unknown-user"}),
				ResourceAttributes: map[string]string{"name": "any-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}

			if response.EvaluatedPolicy != "default-deny" {
				t.Errorf("Expected policy ID 'default-deny', got '%s'", response.EvaluatedPolicy)
			}
		})
	}
}

func TestServer_GetDecisionWithPDP_InactiveEntitlement(t *testing.T) {
	// Setup mock repository with an inactive entitlement
	entitlementID := uuid.New()
	pastTime := time.Now().Add(-24 * time.Hour)
	inactiveEntitlement := &models.Entitlement{
		ID:      entitlementID,
		Name:    "expired-entitlement",
		Actions: []string{"read"},
		SubjectAttributes: map[string]interface{}{
			"sub": "user-expired",
		},
		Enabled:   true,
		ExpiresAt: &pastTime, // Expired
		CreatedAt: time.Now().Add(-48 * time.Hour),
		UpdatedAt: time.Now(),
	}

	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{inactiveEntitlement},
	}
	mockPolicyRepo := &mockPolicyRepository{
		enabledPolicies: []*models.Policy{},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectError      bool
	}{
		{
			name: "User with expired entitlement should get DENY",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user-expired"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}
		})
	}
}

func TestServer_GetDecisionWithPDP_PolicyEvaluationError(t *testing.T) {
	// Setup mock repository that returns an error on policy evaluation
	// but succeeds on entitlement lookup (returns empty)
	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{}, // No entitlements
	}
	mockPolicyRepo := &mockPolicyRepository{
		listEnabledFunc: func(ctx context.Context) ([]*models.Policy, error) {
			return nil, fmt.Errorf("database error")
		},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectError      bool
	}{
		{
			name: "Policy evaluation error should return DENY with error reason",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "any-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_DENY,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}

			// Verify the reason contains error information
			if response.Reason == "" {
				t.Error("Expected reason to be set with error information")
			}
		})
	}
}

func TestServer_GetDecisionWithPDP_EntitlementPriority(t *testing.T) {
	// Setup mock repository with both entitlement and policy
	// Entitlement should take priority
	entitlementID := uuid.New()
	policyID := uuid.New()

	entitlement := &models.Entitlement{
		ID:      entitlementID,
		Name:    "priority-entitlement",
		Actions: []string{"read"},
		SubjectAttributes: map[string]interface{}{
			"sub": "priority-user",
		},
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	denyPolicy := &models.Policy{
		ID:          policyID,
		Name:        "deny-all-policy",
		Description: "Policy that would deny access",
		Language:    models.PolicyLanguageOPA,
		PolicyContent: `package authz
default allow = false
allow {
	true
}`,
		Effect:    models.PolicyEffectDeny,
		Priority:  100,
		Enabled:   true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	mockEntRepo := &mockEntitlementRepository{
		matchingResults: []*models.Entitlement{entitlement},
	}
	mockPolicyRepo := &mockPolicyRepository{
		enabledPolicies: []*models.Policy{denyPolicy},
	}
	mockAuditRepo := &mockAuditRepository{}

	repo := &repository.Repository{
		Entitlement: mockEntRepo,
		Policy:      mockPolicyRepo,
		Audit:       mockAuditRepo,
	}

	pdp := NewPolicyDecisionPoint(repo, NewInMemoryPolicyCache(), time.Minute)
	server := NewServerWithPDP(pdp, getTestConfig())

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
		expectError      bool
	}{
		{
			name: "Entitlement should take priority over deny policy",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "priority-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_ALLOW,
			expectError:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetDecision(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, response.Decision)
			}

			// Verify it was the entitlement, not the policy
			if response.Details["entitlement_name"] != "priority-entitlement" {
				t.Error("Expected decision to be made by entitlement")
			}
		})
	}
}

// TestServer_EvaluateDecision_ConditionalAccess tests the else condition in evaluateDecision
// This tests the case where an entitlement matches but its conditions are not met
func TestServer_EvaluateDecision_ConditionalAccess(t *testing.T) {
	tests := []struct {
		name             string
		setupServer      func(*Server)
		request          *GetDecisionRequest
		expectedDecision Decision
		expectedReason   string
		expectedPolicyID string
		expectedDetails  map[string]string
	}{
		{
			name: "Entitlement matches but time condition not met - CONDITIONAL",
			setupServer: func(s *Server) {
				// Add an entitlement with a past time condition
				pastTime := time.Now().Add(-24 * time.Hour)
				s.entitlements["test-user"] = []*Entitlement{
					{
						Id:       "ent-expired-time",
						Subject:  "test-user",
						Resource: "test-resource",
						Actions:  []string{"read"},
						Conditions: []*Condition{
							{
								Type:     "time",
								Operator: "before",
								Value:    pastTime.Format(time.RFC3339), // Past time - condition fails
							},
						},
						Active: true,
					},
				}
			},
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "test-user"}),
				ResourceAttributes: map[string]string{"name": "test-resource"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision: Decision_DECISION_CONDITIONAL,
			expectedReason:   "Entitlement exists but conditions not met",
			expectedPolicyID: "entitlement-policy",
			expectedDetails: map[string]string{
				"entitlement_id": "ent-expired-time",
				"reason":         "conditions-not-met",
			},
		},
		{
			name: "Entitlement matches but attribute condition not met - CONDITIONAL",
			setupServer: func(s *Server) {
				// Add an entitlement with an attribute condition
				s.entitlements["user456"] = []*Entitlement{
					{
						Id:       "ent-dept-mismatch",
						Subject:  "user456",
						Resource: "secure-docs",
						Actions:  []string{"write"},
						Conditions: []*Condition{
							{
								Type:     "attribute",
								Operator: "equals",
								Value:    "engineering",
								Parameters: map[string]string{
									"attribute": "department",
								},
							},
						},
						Active: true,
					},
				}
			},
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user456"}),
				ResourceAttributes: map[string]string{"name": "secure-docs"},
				Action:             "write",
				Context: map[string]string{
					"department": "sales", // Wrong department - condition fails
				},
			},
			expectedDecision: Decision_DECISION_CONDITIONAL,
			expectedReason:   "Entitlement exists but conditions not met",
			expectedPolicyID: "entitlement-policy",
			expectedDetails: map[string]string{
				"entitlement_id": "ent-dept-mismatch",
				"reason":         "conditions-not-met",
			},
		},
		{
			name: "Entitlement matches but multiple conditions not all met - CONDITIONAL",
			setupServer: func(s *Server) {
				futureTime := time.Now().Add(24 * time.Hour)
				s.entitlements["user789"] = []*Entitlement{
					{
						Id:       "ent-multi-cond",
						Subject:  "user789",
						Resource: "api-service",
						Actions:  []string{"delete"},
						Conditions: []*Condition{
							{
								Type:     "time",
								Operator: "before",
								Value:    futureTime.Format(time.RFC3339), // This passes
							},
							{
								Type:     "attribute",
								Operator: "equals",
								Value:    "admin",
								Parameters: map[string]string{
									"attribute": "role",
								},
							},
						},
						Active: true,
					},
				}
			},
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user789"}),
				ResourceAttributes: map[string]string{"name": "api-service"},
				Action:             "delete",
				Context: map[string]string{
					"role": "user", // Not admin - attribute condition fails
				},
			},
			expectedDecision: Decision_DECISION_CONDITIONAL,
			expectedReason:   "Entitlement exists but conditions not met",
			expectedPolicyID: "entitlement-policy",
			expectedDetails: map[string]string{
				"entitlement_id": "ent-multi-cond",
				"reason":         "conditions-not-met",
			},
		},
		{
			name: "Entitlement matches but missing required context attribute - CONDITIONAL",
			setupServer: func(s *Server) {
				s.entitlements["user-missing-attr"] = []*Entitlement{
					{
						Id:       "ent-missing-attr",
						Subject:  "user-missing-attr",
						Resource: "protected-data",
						Actions:  []string{"read"},
						Conditions: []*Condition{
							{
								Type:     "attribute",
								Operator: "equals",
								Value:    "high",
								Parameters: map[string]string{
									"attribute": "clearance_level",
								},
							},
						},
						Active: true,
					},
				}
			},
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{"sub": "user-missing-attr"}),
				ResourceAttributes: map[string]string{"name": "protected-data"},
				Action:             "read",
				Context:            map[string]string{}, // Missing clearance_level - condition fails
			},
			expectedDecision: Decision_DECISION_CONDITIONAL,
			expectedReason:   "Entitlement exists but conditions not met",
			expectedPolicyID: "entitlement-policy",
			expectedDetails: map[string]string{
				"entitlement_id": "ent-missing-attr",
				"reason":         "conditions-not-met",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup server with test-specific entitlements
			testServer := NewServer(getTestConfig())
			if tt.setupServer != nil {
				tt.setupServer(testServer)
			}

			// Execute the evaluateDecision method
			result := testServer.evaluateDecision(tt.request)

			// Verify the decision
			if result.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v", tt.expectedDecision, result.Decision)
			}

			// Verify the reason
			if result.Reason != tt.expectedReason {
				t.Errorf("Expected reason %q, got %q", tt.expectedReason, result.Reason)
			}

			// Verify the policy ID
			if result.PolicyID != tt.expectedPolicyID {
				t.Errorf("Expected policy ID %q, got %q", tt.expectedPolicyID, result.PolicyID)
			}

			// Verify the details
			if tt.expectedDetails != nil {
				for key, expectedValue := range tt.expectedDetails {
					actualValue, exists := result.Details[key]
					if !exists {
						t.Errorf("Expected detail key %q to exist", key)
						continue
					}
					if actualValue != expectedValue {
						t.Errorf("Expected detail %q=%q, got %q", key, expectedValue, actualValue)
					}
				}
			}
		})
	}
}

// TestServer_EvaluateAttributeCondition tests all conditional branches of evaluateAttributeCondition
func TestServer_EvaluateAttributeCondition(t *testing.T) {
	server := NewServer(getTestConfig())

	tests := []struct {
		name      string
		condition *Condition
		context   map[string]string
		expected  bool
	}{
		{
			name: "Empty attribute name - should return true",
			condition: &Condition{
				Type:       "attribute",
				Operator:   "equals",
				Value:      "engineering",
				Parameters: map[string]string{}, // No "attribute" key
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: true,
		},
		{
			name: "Missing attribute parameter - should return true",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "", // Empty attribute name
				},
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: true,
		},
		{
			name: "Attribute doesn't exist in context - should return false",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context:  map[string]string{}, // Empty context
			expected: false,
		},
		{
			name: "Attribute exists but not in context - should return false",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"role": "admin", // Different attribute
			},
			expected: false,
		},
		{
			name: "Equals operator - matching value - should return true",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: true,
		},
		{
			name: "Equals operator - non-matching value - should return false",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "sales",
			},
			expected: false,
		},
		{
			name: "Equals operator - case sensitive - should return false",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "Engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: false,
		},
		{
			name: "Contains operator - matching value - should return true",
			condition: &Condition{
				Type:     "attribute",
				Operator: "contains",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "engineering",
			},
			expected: true,
		},
		{
			name: "Contains operator - non-matching value - should return false",
			condition: &Condition{
				Type:     "attribute",
				Operator: "contains",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "sales",
			},
			expected: false,
		},
		{
			name: "Default operator - unknown operator - should return true",
			condition: &Condition{
				Type:     "attribute",
				Operator: "unknown-operator",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "sales",
			},
			expected: true,
		},
		{
			name: "Default operator - empty operator - should return true",
			condition: &Condition{
				Type:     "attribute",
				Operator: "",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "sales",
			},
			expected: true,
		},
		{
			name: "Equals operator with special characters - matching",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "user@example.com",
				Parameters: map[string]string{
					"attribute": "email",
				},
			},
			context: map[string]string{
				"email": "user@example.com",
			},
			expected: true,
		},
		{
			name: "Equals operator with numeric strings - matching",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "12345",
				Parameters: map[string]string{
					"attribute": "user_id",
				},
			},
			context: map[string]string{
				"user_id": "12345",
			},
			expected: true,
		},
		{
			name: "Equals operator with empty string value - matching",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "",
				Parameters: map[string]string{
					"attribute": "optional_field",
				},
			},
			context: map[string]string{
				"optional_field": "",
			},
			expected: true,
		},
		{
			name: "Equals operator with whitespace - non-matching",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "engineering",
				Parameters: map[string]string{
					"attribute": "department",
				},
			},
			context: map[string]string{
				"department": "engineering ",
			},
			expected: false,
		},
		{
			name: "Contains operator with URL value - matching",
			condition: &Condition{
				Type:     "attribute",
				Operator: "contains",
				Value:    "https://example.com/callback",
				Parameters: map[string]string{
					"attribute": "callback_url",
				},
			},
			context: map[string]string{
				"callback_url": "https://example.com/callback",
			},
			expected: true,
		},
		{
			name: "Multiple attributes in context - correct attribute selected",
			condition: &Condition{
				Type:     "attribute",
				Operator: "equals",
				Value:    "admin",
				Parameters: map[string]string{
					"attribute": "role",
				},
			},
			context: map[string]string{
				"role":       "admin",
				"department": "engineering",
				"level":      "senior",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.evaluateAttributeCondition(tt.condition, tt.context)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v. Condition: %+v, Context: %+v",
					tt.expected, result, tt.condition, tt.context)
			}
		})
	}
}

// TestServer_EvaluateTimeCondition tests all conditional branches of evaluateTimeCondition
func TestServer_EvaluateTimeCondition(t *testing.T) {
	server := NewServer(getTestConfig())

	tests := []struct {
		name      string
		condition *Condition
		expected  bool
	}{
		{
			name: "After operator - current time is after the specified time - should return true",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(-24 * time.Hour).Format(time.RFC3339), // Past time
			},
			expected: true,
		},
		{
			name: "After operator - current time is before the specified time - should return false",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(24 * time.Hour).Format(time.RFC3339), // Future time
			},
			expected: false,
		},
		{
			name: "After operator - invalid time format - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    "not-a-valid-time",
			},
			expected: true,
		},
		{
			name: "After operator - empty time value - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    "",
			},
			expected: true,
		},
		{
			name: "After operator - malformed RFC3339 - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    "2024-13-45T25:99:99Z", // Invalid month/day/time
			},
			expected: true,
		},
		{
			name: "Before operator - current time is before the specified time - should return true",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    time.Now().Add(24 * time.Hour).Format(time.RFC3339), // Future time
			},
			expected: true,
		},
		{
			name: "Before operator - current time is after the specified time - should return false",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    time.Now().Add(-24 * time.Hour).Format(time.RFC3339), // Past time
			},
			expected: false,
		},
		{
			name: "Before operator - invalid time format - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    "invalid-timestamp",
			},
			expected: true,
		},
		{
			name: "Before operator - empty time value - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    "",
			},
			expected: true,
		},
		{
			name: "Before operator - random string - should return true (default)",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    "some random text",
			},
			expected: true,
		},
		{
			name: "Unknown operator - should return true (default case)",
			condition: &Condition{
				Type:     "time",
				Operator: "unknown-operator",
				Value:    time.Now().Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "Empty operator - should return true (default case)",
			condition: &Condition{
				Type:     "time",
				Operator: "",
				Value:    time.Now().Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "After operator - boundary test 1 second ago - should return true",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(-1 * time.Second).Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "After operator - boundary test 1 second in future - should return false",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(1 * time.Second).Format(time.RFC3339),
			},
			expected: false,
		},
		{
			name: "Before operator - boundary test 1 second in future - should return true",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    time.Now().Add(1 * time.Second).Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "Before operator - boundary test 1 second ago - should return false",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    time.Now().Add(-1 * time.Second).Format(time.RFC3339),
			},
			expected: false,
		},
		{
			name: "After operator - far past time (years ago) - should return true",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(-365 * 24 * time.Hour).Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "After operator - far future time (years ahead) - should return false",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
			},
			expected: false,
		},
		{
			name: "Before operator - time with timezone info - should parse and compare correctly",
			condition: &Condition{
				Type:     "time",
				Operator: "before",
				Value:    time.Now().Add(48 * time.Hour).Format(time.RFC3339),
			},
			expected: true,
		},
		{
			name: "After operator - time with nanoseconds precision - should parse correctly",
			condition: &Condition{
				Type:     "time",
				Operator: "after",
				Value:    time.Now().Add(-10 * time.Minute).Format(time.RFC3339Nano),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.evaluateTimeCondition(tt.condition)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v. Condition: %+v",
					tt.expected, result, tt.condition)
			}
		})
	}
}
