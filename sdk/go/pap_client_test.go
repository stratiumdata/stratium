package stratium

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Integration tests for PAPClient using httptest for HTTP mocking.

// mockPAPServer creates a test HTTP server for the PAP service
type mockPAPServer struct {
	server      *httptest.Server
	policies    map[string]*Policy
	entitlement map[string]*EntitlementResponse
	shouldError bool
}

func newMockPAPServer() *mockPAPServer {
	mock := &mockPAPServer{
		policies:    make(map[string]*Policy),
		entitlement: make(map[string]*EntitlementResponse),
	}

	mux := http.NewServeMux()

	// Policy endpoints
	mux.HandleFunc(PAPPoliciesPath, func(w http.ResponseWriter, r *http.Request) {
		if mock.shouldError {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "internal server error"})
			return
		}

		switch r.Method {
		case http.MethodPost:
			// CreatePolicy
			var policy Policy
			if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			policy.ID = "policy-123"
			policy.CreatedAt = "2024-01-01T00:00:00Z"
			policy.UpdatedAt = "2024-01-01T00:00:00Z"
			mock.policies[policy.ID] = &policy

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(policy)

		case http.MethodGet:
			// ListPolicies
			policies := make([]*Policy, 0, len(mock.policies))
			for _, p := range mock.policies {
				policies = append(policies, p)
			}
			json.NewEncoder(w).Encode(policies)
		}
	})

	mux.HandleFunc(PAPPoliciesPath+"/", func(w http.ResponseWriter, r *http.Request) {
		if mock.shouldError {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Extract policy ID from path
		policyID := r.URL.Path[len(PAPPoliciesPath)+1:]

		switch r.Method {
		case http.MethodGet:
			// GetPolicy
			policy, exists := mock.policies[policyID]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(policy)

		case http.MethodPut:
			// UpdatePolicy
			var policy Policy
			if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			policy.ID = policyID
			policy.UpdatedAt = "2024-01-01T00:00:00Z"
			mock.policies[policyID] = &policy
			json.NewEncoder(w).Encode(policy)

		case http.MethodDelete:
			// DeletePolicy
			delete(mock.policies, policyID)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	// Entitlement endpoints
	mux.HandleFunc(PAPEntitlementsPath, func(w http.ResponseWriter, r *http.Request) {
		if mock.shouldError {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		switch r.Method {
		case http.MethodPost:
			// CreateEntitlement
			var entitlement EntitlementCreate
			if err := json.NewDecoder(r.Body).Decode(&entitlement); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			resp := &EntitlementResponse{
				ID:                 "entitlement-123",
				Name:               entitlement.Name,
				Description:        entitlement.Description,
				SubjectAttributes:  entitlement.SubjectAttributes,
				ResourceAttributes: entitlement.ResourceAttributes,
				Actions:            entitlement.Actions,
				Enabled:            entitlement.Enabled,
				StartsAt:           entitlement.StartsAt,
				ExpiresAt:          entitlement.ExpiresAt,
				Metadata:           entitlement.Metadata,
				CreatedAt:          "2024-01-01T00:00:00Z",
				UpdatedAt:          "2024-01-01T00:00:00Z",
			}
			mock.entitlement[resp.ID] = resp

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(resp)

		case http.MethodGet:
			// ListEntitlements
			entitlements := make([]*EntitlementResponse, 0, len(mock.entitlement))
			for _, e := range mock.entitlement {
				entitlements = append(entitlements, e)
			}
			json.NewEncoder(w).Encode(entitlements)
		}
	})

	mux.HandleFunc(PAPEntitlementsPath+"/", func(w http.ResponseWriter, r *http.Request) {
		if mock.shouldError {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// Extract entitlement ID from path
		entitlementID := r.URL.Path[len(PAPEntitlementsPath)+1:]

		switch r.Method {
		case http.MethodGet:
			// GetEntitlement
			entitlement, exists := mock.entitlement[entitlementID]
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			json.NewEncoder(w).Encode(entitlement)

		case http.MethodDelete:
			// DeleteEntitlement
			delete(mock.entitlement, entitlementID)
			w.WriteHeader(http.StatusNoContent)
		}
	})

	mock.server = httptest.NewServer(mux)
	return mock
}

func (m *mockPAPServer) Close() {
	m.server.Close()
}

func setupPAPTest(t *testing.T, mockServer *mockPAPServer) *PAPClient {
	config := &Config{
		PAPAddress: mockServer.server.URL,
		Timeout:    0,
	}
	mockAuth := &mockAuthManager{
		token: "test-token",
	}
	return newPAPClient(config, mockAuth)
}

// ===== CreatePolicy Tests =====

func TestPAPClient_CreatePolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	policy := &Policy{
		Name:          "test-policy",
		Description:   "Test policy description",
		Language:      "OPA",
		PolicyContent: "package authz\ndefault allow = true",
		Effect:        "allow",
		Priority:      100,
		Enabled:       true,
		Metadata:      map[string]interface{}{"env": "test"},
	}

	ctx := context.Background()
	created, err := client.CreatePolicy(ctx, policy)
	if err != nil {
		t.Fatalf("CreatePolicy() error: %v", err)
	}

	if created == nil {
		t.Fatal("CreatePolicy() returned nil policy")
	}

	if created.ID == "" {
		t.Error("CreatePolicy() should return policy ID")
	}

	if created.Name != policy.Name {
		t.Errorf("CreatePolicy() name = %v, want %v", created.Name, policy.Name)
	}

	if created.CreatedAt == "" {
		t.Error("CreatePolicy() should set created_at")
	}
}

func TestPAPClient_CreatePolicy_NilPolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.CreatePolicy(ctx, nil)
	if err == nil {
		t.Error("CreatePolicy() with nil policy expected error, got nil")
	}
}

func TestPAPClient_CreatePolicy_MissingName(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	policy := &Policy{
		Language:      "OPA",
		PolicyContent: "package authz\ndefault allow = true",
		Effect:        "allow",
		Priority:      100,
		Enabled:       true,
	}

	ctx := context.Background()
	_, err := client.CreatePolicy(ctx, policy)
	if err == nil {
		t.Error("CreatePolicy() with missing name expected error, got nil")
	}
}

func TestPAPClient_CreatePolicy_ServerError(t *testing.T) {
	mockServer := newMockPAPServer()
	mockServer.shouldError = true
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	policy := &Policy{
		Name:          "test-policy",
		Language:      "OPA",
		PolicyContent: "package authz",
		Effect:        "allow",
		Priority:      100,
		Enabled:       true,
	}

	ctx := context.Background()
	_, err := client.CreatePolicy(ctx, policy)
	if err == nil {
		t.Error("CreatePolicy() expected error for server error, got nil")
	}
}

// ===== GetPolicy Tests =====

func TestPAPClient_GetPolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate a policy
	testPolicy := &Policy{
		ID:            "policy-123",
		Name:          "test-policy",
		Description:   "Test policy",
		Language:      "OPA",
		PolicyContent: "package authz",
		Effect:        "allow",
		Priority:      100,
		Enabled:       true,
	}
	mockServer.policies["policy-123"] = testPolicy

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	policy, err := client.GetPolicy(ctx, "policy-123")
	if err != nil {
		t.Fatalf("GetPolicy() error: %v", err)
	}

	if policy == nil {
		t.Fatal("GetPolicy() returned nil policy")
	}

	if policy.ID != testPolicy.ID {
		t.Errorf("GetPolicy() ID = %v, want %v", policy.ID, testPolicy.ID)
	}

	if policy.Name != testPolicy.Name {
		t.Errorf("GetPolicy() name = %v, want %v", policy.Name, testPolicy.Name)
	}
}

func TestPAPClient_GetPolicy_MissingID(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.GetPolicy(ctx, "")
	if err == nil {
		t.Error("GetPolicy() with missing ID expected error, got nil")
	}
}

func TestPAPClient_GetPolicy_NotFound(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.GetPolicy(ctx, "nonexistent-policy")
	if err == nil {
		t.Error("GetPolicy() expected error for not found, got nil")
	}
}

// ===== ListPolicies Tests =====

func TestPAPClient_ListPolicies(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate policies
	mockServer.policies["policy-1"] = &Policy{ID: "policy-1", Name: "Policy 1"}
	mockServer.policies["policy-2"] = &Policy{ID: "policy-2", Name: "Policy 2"}

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("ListPolicies() returned %d policies, want 2", len(policies))
	}
}

func TestPAPClient_ListPolicies_Empty(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	policies, err := client.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies() error: %v", err)
	}

	if len(policies) != 0 {
		t.Errorf("ListPolicies() returned %d policies, want 0", len(policies))
	}
}

// ===== UpdatePolicy Tests =====

func TestPAPClient_UpdatePolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate a policy
	mockServer.policies["policy-123"] = &Policy{
		ID:       "policy-123",
		Name:     "original-name",
		Enabled:  true,
		Priority: 100,
	}

	client := setupPAPTest(t, mockServer)

	updatedPolicy := &Policy{
		ID:       "policy-123",
		Name:     "updated-name",
		Enabled:  false,
		Priority: 200,
	}

	ctx := context.Background()
	result, err := client.UpdatePolicy(ctx, updatedPolicy)
	if err != nil {
		t.Fatalf("UpdatePolicy() error: %v", err)
	}

	if result == nil {
		t.Fatal("UpdatePolicy() returned nil policy")
	}

	if result.Name != "updated-name" {
		t.Errorf("UpdatePolicy() name = %v, want updated-name", result.Name)
	}

	if result.Priority != 200 {
		t.Errorf("UpdatePolicy() priority = %v, want 200", result.Priority)
	}
}

func TestPAPClient_UpdatePolicy_NilPolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.UpdatePolicy(ctx, nil)
	if err == nil {
		t.Error("UpdatePolicy() with nil policy expected error, got nil")
	}
}

func TestPAPClient_UpdatePolicy_MissingID(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	policy := &Policy{
		Name:    "test-policy",
		Enabled: true,
	}

	ctx := context.Background()
	_, err := client.UpdatePolicy(ctx, policy)
	if err == nil {
		t.Error("UpdatePolicy() with missing ID expected error, got nil")
	}
}

// ===== DeletePolicy Tests =====

func TestPAPClient_DeletePolicy(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate a policy
	mockServer.policies["policy-123"] = &Policy{ID: "policy-123", Name: "test"}

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	err := client.DeletePolicy(ctx, "policy-123")
	if err != nil {
		t.Fatalf("DeletePolicy() error: %v", err)
	}

	// Verify deletion
	if _, exists := mockServer.policies["policy-123"]; exists {
		t.Error("DeletePolicy() should have removed the policy")
	}
}

func TestPAPClient_DeletePolicy_MissingID(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	err := client.DeletePolicy(ctx, "")
	if err == nil {
		t.Error("DeletePolicy() with missing ID expected error, got nil")
	}
}

// ===== CreateEntitlement Tests =====

func TestPAPClient_CreateEntitlement(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	entitlement := &EntitlementCreate{
		Name:        "test-entitlement",
		Description: "Test entitlement",
		SubjectAttributes: map[string]interface{}{
			"department": "engineering",
		},
		ResourceAttributes: map[string]interface{}{
			"type": "document",
		},
		Actions: []string{"read", "write"},
		Enabled: true,
	}

	ctx := context.Background()
	created, err := client.CreateEntitlement(ctx, entitlement)
	if err != nil {
		t.Fatalf("CreateEntitlement() error: %v", err)
	}

	if created == nil {
		t.Fatal("CreateEntitlement() returned nil entitlement")
	}

	if created.ID == "" {
		t.Error("CreateEntitlement() should return entitlement ID")
	}

	if created.Name != entitlement.Name {
		t.Errorf("CreateEntitlement() name = %v, want %v", created.Name, entitlement.Name)
	}

	if len(created.Actions) != 2 {
		t.Errorf("CreateEntitlement() actions count = %v, want 2", len(created.Actions))
	}
}

func TestPAPClient_CreateEntitlement_NilEntitlement(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.CreateEntitlement(ctx, nil)
	if err == nil {
		t.Error("CreateEntitlement() with nil entitlement expected error, got nil")
	}
}

func TestPAPClient_CreateEntitlement_MissingName(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	entitlement := &EntitlementCreate{
		SubjectAttributes: map[string]interface{}{"sub": "user123"},
		Actions:           []string{"read"},
		Enabled:           true,
	}

	ctx := context.Background()
	_, err := client.CreateEntitlement(ctx, entitlement)
	if err == nil {
		t.Error("CreateEntitlement() with missing name expected error, got nil")
	}
}

// ===== GetEntitlement Tests =====

func TestPAPClient_GetEntitlement(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate an entitlement
	testEntitlement := &EntitlementResponse{
		ID:      "entitlement-123",
		Name:    "test-entitlement",
		Actions: []string{"read"},
		Enabled: true,
	}
	mockServer.entitlement["entitlement-123"] = testEntitlement

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	entitlement, err := client.GetEntitlement(ctx, "entitlement-123")
	if err != nil {
		t.Fatalf("GetEntitlement() error: %v", err)
	}

	if entitlement == nil {
		t.Fatal("GetEntitlement() returned nil entitlement")
	}

	if entitlement.ID != testEntitlement.ID {
		t.Errorf("GetEntitlement() ID = %v, want %v", entitlement.ID, testEntitlement.ID)
	}
}

func TestPAPClient_GetEntitlement_MissingID(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.GetEntitlement(ctx, "")
	if err == nil {
		t.Error("GetEntitlement() with missing ID expected error, got nil")
	}
}

func TestPAPClient_GetEntitlement_NotFound(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	_, err := client.GetEntitlement(ctx, "nonexistent-entitlement")
	if err == nil {
		t.Error("GetEntitlement() expected error for not found, got nil")
	}
}

// ===== ListEntitlements Tests =====

func TestPAPClient_ListEntitlements(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate entitlements
	mockServer.entitlement["ent-1"] = &EntitlementResponse{ID: "ent-1", Name: "Entitlement 1"}
	mockServer.entitlement["ent-2"] = &EntitlementResponse{ID: "ent-2", Name: "Entitlement 2"}

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	entitlements, err := client.ListEntitlements(ctx)
	if err != nil {
		t.Fatalf("ListEntitlements() error: %v", err)
	}

	if len(entitlements) != 2 {
		t.Errorf("ListEntitlements() returned %d entitlements, want 2", len(entitlements))
	}
}

func TestPAPClient_ListEntitlements_Empty(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	entitlements, err := client.ListEntitlements(ctx)
	if err != nil {
		t.Fatalf("ListEntitlements() error: %v", err)
	}

	if len(entitlements) != 0 {
		t.Errorf("ListEntitlements() returned %d entitlements, want 0", len(entitlements))
	}
}

// ===== DeleteEntitlement Tests =====

func TestPAPClient_DeleteEntitlement(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()

	// Pre-populate an entitlement
	mockServer.entitlement["entitlement-123"] = &EntitlementResponse{ID: "entitlement-123", Name: "test"}

	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	err := client.DeleteEntitlement(ctx, "entitlement-123")
	if err != nil {
		t.Fatalf("DeleteEntitlement() error: %v", err)
	}

	// Verify deletion
	if _, exists := mockServer.entitlement["entitlement-123"]; exists {
		t.Error("DeleteEntitlement() should have removed the entitlement")
	}
}

func TestPAPClient_DeleteEntitlement_MissingID(t *testing.T) {
	mockServer := newMockPAPServer()
	defer mockServer.Close()
	client := setupPAPTest(t, mockServer)

	ctx := context.Background()
	err := client.DeleteEntitlement(ctx, "")
	if err == nil {
		t.Error("DeleteEntitlement() with missing ID expected error, got nil")
	}
}