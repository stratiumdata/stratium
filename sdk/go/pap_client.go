package stratium

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// PAPClient provides methods for managing policies and entitlements.
//
// The PAP (Policy Administration Point) service provides HTTP REST APIs
// for CRUD operations on policies and entitlements.
type PAPClient struct {
	config     *Config
	auth       tokenProvider
	httpClient *http.Client
	baseURL    string
}

// Policy represents an authorization policy.
type Policy struct {
	ID            string                 `json:"id,omitempty"`
	Name          string                 `json:"name"`
	Description   string                 `json:"description,omitempty"`
	Language      string                 `json:"language"` // "XACML" or "OPA"
	PolicyContent string                 `json:"policy_content"`
	Effect        string                 `json:"effect"` // "allow" or "deny"
	Priority      int                    `json:"priority"`
	Enabled       bool                   `json:"enabled"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     string                 `json:"created_at,omitempty"`
	UpdatedAt     string                 `json:"updated_at,omitempty"`
}

// EntitlementCreate represents an entitlement creation request.
type EntitlementCreate struct {
	Name               string                 `json:"name"`
	Description        string                 `json:"description,omitempty"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes,omitempty"`
	Actions            []string               `json:"actions"`
	Enabled            bool                   `json:"enabled"`
	StartsAt           string                 `json:"starts_at,omitempty"`
	ExpiresAt          string                 `json:"expires_at,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

// EntitlementResponse represents an entitlement from the API.
type EntitlementResponse struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Description        string                 `json:"description,omitempty"`
	SubjectAttributes  map[string]interface{} `json:"subject_attributes"`
	ResourceAttributes map[string]interface{} `json:"resource_attributes,omitempty"`
	Actions            []string               `json:"actions"`
	Enabled            bool                   `json:"enabled"`
	StartsAt           string                 `json:"starts_at,omitempty"`
	ExpiresAt          string                 `json:"expires_at,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt          string                 `json:"created_at"`
	UpdatedAt          string                 `json:"updated_at"`
}

// newPAPClient creates a new PAP client.
func newPAPClient(config *Config, auth tokenProvider) *PAPClient {
	return &PAPClient{
		config:  config,
		auth:    auth,
		baseURL: config.PAPAddress,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// getToken retrieves the auth token if authentication is configured
func (c *PAPClient) getToken(ctx context.Context) (string, error) {
	if c.auth == nil {
		return "", nil
	}
	token, err := c.auth.GetToken(ctx)
	if err != nil {
		return "", NewAuthenticationError("failed to get auth token", err)
	}
	return token, nil
}

// CreatePolicy creates a new policy.
//
// Example:
//
//	policy, err := client.PAP.CreatePolicy(ctx, &stratium.Policy{
//	    Name:          "admin-access",
//	    Description:   "Admins have full access",
//	    Language:      "OPA",
//	    PolicyContent: "package authz\ndefault allow = true",
//	    Effect:        "allow",
//	    Priority:      100,
//	    Enabled:       true,
//	})
func (c *PAPClient) CreatePolicy(ctx context.Context, policy *Policy) (*Policy, error) {
	// Validate request
	if policy == nil {
		return nil, NewValidationError("policy", "cannot be nil")
	}
	if policy.Name == "" {
		return nil, NewValidationError("policy.name", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+PAPPoliciesPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeJSON)
	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdPolicy Policy
	if err := json.NewDecoder(resp.Body).Decode(&createdPolicy); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &createdPolicy, nil
}

// GetPolicy retrieves a policy by ID.
//
// Example:
//
//	policy, err := client.PAP.GetPolicy(ctx, "policy-123")
func (c *PAPClient) GetPolicy(ctx context.Context, policyID string) (*Policy, error) {
	// Validate request
	if policyID == "" {
		return nil, NewValidationError("policy_id", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s%s/%s", c.baseURL, PAPPoliciesPath, policyID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var policy Policy
	if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &policy, nil
}

// ListPolicies retrieves all policies.
//
// Example:
//
//	policies, err := client.PAP.ListPolicies(ctx)
func (c *PAPClient) ListPolicies(ctx context.Context) ([]*Policy, error) {
	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+PAPPoliciesPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var policies []*Policy
	if err := json.NewDecoder(resp.Body).Decode(&policies); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return policies, nil
}

// UpdatePolicy updates an existing policy.
//
// Example:
//
//	policy.Enabled = false
//	updated, err := client.PAP.UpdatePolicy(ctx, policy)
func (c *PAPClient) UpdatePolicy(ctx context.Context, policy *Policy) (*Policy, error) {
	// Validate request
	if policy == nil {
		return nil, NewValidationError("policy", "cannot be nil")
	}
	if policy.ID == "" {
		return nil, NewValidationError("policy.id", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", fmt.Sprintf("%s%s/%s", c.baseURL, PAPPoliciesPath, policy.ID), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeJSON)
	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var updatedPolicy Policy
	if err := json.NewDecoder(resp.Body).Decode(&updatedPolicy); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &updatedPolicy, nil
}

// DeletePolicy deletes a policy.
//
// Example:
//
//	err := client.PAP.DeletePolicy(ctx, "policy-123")
func (c *PAPClient) DeletePolicy(ctx context.Context, policyID string) error {
	// Validate request
	if policyID == "" {
		return NewValidationError("policy_id", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s%s/%s", c.baseURL, PAPPoliciesPath, policyID), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// CreateEntitlement creates a new entitlement.
//
// Example:
//
//	entitlement, err := client.PAP.CreateEntitlement(ctx, &stratium.EntitlementCreate{
//	    Name: "engineering-docs-read",
//	    SubjectAttributes: map[string]interface{}{
//	        "department": "engineering",
//	    },
//	    ResourceAttributes: map[string]interface{}{
//	        "type": "document",
//	    },
//	    Actions: []string{"read"},
//	    Enabled: true,
//	})
func (c *PAPClient) CreateEntitlement(ctx context.Context, entitlement *EntitlementCreate) (*EntitlementResponse, error) {
	// Validate request
	if entitlement == nil {
		return nil, NewValidationError("entitlement", "cannot be nil")
	}
	if entitlement.Name == "" {
		return nil, NewValidationError("entitlement.name", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(entitlement)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entitlement: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+PAPEntitlementsPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", ContentTypeJSON)
	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var createdEntitlement EntitlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&createdEntitlement); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &createdEntitlement, nil
}

// GetEntitlement retrieves an entitlement by ID.
//
// Example:
//
//	entitlement, err := client.PAP.GetEntitlement(ctx, "entitlement-123")
func (c *PAPClient) GetEntitlement(ctx context.Context, entitlementID string) (*EntitlementResponse, error) {
	// Validate request
	if entitlementID == "" {
		return nil, NewValidationError("entitlement_id", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s%s/%s", c.baseURL, PAPEntitlementsPath, entitlementID), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var entitlement EntitlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&entitlement); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &entitlement, nil
}

// ListEntitlements retrieves all entitlements.
//
// Example:
//
//	entitlements, err := client.PAP.ListEntitlements(ctx)
func (c *PAPClient) ListEntitlements(ctx context.Context) ([]*EntitlementResponse, error) {
	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", c.baseURL+PAPEntitlementsPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var entitlements []*EntitlementResponse
	if err := json.NewDecoder(resp.Body).Decode(&entitlements); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return entitlements, nil
}

// DeleteEntitlement deletes an entitlement.
//
// Example:
//
//	err := client.PAP.DeleteEntitlement(ctx, "entitlement-123")
func (c *PAPClient) DeleteEntitlement(ctx context.Context, entitlementID string) error {
	// Validate request
	if entitlementID == "" {
		return NewValidationError("entitlement_id", "is required")
	}

	// Get auth token
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s%s/%s", c.baseURL, PAPEntitlementsPath, entitlementID), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if token != "" {
		req.Header.Set("Authorization", AuthHeaderPrefix+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
