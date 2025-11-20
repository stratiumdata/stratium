package platform

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttributeBasedDecision tests the complete flow with attribute maps
func TestAttributeBasedDecision(t *testing.T) {
	// Create server without PDP (legacy mode for testing)
	server := NewServer(getTestConfig())
	require.NotNil(t, server)

	ctx := context.Background()

	tests := []struct {
		name               string
		request            *GetDecisionRequest
		expectedDecision   Decision
		expectedReasonPart string
	}{
		{
			name: "Admin access allowed",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":  "admin456",
					"role": "admin",
				}),
				ResourceAttributes: map[string]string{
					"name": "sensitive-document",
					"type": "document",
				},
				Action:  "delete",
				Context: map[string]string{},
			},
			expectedDecision:   Decision_DECISION_ALLOW,
			expectedReasonPart: "admin privileges",
		},
		{
			name: "User with valid entitlement",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":        "user123",
					"department": "engineering",
				}),
				ResourceAttributes: map[string]string{
					"name": "document-service",
					"type": "service",
				},
				Action:  "read",
				Context: map[string]string{},
			},
			expectedDecision:   Decision_DECISION_ALLOW,
			expectedReasonPart: "entitlement",
		},
		{
			name: "User without entitlement denied",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":        "user123",
					"department": "engineering",
				}),
				ResourceAttributes: map[string]string{
					"name": "restricted-service",
					"type": "service",
				},
				Action:  "admin",
				Context: map[string]string{},
			},
			expectedDecision:   Decision_DECISION_DENY,
			expectedReasonPart: "No matching entitlements",
		},
		{
			name: "Missing subject attributes",
			request: &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(map[string]string{}),
				ResourceAttributes: map[string]string{"name": "test"},
				Action:             "read",
				Context:            map[string]string{},
			},
			expectedDecision:   Decision_DECISION_DENY,
			expectedReasonPart: "must contain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.GetDecision(ctx, tt.request)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedDecision, resp.Decision)
			assert.Contains(t, resp.Reason, tt.expectedReasonPart)
			assert.NotNil(t, resp.Timestamp)
		})
	}
}

// TestGetEntitlementsWithAttributeMap tests entitlement retrieval with attribute maps
func TestGetEntitlementsWithAttributeMap(t *testing.T) {
	server := NewServer(getTestConfig())
	require.NotNil(t, server)

	ctx := context.Background()

	tests := []struct {
		name                  string
		request               *GetEntitlementsRequest
		expectedMinCount      int
		shouldError           bool
		expectedErrorContains string
	}{
		{
			name: "Get entitlements for user123",
			request: &GetEntitlementsRequest{
				Subject: StringMapToValueMap(map[string]string{
					"sub":   "user123",
					"email": "user123@example.com",
				}),
				PageSize: 10,
			},
			expectedMinCount: 1,
			shouldError:      false,
		},
		{
			name: "Get entitlements with resource filter",
			request: &GetEntitlementsRequest{
				Subject: StringMapToValueMap(map[string]string{
					"sub": "user123",
				}),
				ResourceFilter: "document-service",
				PageSize:       10,
			},
			expectedMinCount: 1,
			shouldError:      false,
		},
		{
			name: "Missing subject ID in attributes",
			request: &GetEntitlementsRequest{
				Subject: StringMapToValueMap(map[string]string{
					"email": "user@example.com",
				}),
				PageSize: 10,
			},
			shouldError:           true,
			expectedErrorContains: "must contain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := server.GetEntitlements(ctx, tt.request)

			if tt.shouldError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErrorContains)
			} else {
				require.NoError(t, err)
				assert.GreaterOrEqual(t, len(resp.Entitlements), tt.expectedMinCount)
				assert.NotNil(t, resp.Timestamp)
			}
		})
	}
}

// TestManualResourceAttributes tests with manually created resource attributes
// (ZTDF integration test is in pkg/integration to avoid import cycles)
func TestManualResourceAttributes(t *testing.T) {
	server := NewServer(getTestConfig())
	require.NotNil(t, server)

	// Manually create resource attributes (simulating ZTDF extraction)
	resourceAttrs := map[string]string{
		"Classification": "secret",
		"Department":     "engineering",
		"Clearance":      "top-secret",
	}

	// Create a decision request using resource attributes
	req := &GetDecisionRequest{
		SubjectAttributes: StringMapToValueMap(map[string]string{
			"sub":            "user123",
			"classification": "top-secret",
			"department":     "engineering",
		}),
		ResourceAttributes: resourceAttrs,
		Action:             "read",
		Context:            map[string]string{},
	}

	// Evaluate the decision
	resp, err := server.GetDecision(context.Background(), req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Reason)
	assert.NotNil(t, resp.Timestamp)
}

// TestAttributeMatchingScenarios tests various attribute matching scenarios
func TestAttributeMatchingScenarios(t *testing.T) {
	server := NewServer(getTestConfig())
	ctx := context.Background()

	tests := []struct {
		name             string
		subjectAttrs     map[string]string
		resourceAttrs    map[string]string
		action           string
		expectedDecision Decision
		description      string
	}{
		{
			name: "Exact attribute match",
			subjectAttrs: map[string]string{
				"sub":            "user123",
				"classification": "secret",
				"department":     "engineering",
			},
			resourceAttrs: map[string]string{
				"Classification": "secret",
				"Department":     "engineering",
			},
			action:           "read",
			expectedDecision: Decision_DECISION_ALLOW,
			description:      "Subject and resource attributes match perfectly",
		},
		{
			name: "Attribute mismatch - higher classification required",
			subjectAttrs: map[string]string{
				"sub":            "user123",
				"classification": "confidential",
			},
			resourceAttrs: map[string]string{
				"Classification": "secret",
			},
			action:           "read",
			expectedDecision: Decision_DECISION_DENY,
			description:      "Subject classification lower than resource requirement",
		},
		{
			name: "Multiple subject attributes",
			subjectAttrs: map[string]string{
				"sub":          "user123",
				"email":        "user123@example.com",
				"department":   "engineering",
				"role":         "developer",
				"country":      "US",
				"organization": "Acme Corp",
			},
			resourceAttrs: map[string]string{
				"name":       "document-service",
				"department": "engineering",
			},
			action:           "read",
			expectedDecision: Decision_DECISION_ALLOW,
			description:      "Rich subject attributes for fine-grained access control",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &GetDecisionRequest{
				SubjectAttributes:  StringMapToValueMap(tt.subjectAttrs),
				ResourceAttributes: tt.resourceAttrs,
				Action:             tt.action,
				Context:            map[string]string{},
			}

			resp, err := server.GetDecision(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedDecision, resp.Decision, tt.description)
		})
	}
}

// BenchmarkAttributeBasedDecision benchmarks the decision evaluation with attributes
func BenchmarkAttributeBasedDecision(b *testing.B) {
	server := NewServer(getTestConfig())
	ctx := context.Background()

	req := &GetDecisionRequest{
		SubjectAttributes: StringMapToValueMap(map[string]string{
			"sub":        "user123",
			"email":      "user@example.com",
			"department": "engineering",
			"role":       "developer",
		}),
		ResourceAttributes: map[string]string{
			"name":       "document-service",
			"type":       "service",
			"department": "engineering",
		},
		Action:  "read",
		Context: map[string]string{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = server.GetDecision(ctx, req)
	}
}