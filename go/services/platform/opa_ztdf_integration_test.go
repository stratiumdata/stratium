package platform

import (
	"context"
	"encoding/json"
	"stratium/pkg/extractors"
	"strings"
	"testing"

	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/google/uuid"
)

// containsIgnoreCase checks if a string contains another string (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// TestOPAClassificationBasedAccessWithZTDF tests OPA policy evaluation with ZTDF classification
func TestOPAClassificationBasedAccessWithZTDF(t *testing.T) {
	ctx := context.Background()

	// Define the classification-based-access OPA policy
	classificationPolicy := `
package stratium.authz

import rego.v1

# Classification levels hierarchy
classification_levels := {
	"UNCLASSIFIED": 0,
	"RESTRICTED": 1,
	"CONFIDENTIAL": 2,
	"SECRET": 3,
	"TOP-SECRET": 4,
	"TOP_SECRET": 4,
	# URI forms
	"urn:ztdf:nato:classification:unclassified": 0,
	"urn:ztdf:nato:classification:restricted": 1,
	"urn:ztdf:nato:classification:confidential": 2,
	"urn:ztdf:nato:classification:secret": 3,
	"urn:ztdf:nato:classification:top-secret": 4,
	"urn:ztdf:dod:classification:unclassified": 0,
	"urn:ztdf:dod:classification:restricted": 1,
	"urn:ztdf:dod:classification:confidential": 2,
	"urn:ztdf:dod:classification:secret": 3,
	"urn:ztdf:dod:classification:top-secret": 4,
}

# Helper function to get classification level
get_level(classification) := level if {
	# Convert to uppercase for case-insensitive matching
	upper_class := upper(classification)
	level := classification_levels[upper_class]
} else := level if {
	# Try direct match (for URIs)
	level := classification_levels[classification]
} else := -1

# Helper function to normalize classification
normalize_classification(classification) := upper(classification) if {
	not contains(classification, ":")
} else := classification

# Main authorization rule
default allow := false

# Allow if subject clearance >= resource classification
allow if {
	subject_classification := input.subject.classification
	resource_classification := input.resource.classification

	subject_level := get_level(normalize_classification(subject_classification))
	resource_level := get_level(normalize_classification(resource_classification))

	# Subject must have valid clearance
	subject_level >= 0

	# Resource must have valid classification
	resource_level >= 0

	# Subject clearance must be >= resource classification
	subject_level >= resource_level
}

# Allow if both subject and resource have same classification (exact match)
allow if {
	upper(input.subject.classification) == upper(input.resource.classification)
}

# Deny reasons for debugging
deny contains reason if {
	subject_classification := input.subject.classification
	resource_classification := input.resource.classification

	subject_level := get_level(normalize_classification(subject_classification))
	resource_level := get_level(normalize_classification(resource_classification))

	subject_level < resource_level
	reason := sprintf("Insufficient clearance: subject level %d < resource level %d", [subject_level, resource_level])
}

deny contains reason if {
	not input.subject.classification
	reason := "Subject missing classification attribute"
}

deny contains reason if {
	not input.resource.classification
	reason := "Resource missing classification attribute"
}
`

	tests := []struct {
		name                   string
		policy                 *models.Policy
		input                  *policy_engine.EvaluationInput
		expectedAllow          bool
		expectedReasonContains string
	}{
		{
			name: "SECRET clearance can access CONFIDENTIAL document",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@nato.int",
					"classification": "SECRET",
				},
				Resource: map[string]interface{}{
					"name":           "document-123.ztdf",
					"classification": "CONFIDENTIAL",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          true,
			expectedReasonContains: "Access allowed",
		},
		{
			name: "CONFIDENTIAL clearance DENIED for SECRET document",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@nato.int",
					"classification": "CONFIDENTIAL",
				},
				Resource: map[string]interface{}{
					"name":           "document-456.ztdf",
					"classification": "SECRET",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          false,
			expectedReasonContains: "Access denied",
		},
		{
			name: "TOP-SECRET clearance can access UNCLASSIFIED document",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "admin@dod.gov",
					"classification": "TOP-SECRET",
				},
				Resource: map[string]interface{}{
					"name":           "public-doc.ztdf",
					"classification": "UNCLASSIFIED",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          true,
			expectedReasonContains: "Access allowed",
		},
		{
			name: "Case insensitive - secret can access confidential",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@example.com",
					"classification": "secret",
				},
				Resource: map[string]interface{}{
					"name":           "doc.ztdf",
					"classification": "confidential",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          true,
			expectedReasonContains: "Access allowed",
		},
		{
			name: "URI format - urn:ztdf:nato:classification:secret can access confidential",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@nato.int",
					"classification": "urn:ztdf:nato:classification:secret",
				},
				Resource: map[string]interface{}{
					"name":           "classified-doc.ztdf",
					"classification": "urn:ztdf:nato:classification:confidential",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          true,
			expectedReasonContains: "Access allowed",
		},
		{
			name: "Same level - SECRET can access SECRET",
			policy: &models.Policy{
				ID:            uuid.New(),
				Name:          "classification-based-access",
				Language:      models.PolicyLanguageOPA,
				PolicyContent: classificationPolicy,
				Effect:        models.PolicyEffectAllow,
				Priority:      100,
				Enabled:       true,
			},
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "peer@nato.int",
					"classification": "SECRET",
				},
				Resource: map[string]interface{}{
					"name":           "same-level-doc.ztdf",
					"classification": "SECRET",
				},
				Action:      "read",
				Environment: map[string]interface{}{},
			},
			expectedAllow:          true,
			expectedReasonContains: "Access allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create OPA engine
			engine := policy_engine.NewOPAEngine()

			// Evaluate policy
			result, err := engine.Evaluate(ctx, tt.policy, tt.input)
			if err != nil {
				t.Fatalf("Policy evaluation failed: %v", err)
			}

			if result.Allow != tt.expectedAllow {
				t.Errorf("Expected allow=%v, got %v. Reason: %s",
					tt.expectedAllow, result.Allow, result.Reason)

				// Print debug information
				if details, err := json.MarshalIndent(result.Details, "", "  "); err == nil {
					t.Logf("Details: %s", details)
				}
			}

			if tt.expectedReasonContains != "" {
				if !containsIgnoreCase(result.Reason, tt.expectedReasonContains) {
					t.Errorf("Expected reason to contain %q, got %q",
						tt.expectedReasonContains, result.Reason)
				}
			}

			t.Logf("Result: allow=%v, reason=%s", result.Allow, result.Reason)
		})
	}
}

// TestOPAIntegrationWithPDP tests OPA policy integration with the Policy Decision Point
func TestOPAIntegrationWithPDP(t *testing.T) {
	ctx := context.Background()

	// Create classification-based OPA policy
	classificationPolicy := `
package stratium.authz

import rego.v1

classification_levels := {
	"UNCLASSIFIED": 0,
	"RESTRICTED": 1,
	"CONFIDENTIAL": 2,
	"SECRET": 3,
	"TOP-SECRET": 4,
}

default allow := false

allow if {
	subject_level := classification_levels[upper(input.subject.classification)]
	resource_level := classification_levels[upper(input.resource.classification)]
	subject_level >= resource_level
}
`

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "opa-classification-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: classificationPolicy,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Mock repositories
	mockPolicyRepo := &mockPDPPolicyRepository{
		policies: []*models.Policy{policy},
	}

	mockRepo := &repository.Repository{
		Policy:      mockPolicyRepo,
		Entitlement: &mockPDPEntitlementRepository{},
		Audit:       &mockPDPAuditRepository{},
	}

	// Create PDP with OPA support
	pdp := NewPolicyDecisionPoint(mockRepo)

	tests := []struct {
		name             string
		request          *GetDecisionRequest
		expectedDecision Decision
	}{
		{
			name: "PDP with OPA - SECRET accesses CONFIDENTIAL (ALLOW)",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":            "user@nato.int",
					"classification": "SECRET",
				}),
				ResourceAttributes: map[string]string{
					"classification": "CONFIDENTIAL",
				},
				Action: "read",
			},
			expectedDecision: Decision_DECISION_ALLOW,
		},
		{
			name: "PDP with OPA - CONFIDENTIAL accesses SECRET (DENY)",
			request: &GetDecisionRequest{
				SubjectAttributes: StringMapToValueMap(map[string]string{
					"sub":            "user@nato.int",
					"classification": "CONFIDENTIAL",
				}),
				ResourceAttributes: map[string]string{
					"name":           "secret-doc.ztdf",
					"classification": "SECRET",
				},
				Action: "read",
			},
			expectedDecision: Decision_DECISION_DENY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := pdp.evaluatePolicies(ctx, tt.request)
			if err != nil {
				t.Fatalf("PDP evaluation failed: %v", err)
			}

			// Handle default deny (nil result)
			if result == nil {
				result = pdp.defaultDenyDecision(tt.request, "No matching policies found")
			}

			if result.Decision != tt.expectedDecision {
				t.Errorf("Expected decision %v, got %v. Reason: %s",
					tt.expectedDecision, result.Decision, result.Reason)
			}

			t.Logf("Decision: %v, Reason: %s", result.Decision, result.Reason)
		})
	}
}

// TestZTDFAttributeExtraction tests extracting classification from ZTDF manifests
func TestZTDFAttributeExtraction(t *testing.T) {
	tests := []struct {
		name                   string
		manifestJSON           string
		expectedClassification string
		expectedHandling       string
	}{
		{
			name: "Extract classification from ZTDF manifest",
			manifestJSON: `{
				"assertions": [
					{
						"id": "assertion-1",
						"type": "handling",
						"scope": "tdo",
						"appliesToState": "encrypted",
						"statement": {
							"format": "string",
							"value": "urn:ztdf:nato:classification:secret"
						},
						"binding": {
							"method": "jws",
							"signature": "eyJhbGc..."
						}
					},
					{
						"id": "assertion-2",
						"type": "handling",
						"scope": "tdo",
						"appliesToState": "encrypted",
						"statement": {
							"format": "string",
							"value": "urn:ztdf:nato:handling:nato-releasable"
						},
						"binding": {
							"method": "jws",
							"signature": "eyJhbGc..."
						}
					}
				]
			}`,
			expectedClassification: "urn:ztdf:nato:classification:secret",
			expectedHandling:       "urn:ztdf:nato:handling:nato-releasable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse manifest
			var manifestData map[string]interface{}
			err := json.Unmarshal([]byte(tt.manifestJSON), &manifestData)
			if err != nil {
				t.Fatalf("Failed to parse manifest JSON: %v", err)
			}

			// Extract assertions
			assertions, ok := manifestData["assertions"].([]interface{})
			if !ok {
				t.Fatal("Failed to extract assertions from manifest")
			}

			// Extract attributes
			var classification, handling string
			for _, assertion := range assertions {
				assertionMap := assertion.(map[string]interface{})
				statement := assertionMap["statement"].(map[string]interface{})
				value := statement["value"].(string)

				if containsIgnoreCase(value, "classification") {
					classification = value
				} else if containsIgnoreCase(value, "handling") {
					handling = value
				}
			}

			if classification != tt.expectedClassification {
				t.Errorf("Expected classification %q, got %q",
					tt.expectedClassification, classification)
			}

			if handling != tt.expectedHandling {
				t.Errorf("Expected handling %q, got %q",
					tt.expectedHandling, handling)
			}

			t.Logf("Extracted - Classification: %s, Handling: %s",
				classification, handling)
		})
	}
}

// TestEndToEndOPAWithZTDF tests complete workflow: ZTDF → Attribute Extraction → OPA Evaluation
func TestEndToEndOPAWithZTDF(t *testing.T) {
	ctx := context.Background()

	// Simulated ZTDF manifest with classification
	policyBase64 := "eyJ1dWlkIjoiNzQxMjJhNTUtMWIxYy00MmIzLWIyYjItYTExYzZkYmE5NThlIiwgImJvZHkiOnsiZGF0YUF0dHJpYnV0ZXMiOlt7ImF0dHJpYnV0ZSI6Imh0dHA6Ly9leGFtcGxlLmNvbS9hdHRyL2NsYXNzaWZpY2F0aW9uL3ZhbHVlL2NvbmZpZGVudGlhbCJ9XX0sICJ0ZGZTcGVjVmVyc2lvbiI6IjQuMC4wIn0="

	// Extract classification from ZTDF
	resourceAttributes, err := extractors.ExtractResourceAttributes(policyBase64)
	if err != nil {
		t.Fatalf("Failed to extract attributes: %v", err)
	}

	// Note: DisplayName in ZTDF is "Classification" (capital C)
	resourceClassification := resourceAttributes["classification"]

	if resourceClassification == "" {
		t.Fatalf("Failed to extract classification from ZTDF manifest. Got attributes: %+v", resourceAttributes)
	}

	t.Logf("Extracted classification from ZTDF: %s", resourceClassification)

	// Create OPA policy
	classificationPolicy := `
package stratium.authz

import rego.v1

classification_levels := {
	"UNCLASSIFIED": 0,
	"RESTRICTED": 1,
	"confidential": 2,
	"SECRET": 3,
	"TOP-SECRET": 4,
	"TOP_SECRET": 4,
	# URI forms
	"urn:ztdf:nato:classification:unclassified": 0,
	"urn:ztdf:nato:classification:restricted": 1,
	"urn:ztdf:nato:classification:confidential": 2,
	"urn:ztdf:nato:classification:secret": 3,
	"urn:ztdf:nato:classification:top-secret": 4,
	"urn:ztdf:dod:classification:unclassified": 0,
	"urn:ztdf:dod:classification:restricted": 1,
	"urn:ztdf:dod:classification:confidential": 2,
	"urn:ztdf:dod:classification:secret": 3,
	"urn:ztdf:dod:classification:top-secret": 4,
}

default allow := false

allow if {
	subject_level := classification_levels[input.subject.classification]
	resource_level := classification_levels[input.resource.classification]
	subject_level >= resource_level
}
`

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "classification-based-access",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: classificationPolicy,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Create evaluation input with extracted classification
	input := &policy_engine.EvaluationInput{
		Subject: map[string]interface{}{
			"sub":            "user@nato.int",
			"classification": "urn:ztdf:nato:classification:secret",
		},
		Resource: map[string]interface{}{
			"name":           "document.ztdf",
			"classification": resourceClassification,
		},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	// Evaluate with OPA
	engine := policy_engine.NewOPAEngine()
	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("OPA evaluation failed: %v", err)
	}

	// Verify result
	if !result.Allow {
		t.Errorf("Expected ALLOW for SECRET accessing CONFIDENTIAL, got DENY. Reason: %s",
			result.Reason)
	}

	t.Logf("End-to-end test result: allow=%v, reason=%s", result.Allow, result.Reason)
}

// TestOPAWithMultipleZTDFAttributes tests OPA with multiple ZTDF attributes
func TestOPAWithMultipleZTDFAttributes(t *testing.T) {
	ctx := context.Background()

	// OPA policy that checks both classification and handling
	multiAttrPolicy := `
package stratium.authz

import rego.v1

classification_levels := {
	"urn:ztdf:nato:classification:confidential": 2,
	"urn:ztdf:nato:classification:secret": 3,
}

default allow := false

# Allow if classification matches AND handling allows
allow if {
	# Check classification hierarchy
	subject_level := classification_levels[input.subject.classification]
	resource_level := classification_levels[input.resource.classification]
	subject_level >= resource_level

	# Check handling - must match exactly or have nato-releasable
	input.resource.handling == "urn:ztdf:nato:handling:nato-releasable"
}

# Allow if no handling specified on resource
allow if {
	subject_level := classification_levels[input.subject.classification]
	resource_level := classification_levels[input.resource.classification]
	subject_level >= resource_level
	not input.resource.handling
}
`

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "multi-attribute-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: multiAttrPolicy,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	tests := []struct {
		name          string
		input         *policy_engine.EvaluationInput
		expectedAllow bool
	}{
		{
			name: "SECRET with NATO-RELEASABLE handling (ALLOW)",
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@nato.int",
					"classification": "urn:ztdf:nato:classification:secret",
				},
				Resource: map[string]interface{}{
					"name":           "doc.ztdf",
					"classification": "urn:ztdf:nato:classification:confidential",
					"handling":       "urn:ztdf:nato:handling:nato-releasable",
				},
				Action: "read",
			},
			expectedAllow: true,
		},
		{
			name: "SECRET with no handling requirement (ALLOW)",
			input: &policy_engine.EvaluationInput{
				Subject: map[string]interface{}{
					"sub":            "user@nato.int",
					"classification": "urn:ztdf:nato:classification:secret",
				},
				Resource: map[string]interface{}{
					"name":           "doc.ztdf",
					"classification": "urn:ztdf:nato:classification:confidential",
				},
				Action: "read",
			},
			expectedAllow: true,
		},
	}

	engine := policy_engine.NewOPAEngine()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluation failed: %v", err)
			}

			if result.Allow != tt.expectedAllow {
				t.Errorf("Expected allow=%v, got %v. Reason: %s",
					tt.expectedAllow, result.Allow, result.Reason)
			}

			t.Logf("Result: allow=%v, reason=%s", result.Allow, result.Reason)
		})
	}
}
