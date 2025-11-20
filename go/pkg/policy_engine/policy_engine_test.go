package policy_engine

import (
	"context"
	"testing"

	"stratium/pkg/models"
)

func TestEngineFactory_GetEngine(t *testing.T) {
	factory := NewEngineFactory()

	tests := []struct {
		name     string
		language models.PolicyLanguage
		wantErr  bool
	}{
		{
			name:     "Get OPA engine",
			language: models.PolicyLanguageOPA,
			wantErr:  false,
		},
		{
			name:     "Get XACML engine",
			language: models.PolicyLanguageXACML,
			wantErr:  false,
		},
		{
			name:     "Get JSON engine",
			language: models.PolicyLanguageJSON,
			wantErr:  false,
		},
		{
			name:     "Invalid language",
			language: models.PolicyLanguage("invalid"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := factory.GetEngine(tt.language)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if engine == nil {
				t.Error("Expected non-nil engine")
			}
		})
	}
}

func TestOPAEngine_ValidatePolicy(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		wantErr       bool
	}{
		{
			name: "Valid OPA policy",
			policyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
}`,
			language: models.PolicyLanguageOPA,
			wantErr:  false,
		},
		{
			name:          "Invalid OPA policy - syntax error",
			policyContent: `package stratium.authz\ninvalid syntax here`,
			language:      models.PolicyLanguageOPA,
			wantErr:       true,
		},
		{
			name:          "Empty policy content",
			policyContent: "",
			language:      models.PolicyLanguageOPA,
			wantErr:       true,
		},
		{
			name:          "Wrong language",
			policyContent: "package test",
			language:      models.PolicyLanguageXACML,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, tt.language)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestOPAEngine_Evaluate(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	// Simple allow policy
	allowPolicy := &models.Policy{
		Name:     "test-allow",
		Language: models.PolicyLanguageOPA,
		PolicyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
}`,
		Effect: models.PolicyEffectAllow,
	}

	// Simple deny policy - blocks users with "blocked" role
	denyPolicy := &models.Policy{
		Name:     "test-deny",
		Language: models.PolicyLanguageOPA,
		PolicyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role != "blocked"
}`,
		Effect: models.PolicyEffectDeny,
	}

	tests := []struct {
		name        string
		policy      *models.Policy
		input       *EvaluationInput
		expectAllow bool
	}{
		{
			name:   "Admin should be allowed",
			policy: allowPolicy,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name:   "Non-admin should be denied",
			policy: allowPolicy,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: false,
		},
		{
			name:   "Blocked user should be denied",
			policy: denyPolicy,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "blocked",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Evaluate(ctx, tt.policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}

			if result.PolicyName != tt.policy.Name {
				t.Errorf("Expected policy name %s, got %s", tt.policy.Name, result.PolicyName)
			}
		})
	}
}

func TestXACMLEngine_ValidatePolicy(t *testing.T) {
	engine := NewXACMLEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		wantErr       bool
	}{
		{
			name: "Valid XACML policy",
			policyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
    <Description>Test Policy</Description>
    <Target/>
    <Rule RuleId="allow-admin" Effect="Permit">
        <Description>Allow admin</Description>
        <Target/>
        <Condition>
            <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">admin</AttributeValue>
            </Apply>
        </Condition>
    </Rule>
</Policy>`,
			language: models.PolicyLanguageXACML,
			wantErr:  false,
		},
		{
			name:          "Invalid XML",
			policyContent: `<Policy><Invalid>`,
			language:      models.PolicyLanguageXACML,
			wantErr:       true,
		},
		{
			name:          "Missing PolicyId",
			policyContent: `<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"></Policy>`,
			language:      models.PolicyLanguageXACML,
			wantErr:       true,
		},
		{
			name:          "Wrong language",
			policyContent: `<Policy PolicyId="test"></Policy>`,
			language:      models.PolicyLanguageOPA,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, tt.language)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestXACMLEngine_Evaluate(t *testing.T) {
	engine := NewXACMLEngine()
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "test-xacml",
		Language: models.PolicyLanguageXACML,
		PolicyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
    <Rule RuleId="allow-admin" Effect="Permit">
        <Condition>role admin</Condition>
    </Rule>
</Policy>`,
		Effect: models.PolicyEffectAllow,
	}

	tests := []struct {
		name  string
		input *EvaluationInput
	}{
		{
			name: "Evaluate with admin role",
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
		},
		{
			name: "Evaluate with user role",
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result == nil {
				t.Fatal("Expected non-nil result")
			}

			if result.PolicyName != policy.Name {
				t.Errorf("Expected policy name %s, got %s", policy.Name, result.PolicyName)
			}

			if result.Reason == "" {
				t.Error("Expected non-empty reason")
			}
		})
	}
}

// Benchmark tests
func BenchmarkOPAEngine_Evaluate(b *testing.B) {
	engine := NewOPAEngine()
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "benchmark-policy",
		Language: models.PolicyLanguageOPA,
		PolicyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
}`,
		Effect: models.PolicyEffectAllow,
	}

	input := &EvaluationInput{
		Subject: map[string]interface{}{
			"role": "admin",
		},
		Resource: map[string]interface{}{
			"type": "document",
		},
		Action: "read",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, policy, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkXACMLEngine_Evaluate(b *testing.B) {
	engine := NewXACMLEngine()
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "benchmark-xacml",
		Language: models.PolicyLanguageXACML,
		PolicyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="benchmark-policy"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
    <Rule RuleId="allow-admin" Effect="Permit">
        <Condition>role admin</Condition>
    </Rule>
</Policy>`,
		Effect: models.PolicyEffectAllow,
	}

	input := &EvaluationInput{
		Subject: map[string]interface{}{
			"role": "admin",
		},
		Resource: map[string]interface{}{
			"type": "document",
		},
		Action: "read",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, policy, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}
func TestJSONEngine_ValidatePolicy(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		wantErr       bool
	}{
		{
			name: "Valid JSON policy",
			policyContent: `{
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
			language: models.PolicyLanguageJSON,
			wantErr:  false,
		},
		{
			name:          "Invalid JSON syntax",
			policyContent: `{"invalid": json}`,
			language:      models.PolicyLanguageJSON,
			wantErr:       true,
		},
		{
			name: "Missing version field",
			policyContent: `{
				"rules": [
					{
						"id": "test",
						"effect": "allow",
						"conditions": {}
					}
				]
			}`,
			language: models.PolicyLanguageJSON,
			wantErr:  true,
		},
		{
			name: "Missing rules",
			policyContent: `{
				"version": "1.0",
				"rules": []
			}`,
			language: models.PolicyLanguageJSON,
			wantErr:  true,
		},
		{
			name: "Invalid effect",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "test",
						"effect": "invalid",
						"conditions": {}
					}
				]
			}`,
			language: models.PolicyLanguageJSON,
			wantErr:  true,
		},
		{
			name:          "Wrong language",
			policyContent: `{"version": "1.0", "rules": []}`,
			language:      models.PolicyLanguageOPA,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, tt.language)

			if tt.wantErr && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestJSONEngine_Evaluate(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
		expectReason  string
	}{
		{
			name: "Simple allow - admin role",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-admin",
						"description": "Allow administrators",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "admin"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow:  true,
			expectReason: "Rule allow-admin permits access",
		},
		{
			name: "Simple deny - non-admin",
			policyContent: `{
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
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow:  false,
			expectReason: "No matching rule found",
		},
		{
			name: "Action matching - wildcard",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-all-actions",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": "*"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Action matching - specific action",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-read",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": "read"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $eq",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-engineering",
						"effect": "allow",
						"conditions": {
							"subject": {
								"department": {
									"$eq": "engineering"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"department": "engineering",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $in",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-multiple-roles",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": {
									"$in": ["admin", "moderator", "editor"]
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "editor",
				},
				Action: "write",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $contains",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-email-domain",
						"effect": "allow",
						"conditions": {
							"subject": {
								"email": {
									"$contains": "@company.com"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"email": "user@company.com",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "AllOf - AND logic",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "require-admin-and-department",
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
										"department": "engineering"
									}
								}
							]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role":       "admin",
					"department": "engineering",
				},
				Action: "manage",
			},
			expectAllow: true,
		},
		{
			name: "AnyOf - OR logic",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-admin-or-moderator",
						"effect": "allow",
						"conditions": {
							"anyOf": [
								{
									"subject": {
										"role": "admin"
									}
								},
								{
									"subject": {
										"role": "moderator"
									}
								}
							]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "moderator",
				},
				Action: "moderate",
			},
			expectAllow: true,
		},
		{
			name: "Deny rule takes precedence",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-all",
						"effect": "allow",
						"conditions": {
							"subject": {
								"authenticated": true
							}
						}
					},
					{
						"id": "deny-blocked",
						"effect": "deny",
						"conditions": {
							"subject": {
								"status": "blocked"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"authenticated": true,
					"status":        "blocked",
				},
				Action: "read",
			},
			expectAllow:  false,
			expectReason: "Rule deny-blocked denies access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-json-policy",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
				Effect:        models.PolicyEffectAllow,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}

			if tt.expectReason != "" {
				matched := false
				for i := 0; i <= len(result.Reason)-len(tt.expectReason); i++ {
					if result.Reason[i:i+len(tt.expectReason)] == tt.expectReason {
						matched = true
						break
					}
				}
				if !matched {
					t.Errorf("Expected reason to contain %q, got %q", tt.expectReason, result.Reason)
				}
			}
		})
	}
}

func BenchmarkJSONEngine_Evaluate(b *testing.B) {
	engine := NewJSONEngine()
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "benchmark-json",
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
		Effect: models.PolicyEffectAllow,
	}

	input := &EvaluationInput{
		Subject: map[string]interface{}{
			"role": "admin",
		},
		Resource: map[string]interface{}{
			"type": "document",
		},
		Action: "read",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := engine.Evaluate(ctx, policy, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Additional comprehensive tests

func TestOPAEngine_TestPolicy(t *testing.T) {
	engine := NewOPAEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		input         *EvaluationInput
		expectAllow   bool
		wantErr       bool
		checkDetails  bool
		checkReason   string
	}{
		{
			name: "Test valid OPA policy - allow",
			policyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
}`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Action: "read",
			},
			expectAllow:  true,
			wantErr:      false,
			checkDetails: true,
			checkReason:  "Access allowed by policy: test-policy",
		},
		{
			name: "Test valid OPA policy - deny",
			policyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
}`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Action: "read",
			},
			expectAllow:  false,
			wantErr:      false,
			checkDetails: true,
			checkReason:  "Access denied by policy: test-policy",
		},
		{
			name:          "Test with wrong language",
			policyContent: "test policy",
			language:      models.PolicyLanguageJSON,
			input:         &EvaluationInput{Action: "read"},
			wantErr:       true,
		},
		{
			name:          "Test with invalid OPA syntax",
			policyContent: `package stratium.authz\n\ninvalid syntax here {{{`,
			language:      models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Action: "read",
			},
			wantErr: true,
		},
		{
			name: "Test with policy that returns no result",
			policyContent: `package stratium.authz

# No allow rule defined - will return empty result`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Action: "read",
			},
			expectAllow: false,
			wantErr:     false,
			checkReason: "Policy did not return a result (default deny)",
		},
		{
			name: "Test with complex input including environment",
			policyContent: `package stratium.authz

default allow = false

allow {
	input.subject.role == "admin"
	input.environment.secure == true
	input.action == "manage"
}`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "server",
				},
				Environment: map[string]interface{}{
					"secure": true,
				},
				Action: "manage",
			},
			expectAllow:  true,
			wantErr:      false,
			checkDetails: true,
		},
		{
			name: "Test with policy checking resource attributes",
			policyContent: `package stratium.authz

default allow = false

allow {
	input.subject.clearance == "secret"
	input.resource.classification == "secret"
}`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"clearance": "secret",
				},
				Resource: map[string]interface{}{
					"classification": "secret",
				},
				Action: "read",
			},
			expectAllow:  true,
			wantErr:      false,
			checkDetails: true,
		},
		{
			name: "Test with policy using explicit false",
			policyContent: `package stratium.authz

default allow = true

allow = false {
	input.subject.status == "blocked"
}`,
			language: models.PolicyLanguageOPA,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"status": "blocked",
				},
				Action: "read",
			},
			expectAllow: false,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.TestPolicy(ctx, tt.policyContent, tt.language, tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}

			if result.PolicyName != "test-policy" {
				t.Errorf("Expected policy name 'test-policy', got '%s'", result.PolicyName)
			}

			if tt.checkReason != "" && result.Reason != tt.checkReason {
				t.Errorf("Expected reason '%s', got '%s'", tt.checkReason, result.Reason)
			}

			if tt.checkDetails {
				if result.Details == nil {
					t.Error("Expected non-nil details")
				}
				if _, hasExpressions := result.Details["expressions"]; !hasExpressions {
					t.Error("Expected details to contain 'expressions'")
				}
				if _, hasBindings := result.Details["bindings"]; !hasBindings {
					t.Error("Expected details to contain 'bindings'")
				}
			}
		})
	}
}

func TestXACMLEngine_TestPolicy(t *testing.T) {
	engine := NewXACMLEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		input         *EvaluationInput
		wantErr       bool
	}{
		{
			name: "Test valid XACML policy",
			policyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy"
        Version="1.0">
    <Rule RuleId="allow-admin" Effect="Permit">
        <Condition>role admin</Condition>
    </Rule>
</Policy>`,
			language: models.PolicyLanguageXACML,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Action: "read",
			},
			wantErr: false,
		},
		{
			name:          "Test with wrong language",
			policyContent: "test",
			language:      models.PolicyLanguageOPA,
			input:         &EvaluationInput{Action: "read"},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.TestPolicy(ctx, tt.policyContent, tt.language, tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result == nil {
				t.Error("Expected non-nil result")
			}
		})
	}
}

func TestJSONEngine_TestPolicy(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		input         *EvaluationInput
		expectAllow   bool
		wantErr       bool
	}{
		{
			name: "Test valid JSON policy - allow",
			policyContent: `{
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
			language: models.PolicyLanguageJSON,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Action: "read",
			},
			expectAllow: true,
			wantErr:     false,
		},
		{
			name: "Test valid JSON policy - deny",
			policyContent: `{
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
			language: models.PolicyLanguageJSON,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Action: "read",
			},
			expectAllow: false,
			wantErr:     false,
		},
		{
			name:          "Test with wrong language",
			policyContent: "{}",
			language:      models.PolicyLanguageXACML,
			input:         &EvaluationInput{Action: "read"},
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.TestPolicy(ctx, tt.policyContent, tt.language, tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v", tt.expectAllow, result.Allow)
			}
		})
	}
}

func TestJSONEngine_AdditionalOperators(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
	}{
		{
			name: "Operator - $ne (not equal)",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "deny-blocked-users",
						"effect": "allow",
						"conditions": {
							"subject": {
								"status": {
									"$ne": "blocked"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"status": "active",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $nin (not in array)",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-non-restricted-roles",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": {
									"$nin": ["blocked", "suspended", "banned"]
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $startsWith",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-admin-prefix",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": {
									"$startsWith": "admin"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin-super",
				},
				Action: "manage",
			},
			expectAllow: true,
		},
		{
			name: "Operator - $endsWith",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-company-emails",
						"effect": "allow",
						"conditions": {
							"subject": {
								"email": {
									"$endsWith": "@company.com"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"email": "user@company.com",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Multiple action array",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-multiple-actions",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": ["read", "list", "view"]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Action: "view",
			},
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-operators",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}

func TestJSONEngine_EnvironmentAttributes(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
	}{
		{
			name: "Environment - time of day",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "business-hours-only",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"environment": {
								"time_of_day": "business_hours"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Environment: map[string]interface{}{
					"time_of_day": "business_hours",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Environment - IP address check",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "internal-ip-only",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"environment": {
								"ip_address": {
									"$startsWith": "192.168"
								}
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Environment: map[string]interface{}{
					"ip_address": "192.168.1.100",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Environment - multiple conditions",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "secure-access",
						"effect": "allow",
						"conditions": {
							"allOf": [
								{
									"subject": {
										"role": "admin"
									}
								},
								{
									"environment": {
										"secure_connection": true,
										"mfa_enabled": true
									}
								}
							]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Environment: map[string]interface{}{
					"secure_connection": true,
					"mfa_enabled":       true,
				},
				Action: "manage",
			},
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-environment",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}

func TestJSONEngine_ResourceAttributes(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
	}{
		{
			name: "Resource type matching",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "allow-document-access",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"resource": {
								"type": "document"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
		},
		{
			name: "Resource ownership check",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "owner-can-delete",
						"effect": "allow",
						"conditions": {
							"resource": {
								"owner": "user123"
							},
							"subject": {
								"id": "user123"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"id": "user123",
				},
				Resource: map[string]interface{}{
					"owner": "user123",
				},
				Action: "delete",
			},
			expectAllow: true,
		},
		{
			name: "Resource classification",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "secret-clearance-required",
						"effect": "allow",
						"conditions": {
							"subject": {
								"clearance": {
									"$in": ["secret", "top-secret"]
								}
							},
							"resource": {
								"classification": "secret"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"clearance": "secret",
				},
				Resource: map[string]interface{}{
					"classification": "secret",
				},
				Action: "read",
			},
			expectAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-resource",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("Expected allow=%v, got allow=%v. Reason: %s",
					tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}

func TestEngines_ErrorCases(t *testing.T) {
	ctx := context.Background()

	t.Run("OPA - wrong language for policy", func(t *testing.T) {
		engine := NewOPAEngine()
		policy := &models.Policy{
			Name:          "wrong-lang",
			Language:      models.PolicyLanguageJSON,
			PolicyContent: `{"test": "data"}`,
		}
		input := &EvaluationInput{Action: "read"}

		_, err := engine.Evaluate(ctx, policy, input)
		if err == nil {
			t.Error("Expected error for wrong language")
		}
	})

	t.Run("XACML - wrong language for policy", func(t *testing.T) {
		engine := NewXACMLEngine()
		policy := &models.Policy{
			Name:          "wrong-lang",
			Language:      models.PolicyLanguageOPA,
			PolicyContent: `package test`,
		}
		input := &EvaluationInput{Action: "read"}

		_, err := engine.Evaluate(ctx, policy, input)
		if err == nil {
			t.Error("Expected error for wrong language")
		}
	})

	t.Run("JSON - wrong language for policy", func(t *testing.T) {
		engine := NewJSONEngine()
		policy := &models.Policy{
			Name:          "wrong-lang",
			Language:      models.PolicyLanguageXACML,
			PolicyContent: `<Policy></Policy>`,
		}
		input := &EvaluationInput{Action: "read"}

		_, err := engine.Evaluate(ctx, policy, input)
		if err == nil {
			t.Error("Expected error for wrong language")
		}
	})

	t.Run("JSON - invalid policy content", func(t *testing.T) {
		engine := NewJSONEngine()
		policy := &models.Policy{
			Name:          "invalid",
			Language:      models.PolicyLanguageJSON,
			PolicyContent: `{invalid json}`,
		}
		input := &EvaluationInput{Action: "read"}

		_, err := engine.Evaluate(ctx, policy, input)
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})

	t.Run("XACML - invalid XML", func(t *testing.T) {
		engine := NewXACMLEngine()
		policy := &models.Policy{
			Name:          "invalid",
			Language:      models.PolicyLanguageXACML,
			PolicyContent: `<Policy><Invalid>`,
		}
		input := &EvaluationInput{Action: "read"}

		_, err := engine.Evaluate(ctx, policy, input)
		if err == nil {
			t.Error("Expected error for invalid XML")
		}
	})
}

func TestXACMLEngine_RuleValidation(t *testing.T) {
	engine := NewXACMLEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		wantErr       bool
		errContains   string
	}{
		{
			name: "Missing RuleId",
			policyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy">
    <Rule Effect="Permit"></Rule>
</Policy>`,
			wantErr:     true,
			errContains: "RuleId",
		},
		{
			name: "Invalid Effect value",
			policyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy">
    <Rule RuleId="test-rule" Effect="Invalid"></Rule>
</Policy>`,
			wantErr:     true,
			errContains: "Effect",
		},
		{
			name: "No rules",
			policyContent: `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test-policy">
</Policy>`,
			wantErr:     true,
			errContains: "at least one Rule",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, models.PolicyLanguageXACML)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestJSONEngine_RuleValidation(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		wantErr       bool
		errContains   string
	}{
		{
			name: "Missing rule ID",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"effect": "allow",
						"conditions": {}
					}
				]
			}`,
			wantErr:     true,
			errContains: "id",
		},
		{
			name: "Multiple rules - one invalid",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "rule1",
						"effect": "allow",
						"conditions": {}
					},
					{
						"id": "rule2",
						"effect": "invalid",
						"conditions": {}
					}
				]
			}`,
			wantErr:     true,
			errContains: "effect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, models.PolicyLanguageJSON)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Expected error to contain %q, got %q", tt.errContains, err.Error())
				}
			} else if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// Specific tests for resource and action matching logic (lines 171-182 in json_engine.go)

func TestJSONEngine_ResourceMatching_Specific(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
		description   string
	}{
		{
			name: "Empty resource conditions - should match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "no-resource-check",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
					"id":   "123",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "When len(conditions.Resource) == 0, resource check is skipped",
		},
		{
			name: "Non-empty resource conditions - exact match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "resource-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"resource": {
								"type": "document",
								"status": "published"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type":   "document",
					"status": "published",
					"id":     "456",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "When len(conditions.Resource) > 0 and matchAttributes returns true",
		},
		{
			name: "Non-empty resource conditions - no match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "resource-no-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"resource": {
								"type": "document",
								"status": "published"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type":   "document",
					"status": "draft",
				},
				Action: "read",
			},
			expectAllow: false,
			description: "When len(conditions.Resource) > 0 and matchAttributes returns false, matched = false",
		},
		{
			name: "Resource missing required attribute",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "resource-missing-attr",
						"effect": "allow",
						"conditions": {
							"resource": {
								"classification": "secret"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: false,
			description: "When resource is missing required attributes, matchAttributes returns false",
		},
		{
			name: "Multiple resource attributes - all must match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "multi-resource-attrs",
						"effect": "allow",
						"conditions": {
							"resource": {
								"type": "document",
								"department": "engineering",
								"classification": "internal"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type":           "document",
					"department":     "engineering",
					"classification": "internal",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "All resource attributes must match for matchAttributes to return true",
		},
		{
			name: "Multiple resource attributes - one mismatch",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "multi-resource-one-mismatch",
						"effect": "allow",
						"conditions": {
							"resource": {
								"type": "document",
								"department": "engineering",
								"classification": "internal"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type":           "document",
					"department":     "sales",
					"classification": "internal",
				},
				Action: "read",
			},
			expectAllow: false,
			description: "If any resource attribute doesn't match, matchAttributes returns false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-resource-matching",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("%s: Expected allow=%v, got allow=%v. Reason: %s",
					tt.description, tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}

func TestJSONEngine_ActionMatching_Specific(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
		description   string
	}{
		{
			name: "Nil action condition - should match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "no-action-check",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "When conditions.Action == nil, action check is skipped",
		},
		{
			name: "Non-nil action - exact string match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-exact-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": "read"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "When conditions.Action != nil and matchAction returns true",
		},
		{
			name: "Non-nil action - no match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-no-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": "write"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: false,
			description: "When conditions.Action != nil and matchAction returns false, matched = false",
		},
		{
			name: "Action wildcard - matches any",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-wildcard",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "admin"
							},
							"action": "*"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "delete",
			},
			expectAllow: true,
			description: "Wildcard action '*' matches any action",
		},
		{
			name: "Action array - matches one of many",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-array",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": ["read", "list", "view"]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "list",
			},
			expectAllow: true,
			description: "Action array matches if provided action is in the array",
		},
		{
			name: "Action array - no match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-array-no-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": ["read", "list", "view"]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "delete",
			},
			expectAllow: false,
			description: "Action array doesn't match if provided action is not in the array",
		},
		{
			name: "Action with operator - $eq",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-operator",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "user"
							},
							"action": {
								"$eq": "read"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "user",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "Action with $eq operator uses matchValue logic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-action-matching",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("%s: Expected allow=%v, got allow=%v. Reason: %s",
					tt.description, tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}

func TestJSONEngine_ResourceAndAction_Combined(t *testing.T) {
	engine := NewJSONEngine()
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		input         *EvaluationInput
		expectAllow   bool
		description   string
	}{
		{
			name: "Both resource and action match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "both-match",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "editor"
							},
							"resource": {
								"type": "document",
								"status": "draft"
							},
							"action": "edit"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "editor",
				},
				Resource: map[string]interface{}{
					"type":   "document",
					"status": "draft",
				},
				Action: "edit",
			},
			expectAllow: true,
			description: "Both resource and action conditions match",
		},
		{
			name: "Resource matches but action doesn't",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "resource-ok-action-fail",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "editor"
							},
							"resource": {
								"type": "document"
							},
							"action": "delete"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "editor",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "edit",
			},
			expectAllow: false,
			description: "Resource matches but action doesn't - matched set to false",
		},
		{
			name: "Action matches but resource doesn't",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "action-ok-resource-fail",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "editor"
							},
							"resource": {
								"type": "document",
								"status": "published"
							},
							"action": "edit"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "editor",
				},
				Resource: map[string]interface{}{
					"type":   "document",
					"status": "draft",
				},
				Action: "edit",
			},
			expectAllow: false,
			description: "Action matches but resource doesn't - matched set to false",
		},
		{
			name: "Neither resource nor action match",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "both-fail",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "editor"
							},
							"resource": {
								"type": "image"
							},
							"action": "delete"
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "editor",
				},
				Resource: map[string]interface{}{
					"type": "document",
				},
				Action: "edit",
			},
			expectAllow: false,
			description: "Neither resource nor action match - matched set to false",
		},
		{
			name: "Empty resource, nil action - both pass",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "subject-only",
						"effect": "allow",
						"conditions": {
							"subject": {
								"role": "admin"
							}
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"role": "admin",
				},
				Resource: map[string]interface{}{
					"type": "anything",
				},
				Action: "anything",
			},
			expectAllow: true,
			description: "When both resource and action conditions are absent, checks are skipped",
		},
		{
			name: "Complex: resource with operators, action array",
			policyContent: `{
				"version": "1.0",
				"rules": [
					{
						"id": "complex-conditions",
						"effect": "allow",
						"conditions": {
							"subject": {
								"clearance": {
									"$in": ["secret", "top-secret"]
								}
							},
							"resource": {
								"classification": {
									"$ne": "public"
								},
								"department": "engineering"
							},
							"action": ["read", "view", "list"]
						}
					}
				]
			}`,
			input: &EvaluationInput{
				Subject: map[string]interface{}{
					"clearance": "secret",
				},
				Resource: map[string]interface{}{
					"classification": "confidential",
					"department":     "engineering",
				},
				Action: "read",
			},
			expectAllow: true,
			description: "Complex conditions with operators and arrays all match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &models.Policy{
				Name:          "test-combined",
				Language:      models.PolicyLanguageJSON,
				PolicyContent: tt.policyContent,
			}

			result, err := engine.Evaluate(ctx, policy, tt.input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}

			if result.Allow != tt.expectAllow {
				t.Errorf("%s: Expected allow=%v, got allow=%v. Reason: %s",
					tt.description, tt.expectAllow, result.Allow, result.Reason)
			}
		})
	}
}
