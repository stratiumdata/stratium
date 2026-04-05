package policy_engine

import (
	"context"
	"testing"

	"stratium/pkg/models"
)

func TestCedarEngine_ValidatePolicy(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	tests := []struct {
		name          string
		policyContent string
		language      models.PolicyLanguage
		wantErr       bool
	}{
		{
			name: "Valid permit policy",
			policyContent: `permit(
				principal,
				action,
				resource
			);`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
		{
			name: "Valid forbid policy",
			policyContent: `forbid(
				principal,
				action,
				resource
			);`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
		{
			name: "Valid policy with when clause",
			policyContent: `permit(
				principal,
				action == Stratium::Action::"UnwrapDEK",
				resource
			) when {
				context.mfa_verified == true
			};`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
		{
			name: "Valid policy with unless clause",
			policyContent: `forbid(
				principal,
				action,
				resource
			) unless {
				context.mfa_verified == true
			};`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
		{
			name:          "Invalid Cedar syntax",
			policyContent: `this is not cedar syntax`,
			language:      models.PolicyLanguageCedar,
			wantErr:       true,
		},
		{
			name:          "Empty policy content",
			policyContent: "",
			language:      models.PolicyLanguageCedar,
			wantErr:       true,
		},
		{
			name:          "Wrong language",
			policyContent: `permit(principal, action, resource);`,
			language:      models.PolicyLanguageOPA,
			wantErr:       true,
		},
		{
			name: "Multiple policies in one document",
			policyContent: `permit(
				principal == Stratium::User::"alice",
				action,
				resource
			);

			forbid(
				principal,
				action == Stratium::Action::"DeletePolicy",
				resource
			);`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
		{
			name: "Policy with annotations",
			policyContent: `@id("policy-123")
			permit(
				principal,
				action,
				resource
			);`,
			language: models.PolicyLanguageCedar,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.ValidatePolicy(ctx, tt.policyContent, tt.language)
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCedarEngine_Evaluate_BasicPermit(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "allow-all",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal,
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allow {
		t.Error("expected Allow for permit-all policy")
	}

	if result.PolicyName != "allow-all" {
		t.Errorf("expected policy name 'allow-all', got '%s'", result.PolicyName)
	}
}

func TestCedarEngine_Evaluate_BasicForbid(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "deny-all",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `forbid(
			principal,
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allow {
		t.Error("expected Deny for forbid-all policy")
	}
}

func TestCedarEngine_Evaluate_ForbidOverridesPermit(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	// Cedar's evaluation: any forbid overrides all permits (deny takes precedence)
	policy := &models.Policy{
		Name:     "mixed-policies",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal,
			action,
			resource
		);

		forbid(
			principal,
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allow {
		t.Error("expected Deny when forbid overrides permit")
	}
}

func TestCedarEngine_Evaluate_DefaultDeny(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	// Policy that matches only Alice, evaluated for Bob → default deny
	policy := &models.Policy{
		Name:     "alice-only",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal == Stratium::User::"alice",
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "bob"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Allow {
		t.Error("expected Deny for non-matching principal (default deny)")
	}
}

func TestCedarEngine_Evaluate_SpecificPrincipalMatch(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "alice-only",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal == Stratium::User::"alice",
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allow {
		t.Error("expected Allow for matching principal 'alice'")
	}
}

func TestCedarEngine_Evaluate_ActionMatch(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "read-only",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal,
			action == Stratium::Action::"read",
			resource
		);`,
	}

	tests := []struct {
		name    string
		action  string
		allowed bool
	}{
		{"read action allowed", "read", true},
		{"write action denied", "write", false},
		{"delete action denied", "delete", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &EvaluationInput{
				Subject:     map[string]interface{}{"sub": "alice"},
				Resource:    map[string]interface{}{"id": "doc-1"},
				Action:      tt.action,
				Environment: map[string]interface{}{},
			}

			result, err := engine.Evaluate(ctx, policy, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allow != tt.allowed {
				t.Errorf("expected Allow=%v for action '%s', got Allow=%v", tt.allowed, tt.action, result.Allow)
			}
		})
	}
}

func TestCedarEngine_Evaluate_ContextCondition(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	// Policy requires MFA
	policy := &models.Policy{
		Name:     "require-mfa",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal,
			action,
			resource
		) when {
			context.mfa_verified == true
		};`,
	}

	tests := []struct {
		name    string
		env     map[string]interface{}
		allowed bool
	}{
		{
			"MFA verified allows access",
			map[string]interface{}{"mfa_verified": true},
			true,
		},
		{
			"MFA not verified denies access",
			map[string]interface{}{"mfa_verified": false},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &EvaluationInput{
				Subject:     map[string]interface{}{"sub": "alice"},
				Resource:    map[string]interface{}{"id": "doc-1"},
				Action:      "read",
				Environment: tt.env,
			}

			result, err := engine.Evaluate(ctx, policy, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allow != tt.allowed {
				t.Errorf("expected Allow=%v, got Allow=%v (reason: %s)", tt.allowed, result.Allow, result.Reason)
			}
		})
	}
}

func TestCedarEngine_Evaluate_RoleBasedAccess(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	// Policy: only admins can delete
	policy := &models.Policy{
		Name:     "admin-delete",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal in Stratium::Role::"admin",
			action == Stratium::Action::"delete",
			resource
		);`,
	}

	tests := []struct {
		name    string
		roles   []interface{}
		allowed bool
	}{
		{
			"admin can delete",
			[]interface{}{"admin"},
			true,
		},
		{
			"viewer cannot delete",
			[]interface{}{"viewer"},
			false,
		},
		{
			"no roles cannot delete",
			nil,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subject := map[string]interface{}{"sub": "alice"}
			if tt.roles != nil {
				subject["roles"] = tt.roles
			}

			input := &EvaluationInput{
				Subject:     subject,
				Resource:    map[string]interface{}{"id": "doc-1"},
				Action:      "delete",
				Environment: map[string]interface{}{},
			}

			result, err := engine.Evaluate(ctx, policy, input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Allow != tt.allowed {
				t.Errorf("expected Allow=%v for roles %v, got Allow=%v (reason: %s)", tt.allowed, tt.roles, result.Allow, result.Reason)
			}
		})
	}
}

func TestCedarEngine_Evaluate_WrongLanguage(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:          "opa-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: `package test`,
	}

	input := &EvaluationInput{
		Subject:  map[string]interface{}{"sub": "alice"},
		Resource: map[string]interface{}{"id": "doc-1"},
		Action:   "read",
	}

	_, err := engine.Evaluate(ctx, policy, input)
	if err == nil {
		t.Error("expected error for wrong language")
	}
}

func TestCedarEngine_Evaluate_InvalidPolicyContent(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:          "bad-policy",
		Language:      models.PolicyLanguageCedar,
		PolicyContent: `this is not valid cedar`,
	}

	input := &EvaluationInput{
		Subject:  map[string]interface{}{"sub": "alice"},
		Resource: map[string]interface{}{"id": "doc-1"},
		Action:   "read",
	}

	_, err := engine.Evaluate(ctx, policy, input)
	if err == nil {
		t.Error("expected error for invalid Cedar policy content")
	}
}

func TestCedarEngine_TestPolicy(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policyContent := `permit(principal, action, resource);`

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.TestPolicy(ctx, policyContent, models.PolicyLanguageCedar, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.Allow {
		t.Error("expected Allow for permit-all test policy")
	}
}

func TestCedarEngine_Evaluate_DiagnosticDetails(t *testing.T) {
	engine := NewCedarEngine("Stratium")
	ctx := context.Background()

	policy := &models.Policy{
		Name:     "test-details",
		Language: models.PolicyLanguageCedar,
		PolicyContent: `permit(
			principal,
			action,
			resource
		);`,
	}

	input := &EvaluationInput{
		Subject:     map[string]interface{}{"sub": "alice"},
		Resource:    map[string]interface{}{"id": "doc-1"},
		Action:      "read",
		Environment: map[string]interface{}{},
	}

	result, err := engine.Evaluate(ctx, policy, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have determining_policies in details
	if _, ok := result.Details["determining_policies"]; !ok {
		t.Error("expected 'determining_policies' in result details")
	}

	if result.Reason == "" {
		t.Error("expected non-empty reason")
	}
}

func TestEngineFactory_GetCedarEngine(t *testing.T) {
	factory := NewEngineFactory()

	engine, err := factory.GetEngine(models.PolicyLanguageCedar)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if engine == nil {
		t.Fatal("expected non-nil Cedar engine")
	}

	// Verify it's actually a CedarEngine
	if _, ok := engine.(*CedarEngine); !ok {
		t.Error("expected engine to be *CedarEngine")
	}
}
