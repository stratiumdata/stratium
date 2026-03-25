package pap

import (
	"strings"
	"testing"

	"stratium/pkg/models"
)

// TestValidatePolicyLanguage covers all valid languages and invalid inputs.
func TestValidatePolicyLanguage(t *testing.T) {
	tests := []struct {
		name     string
		language models.PolicyLanguage
		wantErr  bool
	}{
		{"xacml", models.PolicyLanguageXACML, false},
		{"opa", models.PolicyLanguageOPA, false},
		{"json", models.PolicyLanguageJSON, false},
		{"empty", models.PolicyLanguage(""), true},
		{"unknown", models.PolicyLanguage("rego"), true},
		{"sql", models.PolicyLanguage("sql"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyLanguage(tt.language)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyLanguage(%q) error = %v, wantErr %v", tt.language, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePolicyEffect covers allow, deny, and invalid values.
func TestValidatePolicyEffect(t *testing.T) {
	tests := []struct {
		name    string
		effect  models.PolicyEffect
		wantErr bool
	}{
		{"allow", models.PolicyEffectAllow, false},
		{"deny", models.PolicyEffectDeny, false},
		{"empty", models.PolicyEffect(""), true},
		{"unknown", models.PolicyEffect("permit"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyEffect(tt.effect)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyEffect(%q) error = %v, wantErr %v", tt.effect, err, tt.wantErr)
			}
		})
	}
}

// TestValidateRequiredString covers whitespace and empty inputs.
func TestValidateRequiredString(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		wantErr bool
	}{
		{"valid value", "name", "hello", false},
		{"empty string", "name", "", true},
		{"whitespace only", "name", "   ", true},
		{"tab only", "name", "\t", true},
		{"single char", "name", "x", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequiredString(tt.field, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequiredString(%q, %q) error = %v, wantErr %v", tt.field, tt.value, err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tt.field) {
				t.Errorf("error should mention field name %q, got: %v", tt.field, err)
			}
		})
	}
}

// TestValidateRequiredAttributes covers empty and populated maps.
func TestValidateRequiredAttributes(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		attrs   map[string]interface{}
		wantErr bool
	}{
		{"nil map", "subject_attributes", nil, true},
		{"empty map", "subject_attributes", map[string]interface{}{}, true},
		{"one entry", "subject_attributes", map[string]interface{}{"role": "admin"}, false},
		{"multiple entries", "resource_attributes", map[string]interface{}{"type": "doc", "class": "secret"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRequiredAttributes(tt.field, tt.attrs)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequiredAttributes(%q) error = %v, wantErr %v", tt.field, err, tt.wantErr)
			}
		})
	}
}

// TestValidateCreatePolicyRequest exercises full validation chain.
func TestValidateCreatePolicyRequest(t *testing.T) {
	base := &models.CreatePolicyRequest{
		Name:          "test-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: "package test\nallow { true }",
		Effect:        models.PolicyEffectAllow,
	}

	tests := []struct {
		name    string
		mutate  func(*models.CreatePolicyRequest)
		wantErr bool
	}{
		{"valid request", func(r *models.CreatePolicyRequest) {}, false},
		{"empty name", func(r *models.CreatePolicyRequest) { r.Name = "" }, true},
		{"whitespace name", func(r *models.CreatePolicyRequest) { r.Name = "  " }, true},
		{"invalid language", func(r *models.CreatePolicyRequest) { r.Language = "graphql" }, true},
		{"empty content", func(r *models.CreatePolicyRequest) { r.PolicyContent = "" }, true},
		{"invalid effect", func(r *models.CreatePolicyRequest) { r.Effect = "grant" }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := *base
			tt.mutate(&req)
			err := validateCreatePolicyRequest(&req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCreatePolicyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateUpdatePolicyRequest covers nil-field (partial update) semantics.
func TestValidateUpdatePolicyRequest(t *testing.T) {
	validName := "new-name"
	validLang := models.PolicyLanguageJSON
	validContent := "{ \"allow\": true }"
	validEffect := models.PolicyEffectDeny
	badLang := models.PolicyLanguage("bad")
	emptyStr := ""

	tests := []struct {
		name    string
		req     *models.UpdatePolicyRequest
		wantErr bool
	}{
		{"empty update (all nil)", &models.UpdatePolicyRequest{}, false},
		{"valid name update", &models.UpdatePolicyRequest{Name: &validName}, false},
		{"empty name update", &models.UpdatePolicyRequest{Name: &emptyStr}, true},
		{"valid language update", &models.UpdatePolicyRequest{Language: &validLang}, false},
		{"invalid language update", &models.UpdatePolicyRequest{Language: &badLang}, true},
		{"valid content update", &models.UpdatePolicyRequest{PolicyContent: &validContent}, false},
		{"empty content update", &models.UpdatePolicyRequest{PolicyContent: &emptyStr}, true},
		{"valid effect update", &models.UpdatePolicyRequest{Effect: &validEffect}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUpdatePolicyRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUpdatePolicyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePolicyCheckRequest covers language and content validation.
func TestValidatePolicyCheckRequest(t *testing.T) {
	tests := []struct {
		name     string
		language models.PolicyLanguage
		content  string
		wantErr  bool
	}{
		{"valid", models.PolicyLanguageOPA, "package x", false},
		{"bad language", models.PolicyLanguage("lua"), "package x", true},
		{"empty content", models.PolicyLanguageOPA, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyCheckRequest(tt.language, tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyCheckRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidatePolicyTestRequest verifies all five fields are checked.
func TestValidatePolicyTestRequest(t *testing.T) {
	validAttrs := map[string]interface{}{"role": "admin"}
	emptyAttrs := map[string]interface{}{}

	tests := []struct {
		name               string
		language           models.PolicyLanguage
		content            string
		subjectAttributes  map[string]interface{}
		resourceAttributes map[string]interface{}
		action             string
		wantErr            bool
	}{
		{"valid", models.PolicyLanguageOPA, "pkg", validAttrs, validAttrs, "read", false},
		{"bad language", models.PolicyLanguage("bad"), "pkg", validAttrs, validAttrs, "read", true},
		{"empty content", models.PolicyLanguageOPA, "", validAttrs, validAttrs, "read", true},
		{"empty subject", models.PolicyLanguageOPA, "pkg", emptyAttrs, validAttrs, "read", true},
		{"nil subject", models.PolicyLanguageOPA, "pkg", nil, validAttrs, "read", true},
		{"empty resource", models.PolicyLanguageOPA, "pkg", validAttrs, emptyAttrs, "read", true},
		{"empty action", models.PolicyLanguageOPA, "pkg", validAttrs, validAttrs, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePolicyTestRequest(tt.language, tt.content, tt.subjectAttributes, tt.resourceAttributes, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePolicyTestRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateEntitlementMatchRequest covers subject_attributes and action.
func TestValidateEntitlementMatchRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *models.EntitlementMatchRequest
		wantErr bool
	}{
		{
			"valid",
			&models.EntitlementMatchRequest{
				SubjectAttributes: map[string]interface{}{"role": "admin"},
				Action:            "read",
			},
			false,
		},
		{
			"empty subject attributes",
			&models.EntitlementMatchRequest{
				SubjectAttributes: map[string]interface{}{},
				Action:            "read",
			},
			true,
		},
		{
			"nil subject attributes",
			&models.EntitlementMatchRequest{
				SubjectAttributes: nil,
				Action:            "read",
			},
			true,
		},
		{
			"empty action",
			&models.EntitlementMatchRequest{
				SubjectAttributes: map[string]interface{}{"role": "admin"},
				Action:            "",
			},
			true,
		},
		{
			"whitespace action",
			&models.EntitlementMatchRequest{
				SubjectAttributes: map[string]interface{}{"role": "admin"},
				Action:            "   ",
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEntitlementMatchRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateEntitlementMatchRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
