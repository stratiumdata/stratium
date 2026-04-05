package cedar

import (
	"testing"
)

func TestIsCedarPolicyRef(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   bool
	}{
		{"simple cedar ref", "cedar:abc-123", true},
		{"json cedar ref", `{"engine": "cedar", "policy_id": "abc-123"}`, true},
		{"base64 opa policy", "eyJwYWNrYWdlIjogInN0cmF0aXVtLmF1dGh6In0=", false},
		{"empty", "", false},
		{"json non-cedar", `{"engine": "opa", "policy_id": "abc"}`, false},
		{"plain text", "just some policy text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsCedarPolicyRef(tt.policy)
			if got != tt.want {
				t.Errorf("IsCedarPolicyRef(%q) = %v, want %v", tt.policy, got, tt.want)
			}
		})
	}
}

func TestParsePolicyRef_Simple(t *testing.T) {
	ref, err := ParsePolicyRef("cedar:550e8400-e29b-41d4-a716-446655440000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.Engine != "cedar" {
		t.Errorf("expected engine 'cedar', got %q", ref.Engine)
	}
	if ref.PolicyID != "550e8400-e29b-41d4-a716-446655440000" {
		t.Errorf("expected policy ID, got %q", ref.PolicyID)
	}
}

func TestParsePolicyRef_JSON(t *testing.T) {
	ref, err := ParsePolicyRef(`{"engine": "cedar", "policy_id": "abc-123", "schema_version": "1.0"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if ref.PolicyID != "abc-123" {
		t.Errorf("expected policy ID 'abc-123', got %q", ref.PolicyID)
	}
	if ref.SchemaVersion != "1.0" {
		t.Errorf("expected schema version '1.0', got %q", ref.SchemaVersion)
	}
}

func TestParsePolicyRef_EmptyID(t *testing.T) {
	_, err := ParsePolicyRef("cedar:")
	if err == nil {
		t.Error("expected error for empty policy ID")
	}
}

func TestParsePolicyRef_InvalidJSON(t *testing.T) {
	_, err := ParsePolicyRef(`{"engine": "opa", "policy_id": "abc"}`)
	if err == nil {
		t.Error("expected error for non-cedar engine")
	}
}

func TestPolicyRef_String(t *testing.T) {
	ref := &PolicyRef{Engine: "cedar", PolicyID: "abc-123"}
	if ref.String() != "cedar:abc-123" {
		t.Errorf("expected 'cedar:abc-123', got %q", ref.String())
	}
}
