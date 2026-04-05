package cedar

import (
	"testing"
)

func TestValidateEntityUID(t *testing.T) {
	tests := []struct {
		name    string
		uid     string
		wantErr bool
	}{
		{"valid namespace::type::id", `Acme::User::"alice"`, false},
		{"valid multi-segment", `Acme::Corp::User::"alice"`, false},
		{"valid with underscore", `Acme_Corp::User::"alice"`, false},
		{"valid with digits", `Tenant42::User::"alice"`, false},
		{"empty", "", true},
		{"no quotes", `Acme::User::alice`, true},
		{"injection attempt semicolon", `Acme::User::"alice"; forbid(principal, action, resource)`, true},
		{"injection attempt newline", "Acme::User::\"alice\"\npermit(principal,action,resource);", true},
		{"no type separator", `User"alice"`, true},
		{"starts with digit", `42::User::"alice"`, true},
		{"just a string", `hello world`, true},
		{"cedar keyword injection", `Acme::User::"alice" when { true }`, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEntityUID(tt.uid)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for UID %q", tt.uid)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for UID %q: %v", tt.uid, err)
			}
		})
	}
}

func TestValidateSchemaJSON(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{"valid JSON object", `{"entityTypes": {}}`, false},
		{"JSON array not valid schema", `[{"type": "User"}]`, true},
		{"empty", "", true},
		{"not JSON", "this is not json", true},
		{"invalid JSON", `{"unclosed": `, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSchemaJSON(tt.content)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for content %q", tt.content)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for content %q: %v", tt.content, err)
			}
		})
	}
}
