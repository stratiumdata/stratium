package cedar

import (
	"testing"
)

func TestNamespaceManager_ValidateNamespace(t *testing.T) {
	mgr := NewNamespaceManager("Stratium")

	tests := []struct {
		name      string
		namespace string
		wantErr   bool
	}{
		{"valid simple", "Acme", false},
		{"valid with underscore", "Acme_Corp", false},
		{"valid with digits", "Tenant42", false},
		{"empty", "", true},
		{"starts with digit", "42Corp", true},
		{"has spaces", "Acme Corp", true},
		{"has hyphens", "Acme-Corp", true},
		{"reserved cedar", "foo__cedar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.ValidateNamespace(tt.namespace)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for namespace %q", tt.namespace)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for namespace %q: %v", tt.namespace, err)
			}
		})
	}
}

func TestNamespaceManager_QualifyEntityType(t *testing.T) {
	mgr := NewNamespaceManager("Stratium")

	tests := []struct {
		namespace  string
		entityType string
		expected   string
	}{
		{"Acme", "User", "Acme::User"},
		{"Acme", "Classification", "Acme::Classification"},
		{"", "User", "Stratium::User"}, // falls back to default
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := mgr.QualifyEntityType(tt.namespace, tt.entityType)
			if string(result) != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestNamespaceManager_ExtractNamespace(t *testing.T) {
	mgr := NewNamespaceManager("Stratium")

	tests := []struct {
		input     string
		wantNS    string
		wantType  string
	}{
		{"Acme::User", "Acme", "User"},
		{"Stratium::Classification", "Stratium", "Classification"},
		{"User", "Stratium", "User"}, // no namespace → default
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ns, et := mgr.ExtractNamespace(tt.input)
			if ns != tt.wantNS {
				t.Errorf("namespace: expected %q, got %q", tt.wantNS, ns)
			}
			if et != tt.wantType {
				t.Errorf("entity type: expected %q, got %q", tt.wantType, et)
			}
		})
	}
}

func TestNamespaceManager_NamespaceBelongsTo(t *testing.T) {
	mgr := NewNamespaceManager("Stratium")

	if !mgr.NamespaceBelongsTo("Acme::User", "Acme") {
		t.Error("expected Acme::User to belong to Acme")
	}
	if mgr.NamespaceBelongsTo("Acme::User", "Corp") {
		t.Error("expected Acme::User NOT to belong to Corp")
	}
}

func TestNamespaceManager_DefaultNamespace(t *testing.T) {
	mgr := NewNamespaceManager("Custom")
	if mgr.DefaultNamespace() != "Custom" {
		t.Errorf("expected default namespace 'Custom', got %q", mgr.DefaultNamespace())
	}

	mgrDefault := NewNamespaceManager("")
	if mgrDefault.DefaultNamespace() != "Stratium" {
		t.Errorf("expected fallback to 'Stratium', got %q", mgrDefault.DefaultNamespace())
	}
}
