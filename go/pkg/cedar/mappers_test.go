package cedar

import (
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func TestMapSubjectToEntity(t *testing.T) {
	uid, attrs := MapSubjectToEntity("Acme", map[string]interface{}{
		"sub":   "alice",
		"email": "alice@acme.com",
		"role":  "admin",
	})

	expectedType := types.EntityType("Acme::User")
	if uid.Type != expectedType {
		t.Errorf("expected type %v, got %v", expectedType, uid.Type)
	}

	// Should use "sub" as the entity ID (first priority key)
	expectedUID := cedarlib.NewEntityUID(expectedType, cedarlib.String("alice"))
	if uid != expectedUID {
		t.Errorf("expected UID %v, got %v", expectedUID, uid)
	}

	// Should have attributes
	if len(attrs) == 0 {
		t.Error("expected non-empty attributes")
	}
}

func TestMapSubjectToEntity_FallbackID(t *testing.T) {
	uid, _ := MapSubjectToEntity("Acme", map[string]interface{}{
		"email": "bob@acme.com",
	})

	// Should fall back to "email" since "sub" and "id" are missing
	expectedUID := cedarlib.NewEntityUID(types.EntityType("Acme::User"), cedarlib.String("bob@acme.com"))
	if uid != expectedUID {
		t.Errorf("expected UID with email, got %v", uid)
	}
}

func TestMapSubjectToEntity_UnknownFallback(t *testing.T) {
	uid, _ := MapSubjectToEntity("Acme", map[string]interface{}{
		"custom_field": "value",
	})

	expectedUID := cedarlib.NewEntityUID(types.EntityType("Acme::User"), cedarlib.String("unknown"))
	if uid != expectedUID {
		t.Errorf("expected UID with 'unknown', got %v", uid)
	}
}

func TestMapResourceToEntity(t *testing.T) {
	uid, attrs := MapResourceToEntity("Acme", map[string]interface{}{
		"id":             "doc-123",
		"classification": "SECRET",
	})

	expectedType := types.EntityType("Acme::Resource")
	if uid.Type != expectedType {
		t.Errorf("expected type %v, got %v", expectedType, uid.Type)
	}

	expectedUID := cedarlib.NewEntityUID(expectedType, cedarlib.String("doc-123"))
	if uid != expectedUID {
		t.Errorf("expected UID %v, got %v", expectedUID, uid)
	}

	if len(attrs) != 2 {
		t.Errorf("expected 2 attributes, got %d", len(attrs))
	}
}

func TestMapActionToEntityUID(t *testing.T) {
	uid := MapActionToEntityUID("Stratium", "UnwrapDEK")

	expected := cedarlib.NewEntityUID(types.EntityType("Stratium::Action"), cedarlib.String("UnwrapDEK"))
	if uid != expected {
		t.Errorf("expected %v, got %v", expected, uid)
	}
}

func TestMapContextToRecord(t *testing.T) {
	record := MapContextToRecord(map[string]interface{}{
		"mfa_verified": true,
		"ip_address":   "10.0.0.1",
	})

	// Should be a valid Cedar Record
	if record.Len() != 2 {
		t.Errorf("expected 2 context entries, got %d", record.Len())
	}
}

func TestMapContextToRecord_Empty(t *testing.T) {
	record := MapContextToRecord(nil)
	if record.Len() != 0 {
		t.Errorf("expected empty record, got %d entries", record.Len())
	}
}

func TestToTypedValue_Types(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{"string", "hello"},
		{"bool", true},
		{"int", 42},
		{"int64", int64(100)},
		{"float64 whole", float64(3)},
		{"float64 decimal", 3.14},
		{"nil", nil},
		{"slice", []interface{}{"a", "b"}},
		{"map", map[string]interface{}{"key": "val"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toTypedValue(tt.input)
			if result == nil {
				t.Error("expected non-nil result")
			}
		})
	}
}
