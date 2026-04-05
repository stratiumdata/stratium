package cedar

import (
	"context"
	"testing"

	"stratium/pkg/models"
)

func TestSchemaManager_CreateSchema(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	req := &models.CreateCedarSchemaRequest{
		Namespace:     "Acme",
		Name:          "main",
		Description:   "Main Acme schema",
		SchemaContent: `{"entityTypes": {}}`,
		SchemaFormat:  "json",
		Version:       "1.0",
	}

	schema, err := mgr.CreateSchema(ctx, req, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if schema.Namespace != "Acme" {
		t.Errorf("expected namespace 'Acme', got %q", schema.Namespace)
	}
	if schema.Name != "main" {
		t.Errorf("expected name 'main', got %q", schema.Name)
	}
	if !schema.IsActive {
		t.Error("expected schema to be active")
	}
}

func TestSchemaManager_CreateSchema_InvalidRequest(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	tests := []struct {
		name string
		req  *models.CreateCedarSchemaRequest
	}{
		{"empty namespace", &models.CreateCedarSchemaRequest{Name: "test", SchemaContent: "{}", SchemaFormat: "json", Version: "1.0"}},
		{"empty name", &models.CreateCedarSchemaRequest{Namespace: "Acme", SchemaContent: "{}", SchemaFormat: "json", Version: "1.0"}},
		{"empty content", &models.CreateCedarSchemaRequest{Namespace: "Acme", Name: "test", SchemaFormat: "json", Version: "1.0"}},
		{"invalid format", &models.CreateCedarSchemaRequest{Namespace: "Acme", Name: "test", SchemaContent: "{}", SchemaFormat: "xml", Version: "1.0"}},
		{"empty version", &models.CreateCedarSchemaRequest{Namespace: "Acme", Name: "test", SchemaContent: "{}", SchemaFormat: "json"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := mgr.CreateSchema(ctx, tt.req, "admin")
			if err == nil {
				t.Error("expected error for invalid request")
			}
		})
	}
}

func TestSchemaManager_GetActiveSchema_Caching(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	req := &models.CreateCedarSchemaRequest{
		Namespace:     "Acme",
		Name:          "main",
		SchemaContent: `{"entityTypes": {}}`,
		SchemaFormat:  "json",
		Version:       "1.0",
	}

	_, err := mgr.CreateSchema(ctx, req, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// First call should go to store
	schema1, err := mgr.GetActiveSchema(ctx, "Acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call should be cached
	schema2, err := mgr.GetActiveSchema(ctx, "Acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if schema1.ID != schema2.ID {
		t.Error("expected same schema from cache")
	}
}

func TestSchemaManager_DeleteSchema(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	req := &models.CreateCedarSchemaRequest{
		Namespace:     "Acme",
		Name:          "main",
		SchemaContent: `{"entityTypes": {}}`,
		SchemaFormat:  "json",
		Version:       "1.0",
	}

	schema, _ := mgr.CreateSchema(ctx, req, "admin")

	err := mgr.DeleteSchema(ctx, schema.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should no longer be found
	_, err = mgr.GetSchema(ctx, schema.ID)
	if err == nil {
		t.Error("expected error after deletion")
	}
}

func TestSchemaManager_UpdateSchema(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	req := &models.CreateCedarSchemaRequest{
		Namespace:     "Acme",
		Name:          "main",
		SchemaContent: `{"entityTypes": {}}`,
		SchemaFormat:  "json",
		Version:       "1.0",
	}

	schema, _ := mgr.CreateSchema(ctx, req, "admin")

	newName := "updated"
	updateReq := &models.UpdateCedarSchemaRequest{
		Name: &newName,
	}

	updated, err := mgr.UpdateSchema(ctx, schema.ID, updateReq, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if updated.Name != "updated" {
		t.Errorf("expected name 'updated', got %q", updated.Name)
	}
}
