package cedar

import (
	"context"
	"testing"

	"stratium/pkg/models"
)

// Tests to cover remaining gaps for 80%+ coverage.

func TestSchemaManager_ListSchemas(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	// Create two schemas
	mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Acme", Name: "s1", SchemaContent: `{"a":1}`, SchemaFormat: "json", Version: "1.0",
	}, "admin")
	mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Corp", Name: "s2", SchemaContent: `{"b":2}`, SchemaFormat: "json", Version: "1.0",
	}, "admin")

	// List all
	all, err := mgr.ListSchemas(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 schemas, got %d", len(all))
	}

	// List by namespace
	acme, err := mgr.ListSchemas(ctx, "Acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(acme) != 1 {
		t.Errorf("expected 1 Acme schema, got %d", len(acme))
	}
}

func TestSchemaManager_ValidateSchemaContent_CedarFormat(t *testing.T) {
	store := NewMemorySchemaStore()
	mgr := NewSchemaManager(store)
	ctx := context.Background()

	// Cedar format with sufficient content
	_, err := mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Acme", Name: "test", SchemaContent: `entity User { name: String };`, SchemaFormat: "cedar", Version: "1.0",
	}, "admin")
	if err != nil {
		t.Errorf("expected success for valid cedar format, got: %v", err)
	}

	// Cedar format too short
	_, err = mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Acme", Name: "test2", SchemaContent: `x`, SchemaFormat: "cedar", Version: "2.0",
	}, "admin")
	if err == nil {
		t.Error("expected error for too-short cedar schema")
	}

	// Invalid format
	_, err = mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Acme", Name: "test3", SchemaContent: `{"a":1}`, SchemaFormat: "xml", Version: "1.0",
	}, "admin")
	if err == nil {
		t.Error("expected error for unsupported format")
	}

	// Invalid JSON schema
	_, err = mgr.CreateSchema(ctx, &models.CreateCedarSchemaRequest{
		Namespace: "Acme", Name: "test4", SchemaContent: `{broken json`, SchemaFormat: "json", Version: "1.0",
	}, "admin")
	if err == nil {
		t.Error("expected error for invalid JSON schema content")
	}
}

func TestTemplateManager_GetAndList(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	tmpl, _ := mgr.CreateTemplate(ctx, &models.CreateCedarTemplateRequest{
		Name: "t1", Namespace: "Acme",
		TemplateContent: `permit(principal == ?principal, action, resource);`,
	}, "admin")

	// Get
	got, err := mgr.GetTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "t1" {
		t.Errorf("expected name 't1', got %q", got.Name)
	}

	// List
	all, err := mgr.ListTemplates(ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected 1 template, got %d", len(all))
	}

	// Delete
	err = mgr.DeleteTemplate(ctx, tmpl.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = mgr.GetTemplate(ctx, tmpl.ID)
	if err == nil {
		t.Error("expected error after deletion")
	}
}

func TestNamespaceManager_QualifyEntityUID(t *testing.T) {
	mgr := NewNamespaceManager("Stratium")

	uid := mgr.QualifyEntityUID("Acme", "User", "alice")
	if uid.Type != "Acme::User" {
		t.Errorf("expected type Acme::User, got %v", uid.Type)
	}

	// Default namespace fallback
	uid2 := mgr.QualifyEntityUID("", "Resource", "doc-1")
	if uid2.Type != "Stratium::Resource" {
		t.Errorf("expected type Stratium::Resource, got %v", uid2.Type)
	}
}
