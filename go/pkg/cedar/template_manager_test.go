package cedar

import (
	"context"
	"strings"
	"testing"

	"stratium/pkg/models"
)

func TestTemplateManager_CreateTemplate(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	req := &models.CreateCedarTemplateRequest{
		Name:      "access-template",
		Namespace: "Acme",
		TemplateContent: `permit(
			principal == ?principal,
			action in [Acme::Action::"read", Acme::Action::"write"],
			resource == ?resource
		);`,
	}

	template, err := mgr.CreateTemplate(ctx, req, "admin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if template.Name != "access-template" {
		t.Errorf("expected name 'access-template', got %q", template.Name)
	}
	if template.Namespace != "Acme" {
		t.Errorf("expected namespace 'Acme', got %q", template.Namespace)
	}
}

func TestTemplateManager_CreateTemplate_InvalidContent(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	tests := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"no permit/forbid", "this is just text"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &models.CreateCedarTemplateRequest{
				Name:            "test",
				Namespace:       "Acme",
				TemplateContent: tt.content,
			}
			_, err := mgr.CreateTemplate(ctx, req, "admin")
			if err == nil {
				t.Error("expected error for invalid template content")
			}
		})
	}
}

func TestTemplateManager_InstantiateTemplate(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	// Create a template with placeholders
	req := &models.CreateCedarTemplateRequest{
		Name:      "user-resource-access",
		Namespace: "Acme",
		TemplateContent: `permit(
			principal == ?principal,
			action in [Acme::Action::"read", Acme::Action::"write"],
			resource == ?resource
		);`,
	}

	template, err := mgr.CreateTemplate(ctx, req, "admin")
	if err != nil {
		t.Fatalf("unexpected error creating template: %v", err)
	}

	// Instantiate with specific principal and resource
	instReq := &models.InstantiateTemplateRequest{
		PrincipalEntity: `Acme::User::"alice"`,
		ResourceEntity:  `Acme::Resource::"project-alpha"`,
	}

	link, policy, err := mgr.InstantiateTemplate(ctx, template.ID, instReq, "admin")
	if err != nil {
		t.Fatalf("unexpected error instantiating template: %v", err)
	}

	if link.TemplateID != template.ID {
		t.Errorf("expected template ID %v, got %v", template.ID, link.TemplateID)
	}

	if link.PrincipalEntity != `Acme::User::"alice"` {
		t.Errorf("expected principal entity %q, got %q", `Acme::User::"alice"`, link.PrincipalEntity)
	}

	if policy.Language != models.PolicyLanguageCedar {
		t.Errorf("expected language 'cedar', got %q", policy.Language)
	}

	// Verify placeholders are substituted
	if strings.Contains(policy.PolicyContent, "?principal") {
		t.Error("policy content still contains ?principal placeholder")
	}
	if strings.Contains(policy.PolicyContent, "?resource") {
		t.Error("policy content still contains ?resource placeholder")
	}
	if !strings.Contains(policy.PolicyContent, `Acme::User::"alice"`) {
		t.Error("policy content should contain the substituted principal")
	}
}

func TestTemplateManager_InstantiateTemplate_NotFound(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	instReq := &models.InstantiateTemplateRequest{
		PrincipalEntity: `Acme::User::"alice"`,
	}

	_, _, err := mgr.InstantiateTemplate(ctx, [16]byte{}, instReq, "admin")
	if err == nil {
		t.Error("expected error for non-existent template")
	}
}

func TestTemplateManager_ListLinkedPolicies(t *testing.T) {
	store := NewMemoryTemplateStore()
	mgr := NewTemplateManager(store)
	ctx := context.Background()

	req := &models.CreateCedarTemplateRequest{
		Name:      "test-template",
		Namespace: "Acme",
		TemplateContent: `permit(
			principal == ?principal,
			action,
			resource == ?resource
		);`,
	}

	template, _ := mgr.CreateTemplate(ctx, req, "admin")

	// Instantiate twice
	inst1 := &models.InstantiateTemplateRequest{
		PrincipalEntity: `Acme::User::"alice"`,
		ResourceEntity:  `Acme::Resource::"doc-1"`,
	}
	inst2 := &models.InstantiateTemplateRequest{
		PrincipalEntity: `Acme::User::"bob"`,
		ResourceEntity:  `Acme::Resource::"doc-2"`,
	}

	mgr.InstantiateTemplate(ctx, template.ID, inst1, "admin")
	mgr.InstantiateTemplate(ctx, template.ID, inst2, "admin")

	links, err := mgr.ListLinkedPolicies(ctx, template.ID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(links) != 2 {
		t.Errorf("expected 2 linked policies, got %d", len(links))
	}
}
