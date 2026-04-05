package cedar

import (
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func TestEntityResolver_Resolve_BasicEntities(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	entities := resolver.Resolve(
		"Stratium",
		map[string]interface{}{"sub": "alice"},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	// Should contain: 10 classification entities + 1 user + 1 resource + 1 action = 13
	if len(entities) < 13 {
		t.Errorf("expected at least 13 entities, got %d", len(entities))
	}

	// Check user entity exists
	userUID := cedarlib.NewEntityUID(types.EntityType("Stratium::User"), cedarlib.String("alice"))
	if _, ok := entities[userUID]; !ok {
		t.Error("expected User::alice entity")
	}

	// Check resource entity exists
	resUID := cedarlib.NewEntityUID(types.EntityType("Stratium::Resource"), cedarlib.String("doc-1"))
	if _, ok := entities[resUID]; !ok {
		t.Error("expected Resource::doc-1 entity")
	}

	// Check action entity exists
	actionUID := cedarlib.NewEntityUID(types.EntityType("Stratium::Action"), cedarlib.String("read"))
	if _, ok := entities[actionUID]; !ok {
		t.Error("expected Action::read entity")
	}
}

func TestEntityResolver_Resolve_WithRoles(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	entities := resolver.Resolve(
		"Stratium",
		map[string]interface{}{
			"sub":   "alice",
			"roles": []interface{}{"admin", "key-admin"},
		},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	// User should exist
	userUID := cedarlib.NewEntityUID(types.EntityType("Stratium::User"), cedarlib.String("alice"))
	user, ok := entities[userUID]
	if !ok {
		t.Fatal("expected User::alice entity")
	}

	// User should have role parents
	adminRoleUID := cedarlib.NewEntityUID(types.EntityType("Stratium::Role"), cedarlib.String("admin"))
	found := false
	for parent := range user.Parents.All() {
		if parent == adminRoleUID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected User::alice to have Role::admin as parent")
	}

	// Role entities should exist
	if _, ok := entities[adminRoleUID]; !ok {
		t.Error("expected Role::admin entity to be created")
	}
}

func TestEntityResolver_Resolve_WithGroups(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	entities := resolver.Resolve(
		"Stratium",
		map[string]interface{}{
			"sub":    "alice",
			"groups": []interface{}{"engineering", "crypto-team"},
		},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	groupUID := cedarlib.NewEntityUID(types.EntityType("Stratium::Group"), cedarlib.String("engineering"))
	if _, ok := entities[groupUID]; !ok {
		t.Error("expected Group::engineering entity to be created")
	}
}

func TestEntityResolver_Resolve_WithClearance(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	entities := resolver.Resolve(
		"Stratium",
		map[string]interface{}{
			"sub":       "alice",
			"clearance": "SECRET",
		},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	userUID := cedarlib.NewEntityUID(types.EntityType("Stratium::User"), cedarlib.String("alice"))
	user, ok := entities[userUID]
	if !ok {
		t.Fatal("expected User::alice entity")
	}

	// Check that clearance attribute is set as entity UID reference
	clearanceVal, ok := user.Attributes.Get(cedarlib.String("clearance"))
	if !ok {
		t.Fatal("expected clearance attribute on User entity")
	}

	expectedClearanceUID := cedarlib.NewEntityUID(
		types.EntityType("Stratium::Classification"),
		cedarlib.String("SECRET"),
	)

	if clearanceVal != expectedClearanceUID {
		t.Errorf("expected clearance to be %v, got %v", expectedClearanceUID, clearanceVal)
	}
}

func TestEntityResolver_Resolve_ClassificationEntities(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	entities := resolver.Resolve("Stratium", nil, nil, "read")

	// Check all NATO classifications exist
	for _, level := range NATOHierarchy.Levels {
		uid := cedarlib.NewEntityUID(types.EntityType("Stratium::Classification"), cedarlib.String(level))
		if _, ok := entities[uid]; !ok {
			t.Errorf("expected Classification::%s entity", level)
		}
	}

	// Check all Commercial classifications exist
	for _, level := range CommercialHierarchy.Levels {
		uid := cedarlib.NewEntityUID(types.EntityType("Stratium::Classification"), cedarlib.String(level))
		if _, ok := entities[uid]; !ok {
			t.Errorf("expected Classification::%s entity", level)
		}
	}
}

func TestEntityResolver_Resolve_DefaultNamespace(t *testing.T) {
	resolver := NewEntityResolver("Default")

	entities := resolver.Resolve(
		"", // empty namespace should fall back to default
		map[string]interface{}{"sub": "alice"},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	userUID := cedarlib.NewEntityUID(types.EntityType("Default::User"), cedarlib.String("alice"))
	if _, ok := entities[userUID]; !ok {
		t.Error("expected entity with default namespace 'Default'")
	}
}

func TestEntityResolver_AddStaticEntities(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	customEntity := EntityDefinition{
		UID:        cedarlib.NewEntityUID(types.EntityType("Stratium::Department"), cedarlib.String("Engineering")),
		Attributes: types.RecordMap{cedarlib.String("name"): cedarlib.String("Engineering")},
	}

	resolver.AddStaticEntities([]EntityDefinition{customEntity})

	entities := resolver.Resolve("Stratium", nil, nil, "read")

	if _, ok := entities[customEntity.UID]; !ok {
		t.Error("expected custom Department entity in resolved entities")
	}
}
