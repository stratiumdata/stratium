package cedar

import (
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

func TestBuildClassificationEntities_NATO(t *testing.T) {
	entities := BuildClassificationEntities("Stratium", NATOHierarchy)

	if len(entities) != 5 {
		t.Fatalf("expected 5 NATO classification entities, got %d", len(entities))
	}

	// Verify each level has the correct parent
	natoLevels := NATOHierarchy.Levels
	entityType := types.EntityType("Stratium::Classification")

	for i, entity := range entities {
		expectedUID := cedarlib.NewEntityUID(entityType, cedarlib.String(natoLevels[i]))
		if entity.UID != expectedUID {
			t.Errorf("entity %d: expected UID %v, got %v", i, expectedUID, entity.UID)
		}

		if i < len(natoLevels)-1 {
			// Should have parent
			if len(entity.Parents) != 1 {
				t.Errorf("entity %d (%s): expected 1 parent, got %d", i, natoLevels[i], len(entity.Parents))
				continue
			}
			expectedParent := cedarlib.NewEntityUID(entityType, cedarlib.String(natoLevels[i+1]))
			if entity.Parents[0] != expectedParent {
				t.Errorf("entity %d (%s): expected parent %v, got %v", i, natoLevels[i], expectedParent, entity.Parents[0])
			}
		} else {
			// TOP-SECRET has no parent
			if len(entity.Parents) != 0 {
				t.Errorf("entity %d (%s): expected 0 parents, got %d", i, natoLevels[i], len(entity.Parents))
			}
		}
	}
}

func TestBuildClassificationEntities_Commercial(t *testing.T) {
	entities := BuildClassificationEntities("Acme", CommercialHierarchy)

	if len(entities) != 5 {
		t.Fatalf("expected 5 Commercial classification entities, got %d", len(entities))
	}

	// Verify the namespace is used
	entityType := types.EntityType("Acme::Classification")
	if entities[0].UID.Type != entityType {
		t.Errorf("expected entity type %v, got %v", entityType, entities[0].UID.Type)
	}
}

func TestBuildAllClassificationEntities(t *testing.T) {
	entities := BuildAllClassificationEntities("Stratium")

	// 5 NATO + 5 Commercial = 10
	if len(entities) != 10 {
		t.Fatalf("expected 10 classification entities, got %d", len(entities))
	}
}

func TestBuildClassificationEntities_HierarchyAttributes(t *testing.T) {
	entities := BuildClassificationEntities("Stratium", NATOHierarchy)

	// Check that UNCLASSIFIED has level 0 and hierarchy "nato"
	unclassified := entities[0]
	levelVal, ok := unclassified.Attributes[cedarlib.String("level")]
	if !ok {
		t.Fatal("UNCLASSIFIED missing 'level' attribute")
	}
	if levelVal != cedarlib.Long(0) {
		t.Errorf("UNCLASSIFIED level: expected 0, got %v", levelVal)
	}

	hierVal, ok := unclassified.Attributes[cedarlib.String("hierarchy")]
	if !ok {
		t.Fatal("UNCLASSIFIED missing 'hierarchy' attribute")
	}
	if hierVal != cedarlib.String("nato") {
		t.Errorf("UNCLASSIFIED hierarchy: expected 'nato', got %v", hierVal)
	}

	// Check that TOP-SECRET has level 4
	topSecret := entities[4]
	levelVal, ok = topSecret.Attributes[cedarlib.String("level")]
	if !ok {
		t.Fatal("TOP-SECRET missing 'level' attribute")
	}
	if levelVal != cedarlib.Long(4) {
		t.Errorf("TOP-SECRET level: expected 4, got %v", levelVal)
	}
}

func TestCedarHierarchyTraversal(t *testing.T) {
	// This is the key test: verify that Cedar's `in` operator works with
	// classification hierarchies. We build the entities and then run a
	// Cedar policy that checks clearance.

	namespace := "Test"
	hierEntities := BuildClassificationEntities(namespace, NATOHierarchy)

	// Build entity map
	entityMap := types.EntityMap{}
	for _, def := range hierEntities {
		entityMap[def.UID] = types.Entity{
			UID:        def.UID,
			Parents:    cedarlib.NewEntityUIDSet(def.Parents...),
			Attributes: cedarlib.NewRecord(def.Attributes),
		}
	}

	// Create a user with SECRET clearance
	classType := types.EntityType("Test::Classification")
	userType := types.EntityType("Test::User")
	userUID := cedarlib.NewEntityUID(userType, cedarlib.String("alice"))
	secretUID := cedarlib.NewEntityUID(classType, cedarlib.String("SECRET"))

	entityMap[userUID] = types.Entity{
		UID:     userUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("clearance"): secretUID,
		}),
	}

	// Create a resource with CONFIDENTIAL classification
	resType := types.EntityType("Test::Resource")
	resUID := cedarlib.NewEntityUID(resType, cedarlib.String("doc-1"))
	confUID := cedarlib.NewEntityUID(classType, cedarlib.String("CONFIDENTIAL"))

	entityMap[resUID] = types.Entity{
		UID:     resUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("classification"): confUID,
		}),
	}

	// Create action entity
	actionType := types.EntityType("Test::Action")
	actionUID := cedarlib.NewEntityUID(actionType, cedarlib.String("read"))
	entityMap[actionUID] = types.Entity{
		UID:        actionUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	// Policy: permit when resource.classification in principal.clearance
	cedarPolicy := `permit(
		principal is Test::User,
		action == Test::Action::"read",
		resource is Test::Resource
	) when {
		resource.classification in principal.clearance
	};`

	policySet, err := cedarlib.NewPolicySetFromBytes("test", []byte(cedarPolicy))
	if err != nil {
		t.Fatalf("failed to parse Cedar policy: %v", err)
	}

	req := types.Request{
		Principal: userUID,
		Action:    actionUID,
		Resource:  resUID,
		Context:   cedarlib.NewRecord(types.RecordMap{}),
	}

	decision, diag := cedarlib.Authorize(policySet, entityMap, req)

	// SECRET clearance should allow access to CONFIDENTIAL resources
	// because CONFIDENTIAL is a child of SECRET in the hierarchy
	if decision != cedarlib.Allow {
		t.Errorf("expected Allow for SECRET user accessing CONFIDENTIAL resource, got Deny")
		for _, e := range diag.Errors {
			t.Logf("  error: %s", e.String())
		}
	}
}

func TestCedarHierarchyDenial(t *testing.T) {
	// Verify that a user with CONFIDENTIAL clearance CANNOT access SECRET resources

	namespace := "Test"
	hierEntities := BuildClassificationEntities(namespace, NATOHierarchy)

	entityMap := types.EntityMap{}
	for _, def := range hierEntities {
		entityMap[def.UID] = types.Entity{
			UID:        def.UID,
			Parents:    cedarlib.NewEntityUIDSet(def.Parents...),
			Attributes: cedarlib.NewRecord(def.Attributes),
		}
	}

	classType := types.EntityType("Test::Classification")
	userType := types.EntityType("Test::User")
	userUID := cedarlib.NewEntityUID(userType, cedarlib.String("bob"))
	confUID := cedarlib.NewEntityUID(classType, cedarlib.String("CONFIDENTIAL"))

	entityMap[userUID] = types.Entity{
		UID:     userUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("clearance"): confUID,
		}),
	}

	resType := types.EntityType("Test::Resource")
	resUID := cedarlib.NewEntityUID(resType, cedarlib.String("top-doc"))
	secretUID := cedarlib.NewEntityUID(classType, cedarlib.String("SECRET"))

	entityMap[resUID] = types.Entity{
		UID:     resUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("classification"): secretUID,
		}),
	}

	actionType := types.EntityType("Test::Action")
	actionUID := cedarlib.NewEntityUID(actionType, cedarlib.String("read"))
	entityMap[actionUID] = types.Entity{
		UID:        actionUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	cedarPolicy := `permit(
		principal is Test::User,
		action == Test::Action::"read",
		resource is Test::Resource
	) when {
		resource.classification in principal.clearance
	};`

	policySet, err := cedarlib.NewPolicySetFromBytes("test", []byte(cedarPolicy))
	if err != nil {
		t.Fatalf("failed to parse Cedar policy: %v", err)
	}

	req := types.Request{
		Principal: userUID,
		Action:    actionUID,
		Resource:  resUID,
		Context:   cedarlib.NewRecord(types.RecordMap{}),
	}

	decision, _ := cedarlib.Authorize(policySet, entityMap, req)

	// CONFIDENTIAL clearance should NOT allow access to SECRET resources
	if decision != cedarlib.Deny {
		t.Errorf("expected Deny for CONFIDENTIAL user accessing SECRET resource, got Allow")
	}
}
