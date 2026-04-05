package cedar

import (
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// BenchmarkCedarPolicyParse measures per-request Cedar policy compilation time.
// This is the hot path — the PRD targets <10ms for typical policy sets.
func BenchmarkCedarPolicyParse(b *testing.B) {
	policy := `permit(
		principal is Stratium::User,
		action == Stratium::Action::"UnwrapDEK",
		resource is Stratium::Resource
	) when {
		resource.classification in principal.clearance
	};`

	policyBytes := []byte(policy)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cedarlib.NewPolicySetFromBytes("bench", policyBytes)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCedarAuthorize measures the full authorization cycle:
// parse + entity resolution + authorize.
func BenchmarkCedarAuthorize(b *testing.B) {
	policy := `permit(
		principal is Stratium::User,
		action == Stratium::Action::"UnwrapDEK",
		resource is Stratium::Resource
	) when {
		resource.classification in principal.clearance
	};`

	policySet, err := cedarlib.NewPolicySetFromBytes("bench", []byte(policy))
	if err != nil {
		b.Fatal(err)
	}

	// Build entities once
	hierEntities := BuildClassificationEntities("Stratium", NATOHierarchy)
	entityMap := types.EntityMap{}
	for _, def := range hierEntities {
		entityMap[def.UID] = types.Entity{
			UID:        def.UID,
			Parents:    cedarlib.NewEntityUIDSet(def.Parents...),
			Attributes: cedarlib.NewRecord(def.Attributes),
		}
	}

	classType := types.EntityType("Stratium::Classification")
	userType := types.EntityType("Stratium::User")
	userUID := cedarlib.NewEntityUID(userType, cedarlib.String("alice"))
	secretUID := cedarlib.NewEntityUID(classType, cedarlib.String("SECRET"))

	entityMap[userUID] = types.Entity{
		UID:     userUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("clearance"): secretUID,
		}),
	}

	resType := types.EntityType("Stratium::Resource")
	resUID := cedarlib.NewEntityUID(resType, cedarlib.String("doc-1"))
	confUID := cedarlib.NewEntityUID(classType, cedarlib.String("CONFIDENTIAL"))

	entityMap[resUID] = types.Entity{
		UID:     resUID,
		Parents: cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{
			cedarlib.String("classification"): confUID,
		}),
	}

	actionType := types.EntityType("Stratium::Action")
	actionUID := cedarlib.NewEntityUID(actionType, cedarlib.String("UnwrapDEK"))
	entityMap[actionUID] = types.Entity{
		UID:        actionUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	req := types.Request{
		Principal: userUID,
		Action:    actionUID,
		Resource:  resUID,
		Context:   cedarlib.NewRecord(types.RecordMap{}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision, _ := cedarlib.Authorize(policySet, entityMap, req)
		if decision != cedarlib.Allow {
			b.Fatal("expected Allow")
		}
	}
}

// BenchmarkCedarParseAndAuthorize measures the full per-request path
// including policy parsing (the V1 approach from the PRD).
func BenchmarkCedarParseAndAuthorize(b *testing.B) {
	policy := `permit(
		principal is Stratium::User,
		action == Stratium::Action::"UnwrapDEK",
		resource is Stratium::Resource
	) when {
		resource.classification in principal.clearance
	};`
	policyBytes := []byte(policy)

	resolver := NewEntityResolver("Stratium")

	subject := map[string]interface{}{
		"sub":       "alice",
		"clearance": "SECRET",
	}
	resource := map[string]interface{}{
		"id":             "doc-1",
		"classification": "CONFIDENTIAL",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		policySet, err := cedarlib.NewPolicySetFromBytes("bench", policyBytes)
		if err != nil {
			b.Fatal(err)
		}

		entities := resolver.Resolve("Stratium", subject, resource, "UnwrapDEK")

		principalUID, _ := MapSubjectToEntity("Stratium", subject)
		resourceUID, _ := MapResourceToEntity("Stratium", resource)
		actionUID := MapActionToEntityUID("Stratium", "UnwrapDEK")

		req := types.Request{
			Principal: principalUID,
			Action:    actionUID,
			Resource:  resourceUID,
			Context:   cedarlib.NewRecord(types.RecordMap{}),
		}

		cedarlib.Authorize(policySet, entities, req)
	}
}

// BenchmarkEntityResolverResolve measures just entity resolution time.
func BenchmarkEntityResolverResolve(b *testing.B) {
	resolver := NewEntityResolver("Stratium")

	subject := map[string]interface{}{
		"sub":       "alice",
		"clearance": "SECRET",
		"roles":     []interface{}{"admin", "key-admin"},
		"groups":    []interface{}{"engineering"},
	}
	resource := map[string]interface{}{
		"id":             "doc-1",
		"classification": "CONFIDENTIAL",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.Resolve("Stratium", subject, resource, "UnwrapDEK")
	}
}

// BenchmarkHierarchyBuild measures classification hierarchy entity construction.
func BenchmarkHierarchyBuild(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildAllClassificationEntities("Stratium")
	}
}
