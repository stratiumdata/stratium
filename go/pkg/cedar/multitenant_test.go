package cedar

import (
	"testing"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// TestMultiTenantIsolation_CrossNamespaceDenial verifies that a policy in
// namespace "Acme" does NOT match entities in namespace "Corp".
// This is the core multi-tenant isolation guarantee.
func TestMultiTenantIsolation_CrossNamespaceDenial(t *testing.T) {
	// Policy: permit Acme users to read Acme resources
	policy := `permit(
		principal is Acme::User,
		action == Acme::Action::"read",
		resource is Acme::Resource
	);`

	policySet, err := cedarlib.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	entities := types.EntityMap{}

	// Create a Corp user (different namespace)
	corpUserUID := cedarlib.NewEntityUID(types.EntityType("Corp::User"), cedarlib.String("alice"))
	entities[corpUserUID] = types.Entity{
		UID:        corpUserUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	// Create a Corp resource
	corpResUID := cedarlib.NewEntityUID(types.EntityType("Corp::Resource"), cedarlib.String("doc-1"))
	entities[corpResUID] = types.Entity{
		UID:        corpResUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	// Create a Corp action
	corpActionUID := cedarlib.NewEntityUID(types.EntityType("Corp::Action"), cedarlib.String("read"))
	entities[corpActionUID] = types.Entity{
		UID:        corpActionUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	req := types.Request{
		Principal: corpUserUID,
		Action:    corpActionUID,
		Resource:  corpResUID,
		Context:   cedarlib.NewRecord(types.RecordMap{}),
	}

	decision, _ := cedarlib.Authorize(policySet, entities, req)

	// Corp::User should NOT match Acme::User — different namespace = default deny
	if decision != cedarlib.Deny {
		t.Error("expected Deny: Corp::User should not match Acme::User policy (cross-namespace isolation)")
	}
}

// TestMultiTenantIsolation_SameNamespaceAllow verifies that entities within
// the same namespace DO match.
func TestMultiTenantIsolation_SameNamespaceAllow(t *testing.T) {
	policy := `permit(
		principal is Acme::User,
		action == Acme::Action::"read",
		resource is Acme::Resource
	);`

	policySet, err := cedarlib.NewPolicySetFromBytes("test", []byte(policy))
	if err != nil {
		t.Fatalf("failed to parse policy: %v", err)
	}

	entities := types.EntityMap{}

	acmeUserUID := cedarlib.NewEntityUID(types.EntityType("Acme::User"), cedarlib.String("alice"))
	entities[acmeUserUID] = types.Entity{
		UID:        acmeUserUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	acmeResUID := cedarlib.NewEntityUID(types.EntityType("Acme::Resource"), cedarlib.String("doc-1"))
	entities[acmeResUID] = types.Entity{
		UID:        acmeResUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	acmeActionUID := cedarlib.NewEntityUID(types.EntityType("Acme::Action"), cedarlib.String("read"))
	entities[acmeActionUID] = types.Entity{
		UID:        acmeActionUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(types.RecordMap{}),
	}

	req := types.Request{
		Principal: acmeUserUID,
		Action:    acmeActionUID,
		Resource:  acmeResUID,
		Context:   cedarlib.NewRecord(types.RecordMap{}),
	}

	decision, _ := cedarlib.Authorize(policySet, entities, req)

	if decision != cedarlib.Allow {
		t.Error("expected Allow: Acme::User should match Acme::User policy (same namespace)")
	}
}

// TestMultiTenantIsolation_EntityResolverNamespaceScoping verifies the
// EntityResolver correctly scopes entities to the requested namespace.
func TestMultiTenantIsolation_EntityResolverNamespaceScoping(t *testing.T) {
	resolver := NewEntityResolver("Stratium")

	// Resolve with Acme namespace
	acmeEntities := resolver.Resolve(
		"Acme",
		map[string]interface{}{"sub": "alice"},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	// Resolve with Corp namespace
	corpEntities := resolver.Resolve(
		"Corp",
		map[string]interface{}{"sub": "alice"},
		map[string]interface{}{"id": "doc-1"},
		"read",
	)

	// Acme entities should use Acme:: prefix
	acmeUserUID := cedarlib.NewEntityUID(types.EntityType("Acme::User"), cedarlib.String("alice"))
	if _, ok := acmeEntities[acmeUserUID]; !ok {
		t.Error("expected Acme::User::\"alice\" in Acme namespace entities")
	}

	// Corp entities should use Corp:: prefix
	corpUserUID := cedarlib.NewEntityUID(types.EntityType("Corp::User"), cedarlib.String("alice"))
	if _, ok := corpEntities[corpUserUID]; !ok {
		t.Error("expected Corp::User::\"alice\" in Corp namespace entities")
	}

	// Acme entities should NOT contain Corp entities
	if _, ok := acmeEntities[corpUserUID]; ok {
		t.Error("Acme entities should not contain Corp::User")
	}

	// Corp entities should NOT contain Acme entities
	if _, ok := corpEntities[acmeUserUID]; ok {
		t.Error("Corp entities should not contain Acme::User")
	}
}

// TestMultiTenantIsolation_ClassificationHierarchyPerNamespace verifies that
// classification hierarchies are scoped per-namespace.
func TestMultiTenantIsolation_ClassificationHierarchyPerNamespace(t *testing.T) {
	acmeEntities := BuildAllClassificationEntities("Acme")
	corpEntities := BuildAllClassificationEntities("Corp")

	// Acme SECRET entity should have Acme:: prefix
	acmeSecretUID := cedarlib.NewEntityUID(types.EntityType("Acme::Classification"), cedarlib.String("SECRET"))
	found := false
	for _, e := range acmeEntities {
		if e.UID == acmeSecretUID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Acme::Classification::\"SECRET\" in Acme entities")
	}

	// Corp SECRET entity should have Corp:: prefix
	corpSecretUID := cedarlib.NewEntityUID(types.EntityType("Corp::Classification"), cedarlib.String("SECRET"))
	found = false
	for _, e := range corpEntities {
		if e.UID == corpSecretUID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected Corp::Classification::\"SECRET\" in Corp entities")
	}

	// They should be different UIDs
	if acmeSecretUID == corpSecretUID {
		t.Error("Acme and Corp SECRET UIDs should be different (namespace isolation)")
	}
}
