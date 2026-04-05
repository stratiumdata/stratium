package cedar

import (
	"fmt"
	"sync"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// EntityResolver builds Cedar entity maps by combining cached static entities
// (classification hierarchies, groups, roles) with per-request entities
// (user from JWT, resource from request).
type EntityResolver struct {
	mu          sync.RWMutex
	staticCache []EntityDefinition
	defaultNS   string
}

// NewEntityResolver creates a new resolver with a default namespace.
func NewEntityResolver(defaultNamespace string) *EntityResolver {
	er := &EntityResolver{
		defaultNS: defaultNamespace,
	}
	// Seed with classification hierarchy entities
	er.RefreshStaticEntities()
	return er
}

// RefreshStaticEntities rebuilds the cached static entity set
// (classification hierarchies for the default namespace).
func (r *EntityResolver) RefreshStaticEntities() {
	entities := BuildAllClassificationEntities(r.defaultNS)
	r.mu.Lock()
	r.staticCache = entities
	r.mu.Unlock()
}

// AddStaticEntities appends additional static entities to the cache.
func (r *EntityResolver) AddStaticEntities(entities []EntityDefinition) {
	r.mu.Lock()
	r.staticCache = append(r.staticCache, entities...)
	r.mu.Unlock()
}

// Resolve builds a complete Cedar EntityMap for an authorization request.
// It merges cached static entities with request-specific entities built from
// the subject, resource, and action data.
func (r *EntityResolver) Resolve(
	namespace string,
	subject map[string]interface{},
	resource map[string]interface{},
	action string,
) types.EntityMap {
	entities := types.EntityMap{}

	// 1. Add cached static entities (classification hierarchies, etc.)
	r.mu.RLock()
	for _, def := range r.staticCache {
		entities[def.UID] = entityFromDefinition(def)
	}
	r.mu.RUnlock()

	// 2. Build the principal (User) entity from subject attributes
	principalUID, principalAttrs := MapSubjectToEntity(namespace, subject)
	var principalParents []types.EntityUID

	// If subject has groups, set group memberships as parents
	if groups, ok := subject["groups"]; ok {
		if groupList, ok := groups.([]interface{}); ok {
			groupType := qualifiedType(namespace, "Group")
			for _, g := range groupList {
				groupUID := cedarlib.NewEntityUID(groupType, cedarlib.String(fmt.Sprintf("%v", g)))
				principalParents = append(principalParents, groupUID)
				// Ensure the group entity exists
				if _, exists := entities[groupUID]; !exists {
					entities[groupUID] = types.Entity{
						UID:        groupUID,
						Parents:    cedarlib.NewEntityUIDSet(),
						Attributes: cedarlib.NewRecord(types.RecordMap{}),
					}
				}
			}
		}
	}

	// If subject has roles, set role memberships as parents
	if roles, ok := subject["roles"]; ok {
		if roleList, ok := roles.([]interface{}); ok {
			roleType := qualifiedType(namespace, "Role")
			for _, rl := range roleList {
				roleUID := cedarlib.NewEntityUID(roleType, cedarlib.String(fmt.Sprintf("%v", rl)))
				principalParents = append(principalParents, roleUID)
				if _, exists := entities[roleUID]; !exists {
					entities[roleUID] = types.Entity{
						UID:        roleUID,
						Parents:    cedarlib.NewEntityUIDSet(),
						Attributes: cedarlib.NewRecord(types.RecordMap{}),
					}
				}
			}
		}
	}

	// If subject has a clearance, add it as an entity UID attribute
	if clearance, ok := subject["clearance"]; ok {
		classType := qualifiedType(namespace, "Classification")
		classUID := cedarlib.NewEntityUID(classType, cedarlib.String(fmt.Sprintf("%v", clearance)))
		principalAttrs[cedarlib.String("clearance")] = classUID
	}

	entities[principalUID] = types.Entity{
		UID:        principalUID,
		Parents:    cedarlib.NewEntityUIDSet(principalParents...),
		Attributes: cedarlib.NewRecord(principalAttrs),
	}

	// 3. Build the resource entity from request attributes
	resourceUID, resourceAttrs := MapResourceToEntity(namespace, resource)

	// If resource has a classification, reference the classification entity
	if classification, ok := resource["classification"]; ok {
		classType := qualifiedType(namespace, "Classification")
		classUID := cedarlib.NewEntityUID(classType, cedarlib.String(fmt.Sprintf("%v", classification)))
		resourceAttrs[cedarlib.String("classification")] = classUID
	}

	entities[resourceUID] = types.Entity{
		UID:        resourceUID,
		Parents:    cedarlib.NewEntityUIDSet(),
		Attributes: cedarlib.NewRecord(resourceAttrs),
	}

	// 4. Ensure the action entity exists
	actionUID := MapActionToEntityUID(namespace, action)
	if _, exists := entities[actionUID]; !exists {
		entities[actionUID] = types.Entity{
			UID:        actionUID,
			Parents:    cedarlib.NewEntityUIDSet(),
			Attributes: cedarlib.NewRecord(types.RecordMap{}),
		}
	}

	return entities
}

// entityFromDefinition converts an EntityDefinition to a types.Entity.
func entityFromDefinition(def EntityDefinition) types.Entity {
	return types.Entity{
		UID:        def.UID,
		Parents:    cedarlib.NewEntityUIDSet(def.Parents...),
		Attributes: cedarlib.NewRecord(def.Attributes),
	}
}
