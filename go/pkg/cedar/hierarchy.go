package cedar

import (
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// ClassificationHierarchy represents a named classification hierarchy (e.g., NATO, Commercial).
type ClassificationHierarchy struct {
	Name   string
	Levels []string // Ordered from lowest to highest clearance
}

// NATOHierarchy defines the NATO/DoD classification levels.
var NATOHierarchy = ClassificationHierarchy{
	Name: "nato",
	Levels: []string{
		"UNCLASSIFIED",
		"RESTRICTED",
		"CONFIDENTIAL",
		"SECRET",
		"TOP-SECRET",
	},
}

// CommercialHierarchy defines the commercial classification levels.
var CommercialHierarchy = ClassificationHierarchy{
	Name: "commercial",
	Levels: []string{
		"PUBLIC",
		"INTERNAL",
		"CONFIDENTIAL-COMMERCIAL",
		"RESTRICTED-COMMERCIAL",
		"HIGHLY-CONFIDENTIAL",
	},
}

// DefaultHierarchies returns all built-in classification hierarchies.
func DefaultHierarchies() []ClassificationHierarchy {
	return []ClassificationHierarchy{NATOHierarchy, CommercialHierarchy}
}

// EntityDefinition holds the data needed to create a Cedar entity.
type EntityDefinition struct {
	UID        types.EntityUID
	Parents    []types.EntityUID
	Attributes types.RecordMap
}

// BuildClassificationEntities creates Cedar entities for a classification hierarchy.
// Each level is an entity whose parent is the next-higher level, enabling Cedar's
// `in` operator to perform clearance checks (e.g., SECRET in TOP-SECRET evaluates true).
func BuildClassificationEntities(namespace string, hierarchy ClassificationHierarchy) []EntityDefinition {
	entityType := types.EntityType(fmt.Sprintf("%s::Classification", namespace))
	entities := make([]EntityDefinition, 0, len(hierarchy.Levels))

	for i, level := range hierarchy.Levels {
		entity := EntityDefinition{
			UID: cedarlib.NewEntityUID(entityType, cedarlib.String(level)),
			Attributes: types.RecordMap{
				cedarlib.String("level"):     cedarlib.Long(i),
				cedarlib.String("hierarchy"): cedarlib.String(hierarchy.Name),
			},
		}

		// Every level except the highest has the next level as its parent.
		// This means UNCLASSIFIED → RESTRICTED → CONFIDENTIAL → SECRET → TOP-SECRET.
		if i < len(hierarchy.Levels)-1 {
			parentLevel := hierarchy.Levels[i+1]
			entity.Parents = []types.EntityUID{
				cedarlib.NewEntityUID(entityType, cedarlib.String(parentLevel)),
			}
		}

		entities = append(entities, entity)
	}

	return entities
}

// BuildAllClassificationEntities creates Cedar entities for all default hierarchies.
func BuildAllClassificationEntities(namespace string) []EntityDefinition {
	var all []EntityDefinition
	for _, h := range DefaultHierarchies() {
		all = append(all, BuildClassificationEntities(namespace, h)...)
	}
	return all
}
