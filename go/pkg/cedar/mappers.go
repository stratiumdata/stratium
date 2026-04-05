package cedar

import (
	"fmt"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// qualifiedType returns "Namespace::TypeName" when a namespace is provided,
// or just "TypeName" when namespace is empty (for un-namespaced policies).
func qualifiedType(namespace, typeName string) types.EntityType {
	if namespace == "" {
		return types.EntityType(typeName)
	}
	return types.EntityType(fmt.Sprintf("%s::%s", namespace, typeName))
}

// MapSubjectToEntity converts a subject attributes map (from JWT claims or gRPC context)
// into a Cedar entity UID and attributes.
func MapSubjectToEntity(namespace string, subject map[string]interface{}) (types.EntityUID, types.RecordMap) {
	entityType := qualifiedType(namespace, "User")

	// Use "sub" or "id" or "email" as the entity ID, falling back to "unknown"
	entityID := "unknown"
	for _, key := range []string{"sub", "id", "email", "name"} {
		if v, ok := subject[key]; ok {
			entityID = fmt.Sprintf("%v", v)
			break
		}
	}

	uid := cedarlib.NewEntityUID(entityType, cedarlib.String(entityID))
	attrs := mapToRecordMap(subject)

	return uid, attrs
}

// MapResourceToEntity converts a resource attributes map into a Cedar entity UID and attributes.
func MapResourceToEntity(namespace string, resource map[string]interface{}) (types.EntityUID, types.RecordMap) {
	entityType := qualifiedType(namespace, "Resource")

	// Use "id" or "name" or "resource_id" as the entity ID
	entityID := "unknown"
	for _, key := range []string{"id", "resource_id", "name", "uri"} {
		if v, ok := resource[key]; ok {
			entityID = fmt.Sprintf("%v", v)
			break
		}
	}

	uid := cedarlib.NewEntityUID(entityType, cedarlib.String(entityID))
	attrs := mapToRecordMap(resource)

	return uid, attrs
}

// MapActionToEntityUID converts an action string to a Cedar action entity UID.
func MapActionToEntityUID(namespace, action string) types.EntityUID {
	actionType := qualifiedType(namespace, "Action")
	return cedarlib.NewEntityUID(actionType, cedarlib.String(action))
}

// MapContextToRecord converts an environment/context map to a Cedar record value.
func MapContextToRecord(env map[string]interface{}) types.Record {
	if len(env) == 0 {
		return cedarlib.NewRecord(types.RecordMap{})
	}
	return cedarlib.NewRecord(mapToRecordMap(env))
}

// mapToRecordMap converts a generic map[string]interface{} to Cedar RecordMap.
func mapToRecordMap(m map[string]interface{}) types.RecordMap {
	result := make(types.RecordMap, len(m))
	for k, v := range m {
		result[cedarlib.String(k)] = toTypedValue(v)
	}
	return result
}

// toTypedValue converts a Go value to the corresponding Cedar types.Value.
func toTypedValue(v interface{}) types.Value {
	switch val := v.(type) {
	case string:
		return cedarlib.String(val)
	case bool:
		return cedarlib.Boolean(val)
	case int:
		return cedarlib.Long(val)
	case int64:
		return cedarlib.Long(val)
	case float64:
		// Cedar has no float type; if it's a whole number use Long, otherwise String.
		if val == float64(int64(val)) {
			return cedarlib.Long(int64(val))
		}
		return cedarlib.String(fmt.Sprintf("%v", val))
	case []interface{}:
		items := make([]types.Value, len(val))
		for i, item := range val {
			items[i] = toTypedValue(item)
		}
		return cedarlib.NewSet(items...)
	case map[string]interface{}:
		return cedarlib.NewRecord(mapToRecordMap(val))
	case nil:
		return cedarlib.String("")
	default:
		return cedarlib.String(fmt.Sprintf("%v", val))
	}
}
