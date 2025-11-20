package platform

import (
	"google.golang.org/protobuf/types/known/structpb"
)

// StringMapToValueMap converts a map[string]string to map[string]*structpb.Value
// This is useful for tests where we need to create subject_attributes with protobuf Values
func StringMapToValueMap(m map[string]string) map[string]*structpb.Value {
	result := make(map[string]*structpb.Value)
	for k, v := range m {
		result[k] = structpb.NewStringValue(v)
	}
	return result
}

// InterfaceMapToValueMap converts a map[string]interface{} to map[string]*structpb.Value
// This is useful for tests where we have mixed types
func InterfaceMapToValueMap(m map[string]interface{}) map[string]*structpb.Value {
	result := make(map[string]*structpb.Value)
	for k, v := range m {
		switch val := v.(type) {
		case string:
			result[k] = structpb.NewStringValue(val)
		case int:
			result[k] = structpb.NewNumberValue(float64(val))
		case float64:
			result[k] = structpb.NewNumberValue(val)
		case bool:
			result[k] = structpb.NewBoolValue(val)
		case []interface{}:
			list, _ := structpb.NewList(val)
			result[k] = structpb.NewListValue(list)
		case map[string]interface{}:
			str, _ := structpb.NewStruct(val)
			result[k] = structpb.NewStructValue(str)
		default:
			// Default to string representation
			result[k] = structpb.NewStringValue("")
		}
	}
	return result
}