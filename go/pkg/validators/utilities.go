package validators

import (
	"github.com/samber/lo"
	"reflect"
)

func isZero(obj interface{}) bool {
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		if val.IsNil() {
			return true
		}
		val = val.Elem()
	}

	fieldStart := 0
	if val.Kind() == reflect.Struct {
		check := val.FieldByName("state")
		if check.IsValid() {
			fieldStart = lo.Ternary(check.IsZero(), 0, 1)
		}

		for i := fieldStart; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.IsZero() {
				return false
			}
		}
	} else if val.Kind() == reflect.Slice || val.Kind() == reflect.Array || val.Kind() == reflect.String || val.Kind() == reflect.Map {
		return val.Len() == 0
	}

	return true
}
