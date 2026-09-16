package permset

import (
	"reflect"
	"testing"

	"stratium/pkg/models"
)

// TestEveryDelegationFieldIsClassified is the whole of gap 5. A field added
// to models.Delegation must be classified as a permission dimension or
// explicitly excluded with a reason. A field in neither fails the build,
// which is what turns "someone remembered to add an if" into "the compiler
// asked a question".
//
// See docs/superpowers/specs/2026-09-15-permission-set-containment-design.md.
// WHEN THIS FAILS: you added a field to models.Delegation. Decide whether it
// bounds what its holder may do. If it does, add it to dimensions and add a
// containment rule AND a union rule for it. If it does not, add it to
// notDimensions with a falsifiable reason -- "enforced per hop at
// authz/delegation.go" is falsifiable; "not relevant" is not.
func TestEveryDelegationFieldIsClassified(t *testing.T) {
	dt := reflect.TypeOf(models.Delegation{})
	for i := range dt.NumField() {
		name := dt.Field(i).Name
		_, isDimension := dimensions[name]
		reason, isExcluded := notDimensions[name]

		switch {
		case isDimension && isExcluded:
			t.Errorf("field %s is both a dimension and excluded; pick one", name)
		case !isDimension && !isExcluded:
			t.Errorf("field %s is classified neither as a permission dimension "+
				"(dimensions, registry.go) nor as excluded (notDimensions). "+
				"Read this test's doc comment before adding it to either.", name)
		case isExcluded && reason == "":
			t.Errorf("field %s is excluded with an empty reason; the reason is "+
				"the part that makes the exclusion reviewable", name)
		}
	}
}

// TestDimensionsAreDelegationFields is the mirror: a registry entry naming a
// field that no longer exists is a stale rule, and a stale rule reads as
// coverage it no longer provides.
func TestDimensionsAreDelegationFields(t *testing.T) {
	dt := reflect.TypeOf(models.Delegation{})
	for _, registry := range []map[string]string{dimensions, notDimensions} {
		for name := range registry {
			if _, ok := dt.FieldByName(name); !ok {
				t.Errorf("registry names %q, which models.Delegation does not have", name)
			}
		}
	}
}
