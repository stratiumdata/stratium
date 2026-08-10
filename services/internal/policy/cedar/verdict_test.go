package cedar

import (
	"reflect"
	"testing"

	"stratium/internal/authz"
)

// TestPolicyVerdict_CannotWiden is a structural claim about the return type
// of Evaluate, not a behavioural one: no input, and no policy text, can ever
// make Evaluate return something able to raise a tier, add a tool, or loosen
// a cap, because authz.PolicyVerdict — the only thing Evaluate returns —
// has no field through which such a thing could travel. Effect itself caps
// at allow/deny/escalate for exactly one leg's opinion; Priority is
// provenance-only (spec Y7) and this package never reads it back.
//
// This is pinned by field name and type, not just by count, so a future
// PolicyVerdict field named e.g. "GrantedTier" or "AddedTools" fails here by
// name — the point where its widening risk must be reviewed — rather than
// silently becoming something a Cedar (or any) engine could populate.
func TestPolicyVerdict_CannotWiden(t *testing.T) {
	want := map[string]reflect.Kind{
		"Effect":   reflect.Int, // authz.Effect
		"Reason":   reflect.String,
		"Source":   reflect.String,
		"PolicyID": reflect.String,
		"Priority": reflect.Int,
	}

	typ := reflect.TypeOf(authz.PolicyVerdict{})
	if typ.NumField() != len(want) {
		t.Fatalf("authz.PolicyVerdict has %d fields, want %d %v — a new field changes what a policy verdict can carry; review it for widening risk (a raised tier, an added tool, a loosened cap) before extending this test's expectations",
			typ.NumField(), len(want), fieldNames(want))
	}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		wantKind, ok := want[f.Name]
		if !ok {
			t.Errorf("unexpected field %s on authz.PolicyVerdict — not covered by this guard", f.Name)
			continue
		}
		if f.Type.Kind() != wantKind {
			t.Errorf("field %s has kind %s, want %s", f.Name, f.Type.Kind(), wantKind)
		}
	}
}

func fieldNames(m map[string]reflect.Kind) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}
