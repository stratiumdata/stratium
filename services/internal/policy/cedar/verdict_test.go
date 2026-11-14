package cedar

import (
	"reflect"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
)

// TestPolicyVerdict_CannotWiden is a structural claim about the return type
// of Evaluate, not a behavioural one: no input, and no policy text, can ever
// make Evaluate return something able to raise a tier, add a tool, or loosen
// a cap, because authz.PolicyVerdict — the only thing Evaluate returns —
// has no field through which such a thing could travel. Effect itself caps
// at allow/deny/escalate for exactly one leg's opinion; Priority is
// provenance-only (spec Y7) and this package never reads it back.
// UnevaluatedPolicyIDs was reviewed under this same guard when it was
// added: it is diagnostic-only, listing ids a language could not evaluate,
// never granting anything — Effect is still the only field any fold or
// ceiling check ever consults — and this package's own Evaluate never
// populates it (that is exclusively internal/policy.orphanVerdicts and
// prepareFailureVerdicts' job, for a language with no engine at all or one
// whose Prepare failed; a live, running Cedar evaluation is neither).
//
// This is pinned by field name and type, not just by count, so a future
// PolicyVerdict field named e.g. "GrantedTier" or "AddedTools" fails here by
// name — the point where its widening risk must be reviewed — rather than
// silently becoming something a Cedar (or any) engine could populate.
func TestPolicyVerdict_CannotWiden(t *testing.T) {
	want := map[string]reflect.Kind{
		"Effect":               reflect.Int, // authz.Effect
		"Reason":               reflect.String,
		"Source":               reflect.String,
		"PolicyID":             reflect.String,
		"Priority":             reflect.Int,
		"UnevaluatedPolicyIDs": reflect.Slice,
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
