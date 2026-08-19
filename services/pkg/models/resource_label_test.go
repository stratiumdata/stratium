package models

import (
	"reflect"
	"testing"

	"stratium/pkg/classification"
)

// TestResourceLabelRule_RuleCopiesEveryMatcherField is the guarantee
// ResourceLabelRule's own doc comment once claimed the compiler gave, and does
// not: Rule is a KEYED composite literal, so a field added to
// classification.Rule is silently zero-valued through the conversion and a
// field added here is silently dropped by it. Neither is a compile error;
// adding a Category field to classification.Rule was measured to leave both
// `go build ./...` and the entire test suite green.
//
// That matters more here than the usual struct-drift case. The two shapes exist
// separately so the pure, mutation-verified matcher never acquires a surrogate
// id or wire tags, and the ONLY thing standing between that choice and silent
// divergence is this test. A field added to classification.Rule that the store
// then never persists, or persists and never reads back, is the drift class
// this whole task exists to prevent — asserted impossible where it was merely
// unlikely.
//
// It ENUMERATES rather than counting, the same property this project's own
// TestNoProductionQueryFiltersByTenantID has and a bare NumField check does
// not: a field renamed on one side and a field added to both but forgotten in
// Rule are both caught, and no number needs updating by hand when the structs
// legitimately grow.
//
// Fields on ResourceLabelRule with NO counterpart on classification.Rule are
// deliberately not checked. ID and TenantID are exactly that — persistence
// identity the matcher has no use for — and they are the reason the two types
// are separate in the first place.
func TestResourceLabelRule_RuleCopiesEveryMatcherField(t *testing.T) {
	// Every string field gets its own name as its value, so a conversion that
	// copied the right number of fields in the wrong ORDER (Hierarchy into
	// Level) fails as loudly as one that dropped a field.
	src := ResourceLabelRule{}
	v := reflect.ValueOf(&src).Elem()
	for i := range v.NumField() {
		if f := v.Field(i); f.Kind() == reflect.String {
			f.SetString(v.Type().Field(i).Name)
		}
	}

	got := reflect.ValueOf(src.Rule())
	matcher := reflect.TypeOf(classification.Rule{})

	// A floor, for the same reason ShareOneValidator carries one: the loop
	// below is the whole test, and a loop over zero fields passes silently.
	// This guard exists to catch a field going unchecked, so it must not be
	// able to check nothing and report success.
	if matcher.NumField() < 3 {
		t.Fatalf("classification.Rule has %d fields, want at least 3 — either the matcher "+
			"lost a field or this guard is about to verify nothing", matcher.NumField())
	}

	for i := range matcher.NumField() {
		name := matcher.Field(i).Name
		if matcher.Field(i).Type.Kind() != reflect.String {
			t.Errorf("classification.Rule.%s is %s, and this guard only knows how to check string fields — "+
				"extend it rather than letting a field go unchecked", name, matcher.Field(i).Type.Kind())
			continue
		}
		want := v.FieldByName(name)
		if !want.IsValid() {
			t.Errorf("classification.Rule has field %s and models.ResourceLabelRule does not — the PAP cannot "+
				"author, store, or return a field it has no place for, so a decision would be made on a value "+
				"no operator can set", name)
			continue
		}
		if got.Field(i).String() != want.String() {
			t.Errorf("Rule() left %s = %q, want %q — the conversion does not carry it",
				name, got.Field(i).String(), want.String())
		}
	}
}
