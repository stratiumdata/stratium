package classification

import "testing"

func TestIndex_KnownLevels(t *testing.T) {
	if Index("nato", "UNCLASSIFIED") != 0 {
		t.Error("UNCLASSIFIED must be the lowest NATO level")
	}
	if Index("nato", "TOP-SECRET") != 4 {
		t.Error("TOP-SECRET must be the highest NATO level")
	}
	if Index("nato", "SECRET") <= Index("nato", "CONFIDENTIAL") {
		t.Error("SECRET must outrank CONFIDENTIAL")
	}
}

func TestIndex_CaseInsensitive(t *testing.T) {
	if Index("NATO", "top-secret") != Index("nato", "TOP-SECRET") {
		t.Error("hierarchy and level lookups must be case-insensitive")
	}
}

func TestIndex_UnknownReturnsNegative(t *testing.T) {
	if Index("klingon", "SECRET") != -1 {
		t.Error("unknown hierarchy must return -1")
	}
	if Index("nato", "ULTRA-SECRET") != -1 {
		t.Error("unknown level must return -1")
	}
}

func TestIndex_CommercialHierarchy(t *testing.T) {
	if Index("commercial", "PUBLIC") != 0 {
		t.Error("PUBLIC must be the lowest commercial level")
	}
	if Index("commercial", "HIGHLY-CONFIDENTIAL") <= Index("commercial", "INTERNAL") {
		t.Error("HIGHLY-CONFIDENTIAL must outrank INTERNAL")
	}
}

// --- CheckCap: one test per fail-closed rule ---

// No caps means the delegation places no classification restriction.
func TestCheckCap_NoCapsAllows(t *testing.T) {
	ok, reason := CheckCap(nil, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("absent caps must allow, got: %s", reason)
	}
}

// A resource that declares no classification is unrestricted by caps.
func TestCheckCap_NoResourceClassificationAllows(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{})
	if !ok {
		t.Fatalf("undeclared resource classification must allow, got: %s", reason)
	}
}

// A classification without a hierarchy is ambiguous and must DENY. Allowing it
// would let a caller bypass every cap by omitting the hierarchy attribute.
func TestCheckCap_ClassificationWithoutHierarchyDenies(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "TOP-SECRET"})
	if ok {
		t.Fatal("classification without a hierarchy must deny as ambiguous")
	}
	if reason == "" {
		t.Fatal("denial must explain itself")
	}
}

// An empty-string hierarchy is the same as an absent one. A caller that always
// populates the keys must not bypass the ambiguity rule with "".
func TestCheckCap_EmptyHierarchyTreatedAsAbsent(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": ""})
	if ok {
		t.Fatal("empty hierarchy with a declared classification must deny")
	}
}

func TestCheckCap_EmptyClassificationTreatedAsAbsent(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("empty classification must be treated as undeclared, got: %s", reason)
	}
}

func TestCheckCap_WithinCapAllows(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("resource below cap must allow, got: %s", reason)
	}
}

func TestCheckCap_AtCapAllows(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("resource at cap must allow, got: %s", reason)
	}
}

func TestCheckCap_AboveCapDenies(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("resource above cap must deny")
	}
	if reason == "" {
		t.Fatal("denial must explain itself")
	}
}

// A cap on one hierarchy says nothing about another.
func TestCheckCap_NoCapForThisHierarchyAllows(t *testing.T) {
	caps := map[string]string{"commercial": "INTERNAL"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if !ok {
		t.Fatalf("cap on a different hierarchy must not restrict, got: %s", reason)
	}
}

// An unknown level must DENY, not compare as equal or fall through.
func TestCheckCap_UnknownResourceLevelDenies(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "ULTRA-SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("unknown resource level must deny")
	}
}

func TestCheckCap_UnknownCapLevelDenies(t *testing.T) {
	caps := map[string]string{"nato": "MEGA-SECRET"}
	ok, _ := CheckCap(caps, map[string]string{"classification": "SECRET", "hierarchy": "nato"})
	if ok {
		t.Fatal("unknown cap level must deny")
	}
}

func TestCheckCap_CapLookupIsCaseInsensitive(t *testing.T) {
	caps := map[string]string{"nato": "SECRET"}
	ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "NATO"})
	if !ok {
		t.Fatalf("hierarchy lookup must be case-insensitive, got: %s", reason)
	}
}

// Case-insensitivity must hold in BOTH directions. A caps map keyed in any
// casing must be found against a resource declaring any casing. Testing only
// the lowercase-caps direction hides a fail-open: a caps key the lookup cannot
// see falls through to "no cap for this hierarchy", which allows.
func TestCheckCap_CapKeyCasingCannotEvadeTheCap(t *testing.T) {
	for _, capKey := range []string{"nato", "NATO", "Nato", "nAtO"} {
		for _, resourceHierarchy := range []string{"nato", "NATO", "Nato"} {
			t.Run(capKey+"/"+resourceHierarchy, func(t *testing.T) {
				caps := map[string]string{capKey: "CONFIDENTIAL"}
				resource := map[string]string{
					"classification": "TOP-SECRET",
					"hierarchy":      resourceHierarchy,
				}
				if ok, _ := CheckCap(caps, resource); ok {
					t.Fatalf("TOP-SECRET passed a CONFIDENTIAL cap: caps key %q, resource hierarchy %q",
						capKey, resourceHierarchy)
				}
			})
		}
	}
}

// Two keys differing only by case, carrying different caps, is ambiguous.
// Resolving it by picking one would make the ceiling depend on map iteration
// order, so it denies.
func TestCheckCap_ConflictingCaseVariantKeysDeny(t *testing.T) {
	caps := map[string]string{"nato": "TOP-SECRET", "NATO": "UNCLASSIFIED"}
	resource := map[string]string{"classification": "SECRET", "hierarchy": "nato"}
	ok, reason := CheckCap(caps, resource)
	if ok {
		t.Fatal("conflicting case-variant cap keys must deny as ambiguous")
	}
	if reason == "" {
		t.Fatal("an ambiguity denial must explain itself")
	}
}

// Case-variant keys carrying the SAME cap are redundant, not ambiguous, and
// must enforce normally rather than denying.
func TestCheckCap_DuplicateCaseVariantKeysWithSameCapEnforce(t *testing.T) {
	caps := map[string]string{"nato": "SECRET", "NATO": "SECRET"}
	if ok, reason := CheckCap(caps, map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "nato"}); !ok {
		t.Fatalf("identical case-variant caps must enforce, not deny: %s", reason)
	}
	if ok, _ := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"}); ok {
		t.Fatal("identical case-variant caps must still enforce the cap")
	}
}
