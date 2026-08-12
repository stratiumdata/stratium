package classification

import (
	"strings"
	"testing"
)

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

// The no-caps and no-classification short-circuits both see "nothing was
// declared" but must stay independent: a delegation with NO caps at all is
// unrestricted on this axis regardless of what the resource does or does not
// say about itself. This is the entire boundary between "only a configured
// cap becomes strict" (R2, this task) and a change that denies everything —
// see TestCheckCap_ConfiguredCapDeniesWhenResourceHasNoClassification below
// for the mirror case where a cap IS configured. A mutation that widened the
// len(caps) == 0 branch to also require a resource classification would pass
// TestCheckCap_NoCapsAllows above (its resource is fully labelled) but fail
// exactly here.
func TestCheckCap_NoCapsAllowsEvenWhenResourceHasNoClassification(t *testing.T) {
	ok, reason := CheckCap(map[string]string{}, map[string]string{})
	if !ok {
		t.Fatalf("no configured caps must allow regardless of resource classification, got: %s", reason)
	}
}

// A configured cap against a resource that declares no classification cannot
// be evaluated, and R2 rules that unenforceable must not read as compliant:
// this must deny, not allow. This test replaces
// TestCheckCap_NoResourceClassificationAllows, which asserted the opposite
// and was, before Phase 7 Task 3, pinning the exact silent fail-open this
// task exists to close rather than a property worth preserving.
func TestCheckCap_ConfiguredCapDeniesWhenResourceHasNoClassification(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	ok, reason := CheckCap(caps, map[string]string{})
	if ok {
		t.Fatal("a configured cap against an unlabelled resource must deny, not pass uncontested")
	}
	if reason == "" {
		t.Fatal("the denial must explain itself")
	}
}

// The no-classification rule must fire on the classification alone, not on
// "classification AND hierarchy both blank" — found as a real survivor while
// mutation-testing this change beyond the three the brief requires, so it is
// pinned rather than left to luck. A resource that names a hierarchy this
// delegation never capped, while leaving its level unset, must still deny:
// the level is genuinely unknown, and trusting the bare, caller-supplied
// hierarchy claim well enough to skip straight to "no cap for this
// hierarchy" would let an untrusted "hierarchy" attribute launder past a
// classification cap the same way an untrusted "classification" attribute
// would — precisely the gap-in-the-comparison the package doc warns against.
// A guard narrowed to `resourceLevel == "" && resourceHierarchy == ""`
// passes every other test in this file (none combines an unrelated,
// non-empty hierarchy with a blank classification) yet returns ALLOW here.
func TestCheckCap_UnknownLevelDeniesEvenWithAnUncappedHierarchyNamed(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"} // no cap on "commercial"
	ok, reason := CheckCap(caps, map[string]string{"hierarchy": "commercial"})
	if ok {
		t.Fatal("an unknown classification level must deny regardless of which hierarchy the resource names")
	}
	if reason == "" {
		t.Fatal("the denial must explain itself")
	}
}

// The audit trail must be able to tell "we could not check" apart from "we
// checked, and it exceeded the cap" — an operator acts on those differently
// (spec §3.9, R2). This defends that the two reasons are distinguishable
// text, not merely that both happen to be non-empty: a mutation that reused
// the exceeds-cap wording for the uncheckable case would pass every other
// test in this file but fail here.
func TestCheckCap_UncheckableReasonDiffersFromExceedsCapReason(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	_, uncheckable := CheckCap(caps, map[string]string{})
	_, exceeds := CheckCap(caps, map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"})
	if uncheckable == exceeds {
		t.Fatal("an uncheckable cap and an exceeded cap must produce different reasons")
	}
	if strings.Contains(uncheckable, "exceeds") {
		t.Fatalf("the uncheckable-cap reason must not borrow the exceeds-cap wording, got: %q", uncheckable)
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

// Empty-string classification must behave identically to an omitted key —
// not merely "both deny," but the same decision and the same reason, since a
// caller that always populates the map (blanks included) must not be able to
// take a different path than one that omits the key entirely. Both now deny
// (R2); before Phase 7 Task 3 both allowed, and this test defended the same
// equivalence property then too — only the shared outcome changed.
func TestCheckCap_EmptyClassificationTreatedAsAbsent(t *testing.T) {
	caps := map[string]string{"nato": "CONFIDENTIAL"}
	emptyOK, emptyReason := CheckCap(caps, map[string]string{"classification": "", "hierarchy": "nato"})
	omittedOK, omittedReason := CheckCap(caps, map[string]string{"hierarchy": "nato"})
	if emptyOK != omittedOK || emptyReason != omittedReason {
		t.Fatalf("empty classification must behave identically to an omitted key: empty=(%v,%q) omitted=(%v,%q)",
			emptyOK, emptyReason, omittedOK, omittedReason)
	}
	if emptyOK {
		t.Fatal("a cap configured against an unlabelled resource must deny, not allow")
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
