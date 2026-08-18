// Package classification is the single source for Stratium's classification
// hierarchies, for what a given resource's classification IS, and for
// per-hierarchy cap enforcement.
//
// The middle clause arrived with spec §3.9.1: resolving a resource id to a
// level (resolve.go) is stated in this package's own vocabulary — a
// hierarchy and a level, ranked by Levels — and answering "did this rule
// lower the classification?" is a question only an ordering can answer. Two
// packages both constructing a (hierarchy, level) pair would be two places
// for the fail-closed rules below to be got right.
//
// Every rule here fails closed. The recurring attack this defends against is
// bypass-by-omission: a caller that leaves out an attribute, or supplies a
// level nobody recognizes, must be denied rather than slipping through a gap
// in the comparison. Resolve extends that to the rules themselves: a prefix
// carrying two answers resolves to none, never to whichever the store
// returned first.
package classification

import (
	"fmt"
	"strings"
)

// Levels are the canonical hierarchies, ordered low to high.
var Levels = map[string][]string{
	"nato": {"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP-SECRET"},
	"commercial": {
		"PUBLIC", "INTERNAL", "CONFIDENTIAL-COMMERCIAL",
		"RESTRICTED-COMMERCIAL", "HIGHLY-CONFIDENTIAL",
	},
}

// AttrClassification and AttrHierarchy are the two resource-attribute keys
// CheckCap reads. Named here, in the package that reads them, so the PDP that
// writes them (internal/pdpgrpc's resource labelling) and the check that
// consumes them cannot drift into two spellings — a drift whose only symptom
// would be a label that resolved correctly and then failed to arrive.
//
// They are also the two keys R1 forbids anyone but the PDP from supplying:
// see internal/pdpgrpc/label.go, which strips them from the caller's map
// before writing its own.
const (
	AttrClassification = "classification"
	AttrHierarchy      = "hierarchy"
)

// lookupCap finds a hierarchy's cap in a caller-supplied caps map, scanning
// case-insensitively the way Index scans Levels.
//
// A plain map lookup is not enough here. Levels is ours and always lowercase,
// but caps arrives from the caller in whatever casing it chose. Trying only
// `strings.ToLower(h)` and then the verbatim key misses a caps map keyed
// "NATO" against a resource declaring "nato" — the cap is silently invisible
// and CheckCap falls through to "no cap for this hierarchy", which ALLOWS.
// That is a fail-open on the platform's core authorization primitive.
//
// Two keys matching case-insensitively but carrying different levels is
// ambiguous, and ambiguity denies — picking one would make the effective
// ceiling depend on Go's map iteration order.
func lookupCap(caps map[string]string, hierarchy string) (level string, found bool, ambiguous bool) {
	for k, v := range caps {
		if !strings.EqualFold(k, hierarchy) {
			continue
		}
		if found && v != level {
			return "", false, true
		}
		level, found = v, true
	}
	return level, found, false
}

// Index returns a level's rank within its hierarchy, case-insensitively, or -1
// if either the hierarchy or the level is unknown. Callers must treat -1 as a
// denial, never as a comparable value.
func Index(hierarchy, level string) int {
	levels, ok := Levels[strings.ToLower(hierarchy)]
	if !ok {
		return -1
	}
	for i, l := range levels {
		if strings.EqualFold(l, level) {
			return i
		}
	}
	return -1
}

// CheckCap enforces a delegation's per-hierarchy classification caps against
// the resource being accessed.
//
// Rules, each fail-closed, IN THIS ORDER — the order is part of the contract,
// not an implementation detail (see R9 at the label-validity check below):
//   - no caps                                  → allow (no restriction declared)
//   - no resource classification               → DENY (a configured cap
//     cannot be evaluated against a resource that says nothing about its
//     classification; unenforceable must not read as compliant)
//   - classification without a hierarchy       → DENY (ambiguous; the
//     bypass-by-omission case)
//   - unknown hierarchy, or unknown level      → DENY (R9: a label the system
//     cannot rank is not a permissive label, it is an unreadable one — and
//     this is checked BEFORE the allow below, not after)
//   - no cap for the resource's hierarchy      → allow (this cap says nothing
//     about that hierarchy)
//   - unknown cap level                        → DENY (never compare as equal)
//   - otherwise                                → resource rank ≤ cap rank
//
// The first two rules look alike — both see "nothing was declared" — but
// answer different questions and must stay independent. No caps means this
// delegation restricts nothing on any hierarchy, so there is no rule to
// enforce and allowing costs nothing. A configured cap against an unlabelled
// resource means a restriction WAS declared and cannot be checked: reading
// that as compliant would let the absence of information stand in for having
// satisfied it — the same silent fail-open D10 ruled out for a policy that
// cannot be evaluated, applied here to a cap instead (spec §3.9, R2). Until
// Phase 7 Task 1, no PEP populated a request's resource at all, so this
// branch was not a rare edge case: it fired on every classification-capped
// decision ever made, always as an allow.
func CheckCap(caps map[string]string, resourceAttrs map[string]string) (bool, string) {
	if len(caps) == 0 {
		return true, ""
	}

	// Empty strings are treated as absent. A caller that always populates the
	// keys — building the map from request fields that may be blank — must not
	// be able to sidestep the ambiguity rule by supplying "".
	resourceLevel := resourceAttrs[AttrClassification]
	resourceHierarchy := resourceAttrs[AttrHierarchy]

	if resourceLevel == "" {
		// A cap IS configured here — len(caps) == 0 already returned above —
		// and the resource says nothing about its classification. Nothing
		// tells this function whether the resource even falls under the
		// capped hierarchy, so "no violation found" would be a guess wearing
		// an allow. The reason says "cannot be evaluated," deliberately not
		// "satisfied" and not phrased like the exceeds-cap denial below: an
		// operator's audit trail must be able to tell "we could not check"
		// apart from "we checked, and it was over the line."
		return false, "resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies"
	}
	if resourceHierarchy == "" {
		return false, "resource classification declared without a hierarchy attribute (ambiguous)"
	}

	// R9, and the ordering IS the requirement: the label has to be readable
	// before any branch below is allowed to allow. Everything past this point
	// asks a question about RANK — "is the resource at or under the cap", and,
	// via the !hasCap return, "does this cap speak to the resource's
	// hierarchy at all" — and neither question has an answer for a label the
	// system cannot rank. A permissive early return must be reached only by
	// inputs the system has already established it can evaluate; this is what
	// establishes it.
	//
	// Two unknowns, reported separately, because they are different operator
	// mistakes and a merged "unknown label" would name neither: Index returns
	// -1 for both, so an unknown hierarchy is checked first — a level cannot
	// be ranked within a hierarchy that does not exist, and reporting one as
	// an unknown LEVEL would send an operator looking in the wrong column.
	//
	// This is not the same check as the store's validateResourceLabelRule
	// (internal/store/resource_label.go), duplicated. That one gives an
	// operator a good error at the point of the typo and is worth having for
	// that alone; it is NOT the enforcement, because a stale read, an
	// in-flight migration, or a direct psql write each hand this function
	// rows it never saw. R9 says so in as many words.
	if _, known := Levels[strings.ToLower(resourceHierarchy)]; !known {
		return false, fmt.Sprintf(
			"unknown classification hierarchy %q; the delegation's classification cap cannot be evaluated and therefore denies",
			resourceHierarchy)
	}
	resourceIdx := Index(resourceHierarchy, resourceLevel)
	if resourceIdx < 0 {
		return false, fmt.Sprintf("unknown classification level %q in hierarchy %q",
			resourceLevel, resourceHierarchy)
	}

	capLevel, hasCap, ambiguous := lookupCap(caps, resourceHierarchy)
	if ambiguous {
		return false, fmt.Sprintf(
			"conflicting caps for hierarchy %q (keys differing only by case carry different levels)",
			resourceHierarchy)
	}
	if !hasCap {
		// A KNOWN hierarchy this delegation's caps do not mention. Still an
		// allow, and deliberately so: a cap on nato says nothing about
		// commercial, and silence is not a denial. The check above is what
		// makes that safe — reaching this line now means the label was
		// readable and simply uncapped, not unreadable. Widening this to a
		// denial would turn every uncapped hierarchy into a refusal; see
		// TestCheckCap_NoCapForThisHierarchyAllows, which exists to fail if
		// R9's fix is ever mistaken for a blanket denial.
		return true, ""
	}

	capIdx := Index(resourceHierarchy, capLevel)
	if capIdx < 0 {
		return false, fmt.Sprintf("delegation cap %q is not a known level in hierarchy %q",
			capLevel, resourceHierarchy)
	}

	if resourceIdx > capIdx {
		return false, fmt.Sprintf("resource classification %s exceeds delegation cap %s in hierarchy %q",
			resourceLevel, capLevel, resourceHierarchy)
	}
	return true, ""
}
