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
// Rules, each fail-closed:
//   - no caps                                  → allow (no restriction declared)
//   - no resource classification               → DENY (a configured cap
//     cannot be evaluated against a resource that says nothing about its
//     classification; unenforceable must not read as compliant)
//   - classification without a hierarchy       → DENY (ambiguous; the
//     bypass-by-omission case)
//   - no cap for the resource's hierarchy      → allow (this cap says nothing
//     about that hierarchy)
//   - unknown level or unknown cap             → DENY (never compare as equal)
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
	resourceLevel := resourceAttrs["classification"]
	resourceHierarchy := resourceAttrs["hierarchy"]

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

	capLevel, hasCap, ambiguous := lookupCap(caps, resourceHierarchy)
	if ambiguous {
		return false, fmt.Sprintf(
			"conflicting caps for hierarchy %q (keys differing only by case carry different levels)",
			resourceHierarchy)
	}
	if !hasCap {
		return true, ""
	}

	resourceIdx := Index(resourceHierarchy, resourceLevel)
	if resourceIdx < 0 {
		return false, fmt.Sprintf("unknown classification level %q in hierarchy %q",
			resourceLevel, resourceHierarchy)
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
