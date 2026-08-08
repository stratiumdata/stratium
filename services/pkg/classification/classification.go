// Package classification is the single source for Stratium's classification
// hierarchies and per-hierarchy cap enforcement.
//
// Every rule here fails closed. The recurring attack this defends against is
// bypass-by-omission: a caller that leaves out an attribute, or supplies a
// level nobody recognizes, must be denied rather than slipping through a gap
// in the comparison.
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
//   - no resource classification               → allow (nothing to restrict)
//   - classification without a hierarchy       → DENY (ambiguous; the
//     bypass-by-omission case)
//   - no cap for the resource's hierarchy      → allow (this cap says nothing
//     about that hierarchy)
//   - unknown level or unknown cap             → DENY (never compare as equal)
//   - otherwise                                → resource rank ≤ cap rank
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
		return true, ""
	}
	if resourceHierarchy == "" {
		return false, "resource classification declared without a hierarchy attribute (ambiguous)"
	}

	capLevel, hasCap := caps[strings.ToLower(resourceHierarchy)]
	if !hasCap {
		// Caps are stored as the caller supplied them; try the original casing.
		capLevel, hasCap = caps[resourceHierarchy]
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
