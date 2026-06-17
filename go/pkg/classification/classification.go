// Package classification is the canonical source for Stratium's classification
// hierarchies and per-hierarchy cap enforcement. It consolidates logic that was
// previously duplicated in services/agent-gateway and services/pap.
package classification

import (
	"fmt"
	"strings"
)

// Levels are the canonical ordered hierarchies (low → high).
var Levels = map[string][]string{
	"nato":       {"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP-SECRET"},
	"commercial": {"PUBLIC", "INTERNAL", "CONFIDENTIAL-COMMERCIAL", "RESTRICTED-COMMERCIAL", "HIGHLY-CONFIDENTIAL"},
}

// Index returns the integer rank of a level within a hierarchy (case-insensitive),
// or -1 if the hierarchy or level is unknown.
func Index(hierarchy, level string) int {
	levels, ok := Levels[strings.ToLower(hierarchy)]
	if !ok {
		return -1
	}
	for i, lvl := range levels {
		if strings.EqualFold(lvl, level) {
			return i
		}
	}
	return -1
}

// CheckCap enforces a delegation's per-hierarchy classification caps against the
// resource being accessed. Semantics (fail-closed on ambiguity/unknowns):
//   - No caps → allow.
//   - No resource classification declared → allow.
//   - Classification declared but no hierarchy → DENY (ambiguous; prevents bypass by omission).
//   - Cap exists for the resource's hierarchy → enforce resource_level ≤ cap_level.
//   - No cap for the resource's hierarchy → allow.
//   - Unknown hierarchy/level/cap → DENY with reason.
func CheckCap(caps map[string]string, resourceAttrs map[string]string) (bool, string) {
	if len(caps) == 0 {
		return true, ""
	}

	// Treat empty-string values the same as absent keys. A caller that always
	// inserts the keys (e.g. building the map from request fields that may be
	// empty) must not be able to bypass the ambiguity-deny below by supplying an
	// empty hierarchy alongside a non-empty classification.
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
		// Try original case as fallback (caps are stored as-supplied by caller).
		capLevel, hasCap = caps[resourceHierarchy]
	}
	if !hasCap {
		return true, ""
	}

	resourceIdx := Index(resourceHierarchy, resourceLevel)
	if resourceIdx < 0 {
		return false, fmt.Sprintf("unknown classification level %q for hierarchy %q",
			resourceLevel, resourceHierarchy)
	}
	capIdx := Index(resourceHierarchy, capLevel)
	if capIdx < 0 {
		return false, fmt.Sprintf("delegation cap %q is not a known level in hierarchy %q",
			capLevel, resourceHierarchy)
	}

	if resourceIdx > capIdx {
		return false, fmt.Sprintf("resource classification %s exceeds delegation cap %s (hierarchy %q)",
			resourceLevel, capLevel, resourceHierarchy)
	}
	return true, ""
}
