package permset

import (
	"strings"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// Contains reports whether inner is a valid subset of outer, returning the
// empty string when it is and a reason naming the first violated dimension
// when it is not. The empty-means-valid convention is models.ScopeNarrows's,
// whose behaviour this reproduces exactly -- including the two rules that are
// NOT lattice containment:
//
//   - EscalateAt presence must MATCH. A child may neither introduce the field
//     where the parent leaves it unset nor drop it where the parent sets it.
//     Dropping is a widening. Introducing narrows, and is rejected anyway.
//   - ResourceConstraints may not be INTRODUCED either, by the same rule and
//     for the same reason.
//
// Both are stricter than pointwise ordering requires, both are deliberate
// (spec section 4.3.1), and a clean lattice would quietly permit what they
// forbid. Do not "fix" either without reading contains_test.go's
// EscalateAtPresenceIsAsymmetric case first.
func Contains(outer, inner Set) string {
	if inner.MaxTier > outer.MaxTier {
		return "child max_action_tier " + inner.MaxTier.String() +
			" exceeds parent " + outer.MaxTier.String()
	}

	// EscalateAt narrows in the opposite direction from a first guess: a
	// LOWER threshold escalates sooner, so lowering it narrows and raising it
	// widens. Every branch guards both pointers explicitly rather than
	// relying on the preceding cases having excluded one being nil, so this
	// stays safe if the cases are ever reordered.
	switch {
	case outer.EscalateAt == nil && inner.EscalateAt != nil:
		return "child introduces escalate_at " + inner.EscalateAt.String() +
			" which parent leaves unset"
	case outer.EscalateAt != nil && inner.EscalateAt == nil:
		return "child drops parent escalate_at " + outer.EscalateAt.String()
	case outer.EscalateAt != nil && inner.EscalateAt != nil && *inner.EscalateAt > *outer.EscalateAt:
		return "child escalate_at " + inner.EscalateAt.String() +
			" exceeds parent " + outer.EscalateAt.String()
	}

	// An empty outer list is unrestricted; an empty inner list under a
	// restricted outer is a widening, not an inheritance.
	if len(outer.Tools) > 0 {
		if len(inner.Tools) == 0 {
			return "child has no tool restriction while parent restricts tools"
		}
		allowed := make(map[string]bool, len(outer.Tools))
		for _, t := range outer.Tools {
			allowed[t] = true
		}
		for _, t := range inner.Tools {
			if !allowed[t] {
				return "child tool " + t + " not in parent approved_tools"
			}
		}
	}

	// Iterate the OUTER's caps. A hierarchy outer restricts and inner omits
	// is a widening: CheckCap treats absent caps as "no restriction", so
	// inner would hold unrestricted access to that hierarchy.
	for hierarchy, outerCap := range outer.ClassificationCaps {
		innerCap, ok := inner.ClassificationCaps[hierarchy]
		if !ok {
			return "child does not cap hierarchy " + hierarchy +
				" which parent caps at " + outerCap
		}
		innerIdx := classification.Index(hierarchy, innerCap)
		if innerIdx < 0 {
			return "child cap " + innerCap + " is not a known level in hierarchy " + hierarchy
		}
		outerIdx := classification.Index(hierarchy, outerCap)
		if outerIdx < 0 {
			return "parent cap " + outerCap + " is not a known level in hierarchy " + hierarchy
		}
		if innerIdx > outerIdx {
			return "child cap " + innerCap + " exceeds parent cap " + outerCap +
				" in hierarchy " + hierarchy
		}
	}
	for hierarchy := range inner.ClassificationCaps {
		if _, ok := outer.ClassificationCaps[hierarchy]; !ok {
			return "child caps hierarchy " + hierarchy + " which parent does not cap"
		}
	}

	// Values are opaque caller-defined strings, so the comparison is exact --
	// it does not reason about wildcards or ranges, because every such
	// interpretation is a place a widening could hide. ResourceIDPrefixKey is
	// the one exception: it has prefix semantics, so it narrows by
	// containment. HasPrefix is sufficient ONLY because a stored prefix
	// always ends in "/" (validated at write time) -- without that, parent
	// "/workspace" would accept child "/workspace-evil/" as a narrowing.
	for key, outerVal := range outer.ResourceConstraints {
		innerVal, ok := inner.ResourceConstraints[key]
		if !ok {
			return "child drops parent resource constraint " + key + "=" + outerVal
		}
		if key == models.ResourceIDPrefixKey {
			if !strings.HasPrefix(innerVal, outerVal) {
				return "child resource constraint " + key + "=" + innerVal +
					" is not within parent " + key + "=" + outerVal
			}
			continue
		}
		if innerVal != outerVal {
			return "child resource constraint " + key + "=" + innerVal +
				" differs from parent " + key + "=" + outerVal
		}
	}
	for key := range inner.ResourceConstraints {
		if _, ok := outer.ResourceConstraints[key]; !ok {
			return "child constrains resource key " + key + " which parent does not constrain"
		}
	}

	if inner.ExpiresAt.After(outer.ExpiresAt) {
		return "child expires_at exceeds parent"
	}

	return ""
}
