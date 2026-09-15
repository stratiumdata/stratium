package permset

import (
	"maps"
	"slices"

	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// Union returns the weakest Set containing every input: the permissions a
// holder of all of them would jointly have. The second return is one reason
// per dimension that had to be widened BEYOND an exact join, so an advisory
// report can say where it lost precision instead of quietly losing it.
//
// Union may over-approximate upward; Contains may not. See permset.go's
// package doc -- the resource-constraint rule below is sound only under that
// asymmetry, and a blocking caller of Union is a design change.
func Union(sets ...Set) (Set, []string) {
	if len(sets) == 0 {
		return Set{}, nil
	}

	out := Set{
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
	}
	var reasons []string

	// Tools: an empty list is unrestricted, which is the weakest possible
	// value, so it absorbs.
	unrestricted := false
	seen := map[string]bool{}
	for _, s := range sets {
		if len(s.Tools) == 0 {
			unrestricted = true
		}
		for _, t := range s.Tools {
			seen[t] = true
		}
	}
	if !unrestricted {
		out.Tools = slices.Sorted(maps.Keys(seen))
	}

	// MaxTier: the highest ceiling. ExpiresAt: the latest.
	for _, s := range sets {
		if s.MaxTier > out.MaxTier {
			out.MaxTier = s.MaxTier
		}
		if s.ExpiresAt.After(out.ExpiresAt) {
			out.ExpiresAt = s.ExpiresAt
		}
	}

	// EscalateAt: nil never escalates, which is weakest, so it absorbs;
	// otherwise the highest threshold escalates latest.
	neverEscalates := false
	var highest *models.ActionTier
	for _, s := range sets {
		if s.EscalateAt == nil {
			neverEscalates = true
			continue
		}
		if highest == nil || *s.EscalateAt > *highest {
			v := *s.EscalateAt
			highest = &v
		}
	}
	if !neverEscalates {
		out.EscalateAt = highest
	}

	// Caps: a hierarchy any member leaves uncapped is UNCAPPED in the union,
	// because that member's holder reaches it without restriction. Otherwise
	// the highest level wins.
	capped := map[string]bool{}
	for _, s := range sets {
		for h := range s.ClassificationCaps {
			capped[h] = true
		}
	}
	for h := range capped {
		var best string
		haveBest, all := false, true
		for _, s := range sets {
			lvl, ok := s.ClassificationCaps[h]
			if !ok {
				all = false
				break
			}
			if !haveBest || classificationIndexAtLeast(h, lvl, best) {
				best, haveBest = lvl, true
			}
		}
		if !all {
			reasons = append(reasons,
				"hierarchy "+h+" is capped by some members and not others, so the union is uncapped for it")
			continue
		}
		out.ClassificationCaps[h] = best
	}

	// Resource constraints. Values agree -> the value survives. Values
	// disagree -> unconstrained, named. A key only some members carry ->
	// unconstrained, named.
	//
	// ponytail: the union of "/workspace/" and "/tmp/" is not a prefix and
	// Set holds one string, so it widens to unconstrained. Upgrade path is a
	// prefix-set field on Set, worth taking only if this proves noisy in a
	// real report.
	keys := map[string]bool{}
	for _, s := range sets {
		for k := range s.ResourceConstraints {
			keys[k] = true
		}
	}
	for k := range keys {
		var val string
		haveVal, agree, present := false, true, true
		for _, s := range sets {
			v, ok := s.ResourceConstraints[k]
			if !ok {
				present = false
				break
			}
			if !haveVal {
				val, haveVal = v, true
			} else if v != val {
				agree = false
				reasons = append(reasons,
					"resource constraint "+k+" differs across members ("+val+" vs "+v+
						"), so the union is unconstrained for it")
				break
			}
		}
		if !present {
			reasons = append(reasons,
				"resource constraint "+k+" is set by some members and not others, so the union is unconstrained for it")
			continue
		}
		if agree {
			out.ResourceConstraints[k] = val
		}
	}

	return out, reasons
}

// classificationIndexAtLeast reports whether lvl ranks at or above best in
// hierarchy h. An unrankable level sorts as weakest here rather than
// denying: Union is advisory and must not fail, and a level neither side can
// rank cannot contribute a ceiling either way.
func classificationIndexAtLeast(h, lvl, best string) bool {
	return classification.Index(h, lvl) > classification.Index(h, best)
}
