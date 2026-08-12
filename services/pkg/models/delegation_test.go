package models

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func parentDelegation() *Delegation {
	return &Delegation{
		MaxActionTier:      ActionTierInternalModify,
		ApprovedTools:      []string{"Read", "Write"},
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
		ExpiresAt:          testNow.Add(time.Hour),
	}
}

func validChild() *Delegation {
	return &Delegation{
		MaxActionTier:      ActionTierReadOnly,
		ApprovedTools:      []string{"Read"},
		ClassificationCaps: map[string]string{"nato": "RESTRICTED"},
		ExpiresAt:          testNow.Add(time.Minute),
	}
}

func TestScopeNarrows_ValidChild(t *testing.T) {
	if reason := ScopeNarrows(parentDelegation(), validChild()); reason != "" {
		t.Fatalf("a strictly narrower child must be accepted, got: %s", reason)
	}
}

// An identical child is a valid subset — narrowing is "no wider", not "strictly narrower".
func TestScopeNarrows_IdenticalChildAccepted(t *testing.T) {
	p := parentDelegation()
	c := parentDelegation()
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("an identical child must be accepted, got: %s", reason)
	}
}

func TestScopeNarrows_RejectsWiderTier(t *testing.T) {
	c := validChild()
	c.MaxActionTier = ActionTierDestructive
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child max_action_tier above parent must be rejected")
	}
}

func TestScopeNarrows_RejectsExtraTool(t *testing.T) {
	c := validChild()
	c.ApprovedTools = []string{"Read", "Bash"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child tool outside the parent set must be rejected")
	}
}

// The defect in the previous implementation: cap levels were never compared.
func TestScopeNarrows_RejectsWidenedClassificationCap(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "TOP-SECRET"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child widening nato CONFIDENTIAL -> TOP-SECRET must be rejected")
	}
}

func TestScopeNarrows_AcceptsNarrowedClassificationCap(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "UNCLASSIFIED"}
	if reason := ScopeNarrows(parentDelegation(), c); reason != "" {
		t.Fatalf("narrowing a cap must be accepted, got: %s", reason)
	}
}

func TestScopeNarrows_RejectsCapForHierarchyParentLacks(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "RESTRICTED", "commercial": "PUBLIC"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("a cap on a hierarchy the parent does not cap must be rejected")
	}
}

// An unrecognized level must deny rather than compare as equal.
func TestScopeNarrows_RejectsUnknownChildLevel(t *testing.T) {
	c := validChild()
	c.ClassificationCaps = map[string]string{"nato": "ULTRA-MEGA-SECRET"}
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("unknown child cap level must be rejected")
	}
}

func TestScopeNarrows_RejectsUnknownParentLevel(t *testing.T) {
	p := parentDelegation()
	p.ClassificationCaps = map[string]string{"nato": "NOT-A-LEVEL"}
	c := validChild()
	if ScopeNarrows(p, c) == "" {
		t.Fatal("unknown parent cap level must be rejected")
	}
}

func TestScopeNarrows_RejectsLongerExpiry(t *testing.T) {
	c := validChild()
	c.ExpiresAt = testNow.Add(2 * time.Hour)
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("child outliving its parent must be rejected")
	}
}

// Omitting a cap is a widening, not an inheritance. At decision time CheckCap
// treats absent caps as no restriction, so a child that drops the map holds
// unrestricted classification access — the same outcome as widening an entry,
// reached by a different route.
func TestScopeNarrows_RejectsChildOmittingParentCap(t *testing.T) {
	for name, caps := range map[string]map[string]string{
		"nil":                  nil,
		"empty":                {},
		"other-hierarchy-only": {"commercial": "PUBLIC"},
	} {
		t.Run(name, func(t *testing.T) {
			c := validChild()
			c.ClassificationCaps = caps
			if ScopeNarrows(parentDelegation(), c) == "" {
				t.Fatalf("child with %s caps under a capped parent must be rejected", name)
			}
		})
	}
}

// Resource constraints may only be added. Dropping one, or changing its value,
// widens what the child may reach.
func TestScopeNarrows_RejectsDroppedResourceConstraint(t *testing.T) {
	p := parentDelegation()
	p.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	for name, res := range map[string]map[string]string{
		"nil":      nil,
		"empty":    {},
		"partial":  {"project": "alpha"},
		"altered":  {"project": "beta", "region": "us-east"},
		"wildcard": {"project": "*", "region": "us-east"},
	} {
		t.Run(name, func(t *testing.T) {
			c := validChild()
			c.ResourceConstraints = res
			if ScopeNarrows(p, c) == "" {
				t.Fatalf("child with %s resource constraints must be rejected", name)
			}
		})
	}
}

// A child may not introduce a constraint on a key the parent leaves open, even
// though doing so narrows. Spec §4.3.1 rules that a child narrows dimensions
// its parent constrains and introduces none of its own, so a chain is audited
// by comparing values across a fixed set of dimensions. This mirrors
// TestScopeNarrows_RejectsCapForHierarchyParentLacks; the two dimensions
// disagreed until the ruling, and this test is the half that changed.
func TestScopeNarrows_RejectsAddedResourceConstraint(t *testing.T) {
	p := parentDelegation()
	p.ResourceConstraints = map[string]string{"project": "alpha"}
	c := validChild()
	c.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	if ScopeNarrows(p, c) == "" {
		t.Fatal("child constraining a key the parent leaves open must be rejected")
	}
}

// The corollary: a child repeating exactly its parent's constraint keys, with
// exactly its parent's values, is valid. Without this the rule above could be
// satisfied by rejecting every non-empty constraint map.
func TestScopeNarrows_AcceptsIdenticalResourceConstraints(t *testing.T) {
	p := parentDelegation()
	p.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	c := validChild()
	c.ResourceConstraints = map[string]string{"project": "alpha", "region": "us-east"}
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("identical constraints must be accepted, got: %s", reason)
	}
}

// An empty parent tool list means unrestricted, so any child list is a subset.
func TestScopeNarrows_EmptyParentToolsIsUnrestricted(t *testing.T) {
	p := parentDelegation()
	p.ApprovedTools = nil
	c := validChild()
	c.ApprovedTools = []string{"Anything"}
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("unrestricted parent must accept any child tools, got: %s", reason)
	}
}

// A child with no tool restriction under a restricted parent is a widening.
func TestScopeNarrows_RejectsUnrestrictedChildUnderRestrictedParent(t *testing.T) {
	c := validChild()
	c.ApprovedTools = nil
	if ScopeNarrows(parentDelegation(), c) == "" {
		t.Fatal("an unrestricted child under a restricted parent is a widening")
	}
}

// --- escalate_at narrowing (spec §4.3.1) ---

// Escalating sooner is narrower: a child threshold at or below its parent's
// is a valid subset, symmetric with TestScopeNarrows_ValidChild for tier.
func TestScopeNarrows_AcceptsLoweredEscalateAt(t *testing.T) {
	p := parentDelegation()
	parentThreshold := ActionTierReadOnly // parent ceiling is INTERNAL_MODIFY (2)
	p.EscalateAt = &parentThreshold
	c := validChild()
	childThreshold := ActionTierReasoning // child ceiling is READ_ONLY (1)
	c.EscalateAt = &childThreshold
	if reason := ScopeNarrows(p, c); reason != "" {
		t.Fatalf("a child lowering escalate_at must be accepted, got: %s", reason)
	}
}

// The inverse of lowering: a child that escalates later than its parent has
// widened the all-outright-allow band, exactly as a raised max_action_tier
// would (TestScopeNarrows_RejectsWiderTier).
func TestScopeNarrows_RejectsRaisedEscalateAt(t *testing.T) {
	p := parentDelegation()
	parentThreshold := ActionTierReasoning
	p.EscalateAt = &parentThreshold
	c := validChild()
	childThreshold := ActionTierReadOnly // 1 > parent's 0
	c.EscalateAt = &childThreshold
	if ScopeNarrows(p, c) == "" {
		t.Fatal("child escalate_at above parent's must be rejected")
	}
}

// A parent that never escalates leaves the dimension open; a child may not
// close it. Mirrors TestScopeNarrows_RejectsCapForHierarchyParentLacks — same
// §4.3.1 rule, applied to the one dimension that is a single optional value
// instead of a map.
func TestScopeNarrows_RejectsIntroducedEscalateAt(t *testing.T) {
	p := parentDelegation() // EscalateAt left nil: parent never escalates
	c := validChild()
	childThreshold := ActionTierReasoning
	c.EscalateAt = &childThreshold
	if ScopeNarrows(p, c) == "" {
		t.Fatal("child introducing escalate_at where parent has none must be rejected")
	}
}

// The corollary: a child cannot shed a threshold its parent imposed by
// simply leaving the field nil. Mirrors
// TestScopeNarrows_RejectsChildOmittingParentCap — omission is a widening,
// not an inheritance, for escalate_at exactly as it is for classification
// caps.
func TestScopeNarrows_RejectsDroppedEscalateAt(t *testing.T) {
	p := parentDelegation()
	parentThreshold := ActionTierReadOnly
	p.EscalateAt = &parentThreshold
	c := validChild() // EscalateAt left nil
	if ScopeNarrows(p, c) == "" {
		t.Fatal("child dropping parent's escalate_at must be rejected")
	}
}

// --- lifecycle ---

func TestDelegation_IsActive(t *testing.T) {
	d := validChild()
	if !d.IsActive(testNow) {
		t.Error("a live delegation must be active")
	}
	d.Revoked = true
	if d.IsActive(testNow) {
		t.Error("a revoked delegation must not be active")
	}
	d.Revoked = false
	if d.IsActive(testNow.Add(time.Hour)) {
		t.Error("an expired delegation must not be active")
	}
}

func TestDelegation_HasTool(t *testing.T) {
	d := &Delegation{ApprovedTools: []string{"Read"}}
	if !d.HasTool("Read") {
		t.Error("an approved tool must be reported present")
	}
	if d.HasTool("Bash") {
		t.Error("an unapproved tool must be reported absent")
	}
	empty := &Delegation{}
	if !empty.HasTool("Anything") {
		t.Error("an empty tool list means unrestricted")
	}
}
