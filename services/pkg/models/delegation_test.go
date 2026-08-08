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
