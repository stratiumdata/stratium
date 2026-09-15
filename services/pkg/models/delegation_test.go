package models

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func validChild() *Delegation {
	return &Delegation{
		MaxActionTier:      ActionTierReadOnly,
		ApprovedTools:      []string{"Read"},
		ClassificationCaps: map[string]string{"nato": "RESTRICTED"},
		ExpiresAt:          testNow.Add(time.Minute),
	}
}

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
