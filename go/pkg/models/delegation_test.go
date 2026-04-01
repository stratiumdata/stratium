package models

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDelegation_IsRoot(t *testing.T) {
	root := &Delegation{ParentDelegationID: nil}
	if !root.IsRoot() {
		t.Error("expected root delegation to return IsRoot() = true")
	}

	parentID := uuid.New()
	child := &Delegation{ParentDelegationID: &parentID}
	if child.IsRoot() {
		t.Error("expected child delegation to return IsRoot() = false")
	}
}

func TestDelegation_IsExpired(t *testing.T) {
	expired := &Delegation{ExpiresAt: time.Now().Add(-1 * time.Hour)}
	if !expired.IsExpired() {
		t.Error("expected expired delegation")
	}

	active := &Delegation{ExpiresAt: time.Now().Add(1 * time.Hour)}
	if active.IsExpired() {
		t.Error("expected active delegation")
	}
}

func TestDelegation_IsActive(t *testing.T) {
	active := &Delegation{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Revoked:   false,
	}
	if !active.IsActive() {
		t.Error("expected active delegation")
	}

	revoked := &Delegation{
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Revoked:   true,
	}
	if revoked.IsActive() {
		t.Error("expected revoked delegation to be inactive")
	}

	expired := &Delegation{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Revoked:   false,
	}
	if expired.IsActive() {
		t.Error("expected expired delegation to be inactive")
	}
}

func TestDelegation_HasTool(t *testing.T) {
	d := &Delegation{ApprovedTools: []string{"read", "write"}}
	if !d.HasTool("read") {
		t.Error("HasTool(read) should be true")
	}
	if d.HasTool("delete") {
		t.Error("HasTool(delete) should be false")
	}
}

func TestDelegation_HasActionTier(t *testing.T) {
	d := &Delegation{
		MaxActionTier:   ActionTierInternalModify,
		ApprovedActions: []ActionTier{ActionTierReadOnly, ActionTierInternalModify},
	}

	if !d.HasActionTier(ActionTierReadOnly) {
		t.Error("HasActionTier(ReadOnly) should be true")
	}
	if !d.HasActionTier(ActionTierInternalModify) {
		t.Error("HasActionTier(InternalModify) should be true")
	}
	if d.HasActionTier(ActionTierDestructive) {
		t.Error("HasActionTier(Destructive) should be false (exceeds max)")
	}
	if d.HasActionTier(ActionTierExternalComms) {
		t.Error("HasActionTier(ExternalComms) should be false (exceeds max)")
	}
}

func TestScopeNarrows_ValidChild(t *testing.T) {
	parent := &Delegation{
		ApprovedTools:      []string{"read", "write", "search"},
		ApprovedActions:    []ActionTier{ActionTierReadOnly, ActionTierInternalModify},
		MaxActionTier:      ActionTierInternalModify,
		ClassificationCaps: map[string]string{"nato": "SECRET"},
		ExpiresAt:          time.Now().Add(1 * time.Hour),
	}

	child := &Delegation{
		ApprovedTools:      []string{"read", "search"},
		ApprovedActions:    []ActionTier{ActionTierReadOnly},
		MaxActionTier:      ActionTierReadOnly,
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
		ExpiresAt:          time.Now().Add(30 * time.Minute),
	}

	if reason := ScopeNarrows(parent, child); reason != "" {
		t.Errorf("valid child scope should narrow, got: %s", reason)
	}
}

func TestScopeNarrows_ExceedsMaxActionTier(t *testing.T) {
	parent := &Delegation{
		MaxActionTier: ActionTierReadOnly,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	child := &Delegation{
		MaxActionTier: ActionTierDestructive,
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	reason := ScopeNarrows(parent, child)
	if reason == "" {
		t.Error("expected scope violation for max_action_tier")
	}
}

func TestScopeNarrows_ToolNotInParent(t *testing.T) {
	parent := &Delegation{
		ApprovedTools: []string{"read"},
		MaxActionTier: ActionTierInternalModify,
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}
	child := &Delegation{
		ApprovedTools: []string{"read", "send_email"},
		MaxActionTier: ActionTierReadOnly,
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}

	reason := ScopeNarrows(parent, child)
	if reason == "" {
		t.Error("expected scope violation for unapproved tool")
	}
}

func TestScopeNarrows_ExpiresAfterParent(t *testing.T) {
	parent := &Delegation{
		MaxActionTier: ActionTierReadOnly,
		ExpiresAt:     time.Now().Add(30 * time.Minute),
	}
	child := &Delegation{
		MaxActionTier: ActionTierReadOnly,
		ExpiresAt:     time.Now().Add(2 * time.Hour),
	}

	reason := ScopeNarrows(parent, child)
	if reason == "" {
		t.Error("expected scope violation for child expiring after parent")
	}
}

func TestScopeNarrows_ActionNotInParent(t *testing.T) {
	parent := &Delegation{
		ApprovedActions: []ActionTier{ActionTierReadOnly},
		MaxActionTier:   ActionTierReadOnly,
		ExpiresAt:       time.Now().Add(1 * time.Hour),
	}
	child := &Delegation{
		ApprovedActions: []ActionTier{ActionTierReadOnly, ActionTierInternalModify},
		MaxActionTier:   ActionTierReadOnly,
		ExpiresAt:       time.Now().Add(30 * time.Minute),
	}

	reason := ScopeNarrows(parent, child)
	if reason == "" {
		t.Error("expected scope violation for unapproved action")
	}
}
