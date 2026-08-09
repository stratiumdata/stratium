package authz

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

var authzNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func delegation(depth int, maxTier models.ActionTier, tools []string) *models.Delegation {
	return &models.Delegation{
		ID:            uuid.New(),
		Depth:         depth,
		MaxActionTier: maxTier,
		ApprovedTools: tools,
		ExpiresAt:     authzNow.Add(time.Hour),
	}
}

// linkChain wires the depth-linkage fields ValidateChain checks — tenant,
// root, parent pointers, and the acting agent — onto delegations built with
// delegation(), which only sets the fields DelegationLeg itself reads. Callers
// give each delegation its Depth via delegation()'s first argument; linkChain
// makes the slice a genuine lineage instead of unrelated delegations that
// merely sit next to each other, which is what ValidateChain now requires of
// any chain passed to Decide.
func linkChain(tenantID string, actingAgent uuid.UUID, ds ...*models.Delegation) []*models.Delegation {
	for i, d := range ds {
		d.TenantID = tenantID
		d.RootDelegationID = ds[0].ID
		if i > 0 {
			parent := ds[i-1].ID
			d.ParentDelegationID = &parent
		}
	}
	ds[len(ds)-1].AgentID = actingAgent
	return ds
}

func TestDelegationLeg_AllowsWithinScope(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierInternalModify, []string{"Read"})}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("within scope must allow, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

// MaxActionTier is an INCLUSIVE ceiling: an action exactly at it is allowed.
// Without this, flipping `>` to `>=` passes the whole suite and silently starts
// denying every action at its delegation's authorized limit.
func TestDelegationLeg_AllowsTierExactlyAtCeiling(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierExternalComms, nil)}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierExternalComms, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("tier exactly at the ceiling must be allowed, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

func TestDelegationLeg_DeniesTierAboveCeiling(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierReadOnly, []string{"Bash"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierDestructive, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("tier above ceiling must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesToolNotApproved(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierDestructive, []string{"Read"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("unapproved tool must deny, got %v", got.Effect)
	}
}

// Every hop is checked and the denying depth reported.
func TestDelegationLeg_ReportsDenyingDepth(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierDestructive, []string{"Bash"}),
		delegation(1, models.ActionTierDestructive, []string{"Bash"}),
		delegation(2, models.ActionTierReadOnly, []string{"Bash"}),
	}
	got, depth := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierExternalComms, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("must deny, got %v", got.Effect)
	}
	if depth != 2 {
		t.Fatalf("denial should be attributed to depth 2, got %d", depth)
	}
}

func TestDelegationLeg_DeniesExpiredHop(t *testing.T) {
	expired := delegation(1, models.ActionTierDestructive, []string{"Read"})
	expired.ExpiresAt = authzNow.Add(-time.Minute)
	chain := []*models.Delegation{delegation(0, models.ActionTierDestructive, []string{"Read"}), expired}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 1 {
		t.Fatalf("expired hop must deny at depth 1, got %v at %d", got.Effect, depth)
	}
}

// A revoked root denies every descendant. (C9)
func TestDelegationLeg_DeniesRevokedRoot(t *testing.T) {
	root := delegation(0, models.ActionTierDestructive, []string{"Read"})
	root.Revoked = true
	chain := []*models.Delegation{root, delegation(1, models.ActionTierReadOnly, []string{"Read"})}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 0 {
		t.Fatalf("revoked root must deny at depth 0, got %v at %d", got.Effect, depth)
	}
}

func TestDelegationLeg_DeniesOverMaxDepth(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierDestructive, nil),
		delegation(2, models.ActionTierDestructive, nil),
	}
	got, _ := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 1)
	if got.Effect != EffectDeny {
		t.Fatalf("chain over max depth must deny, got %v", got.Effect)
	}
}

// No delegation means nothing authorizes the action.
func TestDelegationLeg_DeniesEmptyChain(t *testing.T) {
	got, _ := DelegationLeg(nil, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("empty chain must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesClassificationAboveCap(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	resource := map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"}
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("resource above cap must deny, got %v", got.Effect)
	}
}

// The narrowest hop binds, even when it is not the last one.
func TestDelegationLeg_NarrowestHopBinds(t *testing.T) {
	chain := []*models.Delegation{
		delegation(0, models.ActionTierReadOnly, nil),
		delegation(1, models.ActionTierDestructive, nil),
	}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierInternalModify, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 0 {
		t.Fatalf("the narrowest hop must bind, got %v at %d", got.Effect, depth)
	}
}
