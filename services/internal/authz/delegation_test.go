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

// --- escalation band ---
//
// EscalateAt's pointer form is built with tierPtr (tier_test.go) throughout,
// the same helper DeclaredTier's tests already use for the same reason: both
// fields distinguish "unset" from a real zero-valued tier, and construction
// via &t inline would need its own addressable local at every call site
// instead.

// Every boundary of the closed band [EscalateAt, MaxActionTier], each pinned
// by its own case so a one-off comparison mutation (< for <=, or vice versa)
// fails exactly the case that exercises it rather than being masked by a
// neighboring one. One below the threshold falls outside the band on the low
// side — this leg has no opinion, so nothing here raises it above ALLOW;
// TestDelegationLeg_UnsetEscalateAtNeverEscalates below covers "no
// threshold" as its own, separate property.
func TestDelegationLeg_EscalationBandBoundaries(t *testing.T) {
	threshold := models.ActionTierReadOnly    // 1
	ceiling := models.ActionTierExternalComms // 3
	tests := []struct {
		name string
		tier models.ActionTier
		want Effect
	}{
		{"one below the threshold allows", models.ActionTierReasoning, EffectAllow},             // 0 < 1
		{"exactly at the threshold escalates", models.ActionTierReadOnly, EffectEscalate},       // 1 == 1
		{"strictly inside the band escalates", models.ActionTierInternalModify, EffectEscalate}, // 2
		{"exactly at the ceiling escalates", models.ActionTierExternalComms, EffectEscalate},    // 3 == 3, still <= max
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := delegation(0, ceiling, nil)
			d.EscalateAt = tierPtr(threshold)
			got, depth := DelegationLeg([]*models.Delegation{d}, Action{}, tt.tier, nil, authzNow, 5)
			if got.Effect != tt.want {
				t.Fatalf("tier %s: effect = %v, want %v (%s)", tt.tier, got.Effect, tt.want, got.Reason)
			}
			if tt.want == EffectEscalate && depth != -1 {
				t.Fatalf("escalate is not a denial: depth = %d, want -1", depth)
			}
		})
	}
}

// One tier above the ceiling denies outright — the mirror image of
// TestDelegationLeg_AllowsTierExactlyAtCeiling, and distinct from
// TestDelegationLeg_DeniesTierAboveCeiling (which uses a tier several steps
// above, not the exact boundary).
func TestDelegationLeg_DeniesTierOneAboveCeiling(t *testing.T) {
	ceiling := models.ActionTierExternalComms // 3
	d := delegation(0, ceiling, nil)
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, models.ActionTierDestructive, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("tier one above the ceiling must deny, got %v", got.Effect)
	}
}

// Deny overrides escalate even when the SAME hop's own threshold is also
// met: a tier above the ceiling denies whether or not it also sits at or
// above escalate_at (the brief's own worked example). Distinct from
// TestDelegationLeg_DeniesTierOneAboveCeiling above, which sets no
// EscalateAt at all and so cannot tell "the ceiling denies" apart from "the
// ceiling denies AND overrides an active escalate condition" — only this
// test can catch a mutation that lets escalate win once both conditions are
// true on one hop.
func TestDelegationLeg_DenyBeatsEscalateOnSameHop(t *testing.T) {
	ceiling := models.ActionTierExternalComms // 3
	d := delegation(0, ceiling, nil)
	d.EscalateAt = tierPtr(models.ActionTierReadOnly) // 1: comfortably below the tier tested
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, models.ActionTierDestructive, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("deny must beat escalate even when both conditions are met on the same hop, got %v", got.Effect)
	}
}

// Deny overrides escalate across hops, too: the root escalates on its own
// terms, but a deeper hop denies for an unrelated reason (here, revocation),
// and the deny must still win. This is what actually exercises
// DelegationLeg's "record, don't return" design — a mutation that made the
// escalate check return immediately instead of continuing the loop would
// pass TestDelegationLeg_DenyBeatsEscalateOnSameHop (that case never reaches
// the escalate line at all, since the same hop's own deny check returns
// first) but fail here.
func TestDelegationLeg_DenyAtDeeperHopOverridesEarlierEscalate(t *testing.T) {
	root := delegation(0, models.ActionTierExternalComms, nil)
	root.EscalateAt = tierPtr(models.ActionTierReadOnly)
	child := delegation(1, models.ActionTierExternalComms, nil)
	child.Revoked = true // denies for a reason with nothing to do with tier or threshold

	chain := []*models.Delegation{root, child}
	got, depth := DelegationLeg(chain, Action{}, models.ActionTierReadOnly, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("a deny at a deeper hop must override an escalate recorded at an earlier hop, got %v", got.Effect)
	}
	if depth != 1 {
		t.Fatalf("denial should be attributed to depth 1, got %d", depth)
	}
}

// An unset threshold never escalates, at any tier — including tier 0, which
// is the exact value a "treat nil as REASONING" mutation would substitute
// for it. That mutation would make EVERY tier escalate (0 <= anything), so
// any one of these tiers catches it, but all three are asserted so the
// property reads as "never," not "not at this one arbitrary tier."
func TestDelegationLeg_UnsetEscalateAtNeverEscalates(t *testing.T) {
	ceiling := models.ActionTierExternalComms
	for _, tier := range []models.ActionTier{
		models.ActionTierReasoning, models.ActionTierInternalModify, ceiling,
	} {
		t.Run(tier.String(), func(t *testing.T) {
			d := delegation(0, ceiling, nil) // EscalateAt left nil
			got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, tier, nil, authzNow, 5)
			if got.Effect == EffectEscalate {
				t.Fatalf("an unset threshold must never escalate, got %v at tier %s", got.Effect, tier)
			}
		})
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
