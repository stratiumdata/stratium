package authz

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

var authzNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func delegation(depth int, maxTier models.ActionTier, tools []string) *models.Delegation {
	return &models.Delegation{
		ID:            uuid.New(),
		UserID:        "alice@example.com", // request()'s principal (compound_test.go)
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
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
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
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierExternalComms, nil, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("tier exactly at the ceiling must be allowed, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

func TestDelegationLeg_DeniesTierAboveCeiling(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierReadOnly, []string{"Bash"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierDestructive, nil, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("tier above ceiling must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesToolNotApproved(t *testing.T) {
	chain := []*models.Delegation{delegation(0, models.ActionTierDestructive, []string{"Read"})}
	got, _ := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
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
	got, depth := DelegationLeg(chain, Action{Tool: "Bash"}, models.ActionTierExternalComms, nil, nil, authzNow, 5)
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
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 1 {
		t.Fatalf("expired hop must deny at depth 1, got %v at %d", got.Effect, depth)
	}
}

// A revoked root denies every descendant. (C9)
func TestDelegationLeg_DeniesRevokedRoot(t *testing.T) {
	root := delegation(0, models.ActionTierDestructive, []string{"Read"})
	root.Revoked = true
	chain := []*models.Delegation{root, delegation(1, models.ActionTierReadOnly, []string{"Read"})}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
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
	got, _ := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, nil, authzNow, 1)
	if got.Effect != EffectDeny {
		t.Fatalf("chain over max depth must deny, got %v", got.Effect)
	}
}

// No delegation means nothing authorizes the action.
func TestDelegationLeg_DeniesEmptyChain(t *testing.T) {
	got, _ := DelegationLeg(nil, Action{Tool: "Read"}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("empty chain must deny, got %v", got.Effect)
	}
}

func TestDelegationLeg_DeniesClassificationAboveCap(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	resource := map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"}
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("resource above cap must deny, got %v", got.Effect)
	}
}

// R2's behaviour change made concrete at the leg an operator actually calls
// through: a delegation with a classification cap configured now denies a
// resource that declares no classification at all, not only one that
// exceeds the cap. Distinct from TestDelegationLeg_DeniesClassificationAboveCap
// above -- that resource carries a classification and is rejected for being
// too high; this one carries none and is rejected because the cap cannot be
// evaluated, which pkg/classification's own tests establish is a different
// reason string, not just a different fixture.
func TestDelegationLeg_DeniesConfiguredCapWhenResourceHasNoClassification(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}
	resource := map[string]string{"id": "doc-9000"} // identity, but no classification at all
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("a configured cap against an unlabelled resource must deny, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to depth 0, got %d", depth)
	}
}

// Boundary proving R2 is targeted, not a blanket tightening -- the leg-level
// mirror of TestDelegationLeg_EmptyResourceConstraintsUnaffected, which
// defends the same shape of boundary for ResourceConstraints. A delegation
// with no classification caps at all is unaffected by this phase regardless
// of what the resource does or does not declare.
func TestDelegationLeg_NoClassificationCapsUnaffectedByUnlabelledResource(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	// d.ClassificationCaps left nil.
	resource := map[string]string{"id": "doc-9000"} // no classification, no hierarchy
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("no configured caps must allow regardless of resource classification, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
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
			got, depth := DelegationLeg([]*models.Delegation{d}, Action{}, tt.tier, nil, nil, authzNow, 5)
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
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, models.ActionTierDestructive, nil, nil, authzNow, 5)
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
	got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, models.ActionTierDestructive, nil, nil, authzNow, 5)
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
	got, depth := DelegationLeg(chain, Action{}, models.ActionTierReadOnly, nil, nil, authzNow, 5)
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
			got, _ := DelegationLeg([]*models.Delegation{d}, Action{}, tier, nil, nil, authzNow, 5)
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
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierInternalModify, nil, nil, authzNow, 5)
	if got.Effect != EffectDeny || depth != 0 {
		t.Fatalf("the narrowest hop must bind, got %v at %d", got.Effect, depth)
	}
}

// --- resource constraints ---
//
// Values throughout are distinguishable on sight -- "alpha-team" vs.
// "zzz-other-team", never "value1" vs "value2" -- so a mixup (comparing the
// wrong two strings, or asserting the wrong Effect) reads as obviously wrong
// rather than accidentally passing.

// The load-bearing rule: a constrained key the request never mentions must
// deny, even though the request otherwise carries some resource identity.
// Silently passing here would recreate, for identity, exactly the CheckCap
// defect (an absent attribute read as "nothing to restrict") this phase
// exists to fix. The resource map is non-empty on purpose -- it carries
// "id" but not the constrained "project" key -- so this test cannot be
// satisfied by a mutation that only special-cases a wholly empty resource
// map; see TestDelegationLeg_DeniesWhenRequestResourceMapIsEmpty for that
// distinct case.
func TestDelegationLeg_DeniesResourceConstraintAbsentFromRequest(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	resource := map[string]string{"id": "doc-9000"} // carries identity, but never "project"
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("a constrained key absent from the request must deny, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to depth 0, got %d", depth)
	}
}

// The load-bearing rule's most extreme form: skipping the check entirely
// because the request's whole resource map is empty would be a fail-open,
// not an edge case -- an agent that supplies no resource identity at all
// must not thereby escape every constraint on it. Distinct from the test
// above: that one proves per-key absence denies; this one proves the check
// does not short-circuit on an empty map before ever reaching the loop.
func TestDelegationLeg_DeniesWhenRequestResourceMapIsEmpty(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, nil, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("an empty request resource map under a constrained delegation must deny, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to depth 0, got %d", depth)
	}
}

// A constrained key present with a different value denies.
func TestDelegationLeg_DeniesResourceConstraintMismatch(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	resource := map[string]string{"project": "zzz-other-team"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("a mismatched resource constraint must deny, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to depth 0, got %d", depth)
	}
}

// Comparison is exact, not a prefix match: a request value that merely
// starts with the required value must still deny. A `strings.HasPrefix`
// mutation of the equality check would pass this pair ("alpha-team" is a
// prefix of "alpha-team-2") while every equality-based test above stays
// green, so this is the only case that catches it.
func TestDelegationLeg_ResourceConstraintComparisonIsExactNotPrefix(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	resource := map[string]string{"project": "alpha-team-2"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("a request value that only shares a prefix with the required value must deny, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to depth 0, got %d", depth)
	}
}

// A constrained key present with the exact matching value passes.
func TestDelegationLeg_AllowsResourceConstraintExactMatch(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	resource := map[string]string{"project": "alpha-team"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("an exact-matching resource constraint must allow, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

// A delegation whose constraints are all satisfied still passes, across
// more than one constrained key -- proving the loop does not stop early on
// the first satisfied key and does not accidentally flip to deny once a
// second key is added.
func TestDelegationLeg_AllowsWhenAllResourceConstraintsSatisfied(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team", "environment": "staging-east"}
	resource := map[string]string{"project": "alpha-team", "environment": "staging-east"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("fully satisfied resource constraints must allow, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

// Extra request attributes the delegation does not constrain are ignored --
// a constraint set is a filter, not a schema. "id" here is a realistic
// attribute PEP extraction adds (cmd/stratium-pep/resource.go) that this
// delegation never mentions.
func TestDelegationLeg_IgnoresUnconstrainedResourceAttributes(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	d.ResourceConstraints = map[string]string{"project": "alpha-team"}
	resource := map[string]string{"project": "alpha-team", "id": "doc-9000", "type": "file"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("unconstrained extra resource attributes must not affect the decision, got %v: %s",
			got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

// Boundary proving the change is targeted, not a blanket tightening: a
// delegation with an empty (nil) constraint map is unaffected by this check
// regardless of what the request's resource map holds, matching
// Delegation.HasTool's treatment of an empty approved-tools list. Every
// pre-existing test in this file already relies on this implicitly (none
// sets ResourceConstraints), but this is the one that names the property
// and would fail on its own if a mutation flipped empty-map handling.
func TestDelegationLeg_EmptyResourceConstraintsUnaffected(t *testing.T) {
	d := delegation(0, models.ActionTierDestructive, []string{"Read"})
	// d.ResourceConstraints left nil.
	resource := map[string]string{"project": "whatever-the-agent-happens-to-send"}
	got, depth := DelegationLeg([]*models.Delegation{d}, Action{Tool: "Read"},
		models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("an empty constraint map must be unrestricted, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

// At depth: every hop is checked, not only the acting (last) one. A parent
// hop's constraint that the request fails to satisfy denies even though the
// acting child hop carries no resource constraint at all -- a shape
// CreateDelegation's ScopeNarrows check would never let onto the write path
// (a child may not drop a parent's resource constraint), but DelegationLeg
// does not call ScopeNarrows and must not depend on it having run. This is
// the concrete evidence for walking the whole chain rather than trusting
// the acting hop alone: a mutation that checked only chain[len(chain)-1]
// would pass every other resource-constraint test in this file (their acting
// hop IS the constrained one) but fail exactly here.
func TestDelegationLeg_AncestorResourceConstraintBindsEvenWhenActingHopIsUnconstrained(t *testing.T) {
	root := delegation(0, models.ActionTierDestructive, nil)
	root.ResourceConstraints = map[string]string{"project": "alpha-team"}
	child := delegation(1, models.ActionTierDestructive, nil) // ResourceConstraints left nil

	chain := []*models.Delegation{root, child}
	resource := map[string]string{"project": "zzz-other-team"}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectDeny {
		t.Fatalf("an unsatisfied ancestor resource constraint must deny even at depth, got %v", got.Effect)
	}
	if depth != 0 {
		t.Fatalf("denial should be attributed to the ancestor at depth 0, got %d", depth)
	}
}

// The realistic counterpart to the test above: a multi-hop chain shaped the
// way CreateDelegation's ScopeNarrows actually requires (resource
// constraints identical at every hop, since ScopeNarrows treats them as
// neither droppable nor alterable, not merely narrowable) still allows when
// the request satisfies them.
func TestDelegationLeg_AllowsMultiHopChainWithMatchingResourceConstraints(t *testing.T) {
	constraints := map[string]string{"project": "alpha-team"}
	root := delegation(0, models.ActionTierDestructive, nil)
	root.ResourceConstraints = constraints
	child := delegation(1, models.ActionTierDestructive, nil)
	child.ResourceConstraints = constraints

	chain := []*models.Delegation{root, child}
	resource := map[string]string{"project": "alpha-team"}
	got, depth := DelegationLeg(chain, Action{Tool: "Read"}, models.ActionTierReadOnly, resource, nil, authzNow, 5)
	if got.Effect != EffectAllow {
		t.Fatalf("a satisfied constraint identical at every hop must allow, got %v: %s", got.Effect, got.Reason)
	}
	if depth != -1 {
		t.Fatalf("no denial expected, got depth %d", depth)
	}
}

func TestCheckResourceConstraints_IDPrefix(t *testing.T) {
	constraints := map[string]string{models.ResourceIDPrefixKey: "/workspace/"}

	t.Run("every id inside satisfies", func(t *testing.T) {
		ok, reason := checkResourceConstraints(constraints, map[string]string{},
			[]string{"/workspace/a.txt", "/workspace/b.txt"}, "")
		if !ok {
			t.Fatalf("denied (%s), want satisfied", reason)
		}
	})

	t.Run("one id outside denies", func(t *testing.T) {
		ok, _ := checkResourceConstraints(constraints, map[string]string{},
			[]string{"/workspace/a.txt", "/etc/shadow"}, "")
		if ok {
			t.Fatal("allowed a set containing an id outside the prefix")
		}
	})

	t.Run("no ids denies", func(t *testing.T) {
		ok, _ := checkResourceConstraints(constraints, map[string]string{}, nil, "")
		if ok {
			t.Fatal("allowed with no resource identified; unevaluable must deny")
		}
	})
}

// The existing exact-match behaviour must be bit-for-bit unchanged, including
// its deny-if-absent rule. A prefix key is an addition, not a replacement.
func TestCheckResourceConstraints_ExactKeysAreUnchanged(t *testing.T) {
	constraints := map[string]string{"tenant": "acme"}

	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "acme"}, nil, ""); !ok {
		t.Error("an exact key matching its value should satisfy")
	}
	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "other"}, nil, ""); ok {
		t.Error("an exact key with a different value must deny")
	}
	if ok, reason := checkResourceConstraints(constraints, map[string]string{}, nil, ""); ok {
		t.Errorf("an exact key absent from the request must deny, got satisfied (%s)", reason)
	}
}

// Both key kinds in one constraint set: both must hold.
func TestCheckResourceConstraints_PrefixAndExactTogether(t *testing.T) {
	constraints := map[string]string{
		models.ResourceIDPrefixKey: "/workspace/",
		"tenant":                   "acme",
	}
	resource := map[string]string{"tenant": "acme"}

	if ok, reason := checkResourceConstraints(constraints, resource, []string{"/workspace/a.txt"}, ""); !ok {
		t.Fatalf("denied (%s), want satisfied — both constraints hold", reason)
	}
	if ok, _ := checkResourceConstraints(constraints, map[string]string{"tenant": "other"},
		[]string{"/workspace/a.txt"}, ""); ok {
		t.Error("the exact key failed but the call was allowed")
	}
	if ok, _ := checkResourceConstraints(constraints, resource, []string{"/etc/shadow"}, ""); ok {
		t.Error("the prefix failed but the call was allowed")
	}
}
