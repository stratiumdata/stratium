// Conformance suite for the authorization security properties in
// docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md §7.
//
// These are the CI merge gate. Properties whose implementation lands in a later
// phase skip with the phase named — a skip is a visible commitment, not a
// silent gap. Do not delete a property to make the suite pass.
package authz

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// conformanceRan records which C-numbered properties actually executed in
// this run; conformanceNames (bottom of file) names them so a gap can be
// reported by number and by name.
//
// Populated by markRan, called as the first statement of every TestC*
// below — including the t.Skip ones: a phase-deferred property that
// legitimately skips still ran, and completeness cares whether the
// function executed, not whether it currently passes.
// TestConformanceSuiteIsComplete (bottom of file) reads this once every
// TestC* below has had a chance to run. See that test for why this exists
// instead of a TestMain.
var conformanceRan [26]bool // index 0 unused; C-numbers are 1..25

// markRan records that conformance property cNum executed.
func markRan(cNum int) { conformanceRan[cNum] = true }

func TestC1_UnderDeclaredTierDenies(t *testing.T) {
	markRan(1)
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C1: under-declaration must deny, got %v", got.Effect)
	}
}

func TestC2_OverDeclaredTierPermitted(t *testing.T) {
	markRan(2)
	req := request()
	req.Action = Action{Tool: "Read", Verb: "read", DeclaredTier: tierPtr(models.ActionTierDestructive)}
	if got := Decide(req, config()); got.Effect != EffectAllow {
		t.Fatalf("C2: over-declaration must be permitted, got %v: %s", got.Effect, got.Reason)
	}
}

func TestC3_DerivedTierReachesEveryGate(t *testing.T) {
	markRan(3)
	req := request()
	req.Chain = linkChain(req.TenantID, req.Agent.ID, delegation(0, models.ActionTierReadOnly, nil))
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierDestructive)}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("C3: the derived tier must reach the delegation gate, got %v/%s", got.Effect, got.DeniedLeg)
	}
	if got.DerivedTier != models.ActionTierDestructive {
		t.Fatalf("C3: expected derived DESTRUCTIVE, got %v", got.DerivedTier)
	}
}

func TestC4_TierOverrideRaiseOnly(t *testing.T) {
	markRan(4)
	if err := ValidateOverride(models.ActionTierReadOnly, models.ActionTierDestructive); err != nil {
		t.Fatalf("C4: raising must be allowed: %v", err)
	}
	if err := ValidateOverride(models.ActionTierDestructive, models.ActionTierReadOnly); err == nil {
		t.Fatal("C4: lowering must be rejected")
	}
}

func TestC5_AgentWritableOverrideNotHonored(t *testing.T) {
	markRan(5)
	t.Skip("Phase 2: requires the PAP override write path")
}

func TestC6_DelegationClampedToPrincipalAuthority(t *testing.T) {
	markRan(6)
	t.Skip("Phase 2: requires the delegation-creation policy gate")
}

func TestC7_ChildCannotWidenParent(t *testing.T) {
	markRan(7)
	base := func() *models.Delegation {
		return &models.Delegation{
			MaxActionTier:       models.ActionTierInternalModify,
			ApprovedTools:       []string{"Read"},
			ClassificationCaps:  map[string]string{"nato": "CONFIDENTIAL"},
			ResourceConstraints: map[string]string{"project": "alpha"},
			ExpiresAt:           authzNow.Add(time.Hour),
		}
	}
	// C7 names six dimensions: tools, actions, tier, caps, resources, expiry.
	// Omission counts as widening wherever absence means "unrestricted" at
	// decision time — that is how a child sheds a ceiling without ever
	// appearing to widen one.
	widenings := map[string]func(*models.Delegation){
		"tier":              func(d *models.Delegation) { d.MaxActionTier = models.ActionTierDestructive },
		"tools":             func(d *models.Delegation) { d.ApprovedTools = []string{"Read", "Bash"} },
		"tools-omitted":     func(d *models.Delegation) { d.ApprovedTools = nil },
		"classification":    func(d *models.Delegation) { d.ClassificationCaps = map[string]string{"nato": "TOP-SECRET"} },
		"caps-omitted":      func(d *models.Delegation) { d.ClassificationCaps = nil },
		"resources":         func(d *models.Delegation) { d.ResourceConstraints = map[string]string{"project": "*"} },
		"resources-omitted": func(d *models.Delegation) { d.ResourceConstraints = nil },
		"expiry":            func(d *models.Delegation) { d.ExpiresAt = authzNow.Add(2 * time.Hour) },
	}
	for dim, widen := range widenings {
		t.Run(dim, func(t *testing.T) {
			child := base()
			widen(child)
			if models.ScopeNarrows(base(), child) == "" {
				t.Fatalf("C7: widening %s must be rejected", dim)
			}
		})
	}
}

func TestC8_ChainDepthBounded(t *testing.T) {
	markRan(8)
	req := request()
	req.Chain = linkChain(req.TenantID, req.Agent.ID,
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierDestructive, nil),
		delegation(2, models.ActionTierDestructive, nil),
	)
	cfg := config()
	cfg.MaxDepth = 1
	if got := Decide(req, cfg); got.Effect != EffectDeny {
		t.Fatalf("C8: a chain beyond max depth must deny, got %v", got.Effect)
	}
}

func TestC9_RevokedRootDeniesDescendants(t *testing.T) {
	markRan(9)
	req := request()
	root := delegation(0, models.ActionTierDestructive, nil)
	root.Revoked = true
	req.Chain = linkChain(req.TenantID, req.Agent.ID, root, delegation(1, models.ActionTierReadOnly, nil))
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedAtDepth != 0 {
		t.Fatalf("C9: a revoked root must deny at depth 0, got %v at %d", got.Effect, got.DeniedAtDepth)
	}
}

func TestC10_SuspendedAgentDenied(t *testing.T) {
	markRan(10)
	req := request()
	req.Agent.Suspended = true
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C10: a suspended agent must deny, got %v", got.Effect)
	}
}

func TestC11_AllThreeLegsEvaluated(t *testing.T) {
	markRan(11)
	got := Decide(request(), config())
	if got.Principal.Effect != EffectAllow || got.Agent.Effect != EffectAllow || got.Delegation.Effect != EffectAllow {
		t.Fatalf("C11: every leg must be evaluated, got p=%v a=%v d=%v",
			got.Principal.Effect, got.Agent.Effect, got.Delegation.Effect)
	}
	req := request()
	req.PrincipalDecision = LegResult{}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatal("C11: an unevaluated leg must deny")
	}
}

func TestC12_DenyOverridesEverything(t *testing.T) {
	markRan(12)
	req := request()
	req.Agent.Enabled = false
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C12: any deny must override, got %v", got.Effect)
	}
}

func TestC13_DefaultDeny(t *testing.T) {
	markRan(13)
	req := request()
	req.PrincipalDecision = LegResult{}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C13: an absent grant must deny, got %v", got.Effect)
	}
}

func TestC14_PolicyCannotExceedCeiling(t *testing.T) {
	markRan(14)
	req := request()
	req.PrincipalDecision = LegResult{Effect: EffectAllow, Reason: "policy grants everything"}
	req.Chain = linkChain(req.TenantID, req.Agent.ID, delegation(0, models.ActionTierReadOnly, nil))
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("C14: policy must not exceed the ceiling, got %v/%s", got.Effect, got.DeniedLeg)
	}
}

func TestC15_AuditChainDetectsMutation(t *testing.T) {
	markRan(15)
	e1 := audit.Entry{PrevHash: audit.ZeroHash, TenantID: "t", Actor: "alice",
		OccurredAt: authzNow, EventType: "decision", Decision: "ALLOW", Reason: "first"}
	e2 := audit.Entry{PrevHash: e1.Hash(), TenantID: "t", Actor: "alice",
		OccurredAt: authzNow, EventType: "decision", Decision: "ALLOW", Reason: "second"}
	if err := audit.Verify([]audit.Entry{e1, e2}); err != nil {
		t.Fatalf("C15: an intact chain must verify: %v", err)
	}
	e1.Reason = "tampered"
	if err := audit.Verify([]audit.Entry{e1, e2}); err == nil {
		t.Fatal("C15: mutation must be detected")
	}
}

func TestC16_FailedAuditWriteDeniesAction(t *testing.T) {
	markRan(16)
	t.Skip("Phase 2: requires the PDP audit write path")
}

func TestC17_CryptoShreddingPreservesChain(t *testing.T) {
	markRan(17)
	t.Skip("Phase 2+: blocked on per-tenant key management (spec §8)")
}

func TestC18_CrossTenantReadImpossible(t *testing.T) {
	markRan(18)
	t.Skip("Integration: RLS is proven against Postgres in Task 9, not in unit tests")
}

func TestC19_UnreachablePDPDenies(t *testing.T) {
	markRan(19)
	t.Skip("Phase 3: requires the PEP client")
}

func TestC20_StaleEpochCacheEntryNotServed(t *testing.T) {
	markRan(20)
	t.Skip("Phase 3: requires the PEP decision cache")
}

func TestC21_EscalationRoutesToRootPrincipal(t *testing.T) {
	markRan(21)
	t.Skip("Phase 2: requires the approval subsystem")
}

func TestC22_EscalationTimeoutDenies(t *testing.T) {
	markRan(22)
	t.Skip("Phase 2: requires the approval subsystem")
}

func TestC23_NonBlockingSurfaceDegradesToDeny(t *testing.T) {
	markRan(23)
	t.Skip("Phase 4: requires the extauthz PEP mode")
}

func TestC24_ExpiredDelegationDenied(t *testing.T) {
	markRan(24)
	req := request()
	expired := delegation(0, models.ActionTierDestructive, nil)
	expired.ExpiresAt = authzNow.Add(-time.Second)
	req.Chain = []*models.Delegation{expired}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C24: an expired delegation must deny, got %v", got.Effect)
	}
}

func TestC25_MissingDPoPProofDenies(t *testing.T) {
	markRan(25)
	t.Skip("Phase 2: DPoP verification lives in the PDP transport layer")
}

// conformanceNames is the authoritative list of C-numbered properties this
// suite must contain — §7 of the design spec lists 25. Keep in sync with
// that table; this is what turns a missing property into a name, not just
// a count.
var conformanceNames = map[int]string{
	1:  "TestC1_UnderDeclaredTierDenies",
	2:  "TestC2_OverDeclaredTierPermitted",
	3:  "TestC3_DerivedTierReachesEveryGate",
	4:  "TestC4_TierOverrideRaiseOnly",
	5:  "TestC5_AgentWritableOverrideNotHonored",
	6:  "TestC6_DelegationClampedToPrincipalAuthority",
	7:  "TestC7_ChildCannotWidenParent",
	8:  "TestC8_ChainDepthBounded",
	9:  "TestC9_RevokedRootDeniesDescendants",
	10: "TestC10_SuspendedAgentDenied",
	11: "TestC11_AllThreeLegsEvaluated",
	12: "TestC12_DenyOverridesEverything",
	13: "TestC13_DefaultDeny",
	14: "TestC14_PolicyCannotExceedCeiling",
	15: "TestC15_AuditChainDetectsMutation",
	16: "TestC16_FailedAuditWriteDeniesAction",
	17: "TestC17_CryptoShreddingPreservesChain",
	18: "TestC18_CrossTenantReadImpossible",
	19: "TestC19_UnreachablePDPDenies",
	20: "TestC20_StaleEpochCacheEntryNotServed",
	21: "TestC21_EscalationRoutesToRootPrincipal",
	22: "TestC22_EscalationTimeoutDenies",
	23: "TestC23_NonBlockingSurfaceDegradesToDeny",
	24: "TestC24_ExpiredDelegationDenied",
	25: "TestC25_MissingDPoPProofDenies",
}

// TestConformanceSuiteIsComplete is the guard against a vacuous conformance
// gate. Verified: `go test ./internal/authz/ -run "TestZZZ[0-9]"` exits 0
// with "no tests to run" — the -run regexp matches zero tests just as
// happily as twenty-five, so deleting, moving, or renaming a TestC*
// silently drops the CI merge gate to nothing.
//
// This test is deliberately named so that same "TestC[0-9]" filter does
// NOT select it (no digit immediately follows "TestC" in
// "TestConformanceSuiteIsComplete") — it cannot be filtered out alongside
// the properties it is checking. It runs as part of the unfiltered suite
// (go test ./..., which CI's "Test (race)" job always runs) and fails
// loudly, naming exactly which C-numbers did not run, if any TestC* was
// deleted or renamed.
//
// Deliberately not a TestMain: TestMain replaces the test driver for every
// test in the package, so it would also run — and could false-fail — for
// tier_test.go, agent_test.go, and every other unrelated test in this
// package that has nothing to do with conformance.
func TestConformanceSuiteIsComplete(t *testing.T) {
	var missing []string
	for n := 1; n <= 25; n++ {
		if !conformanceRan[n] {
			missing = append(missing, fmt.Sprintf("C%d (%s)", n, conformanceNames[n]))
		}
	}
	if len(missing) > 0 {
		t.Fatalf("conformance suite is incomplete: %d of 25 properties did not run: %s",
			len(missing), strings.Join(missing, ", "))
	}
}
