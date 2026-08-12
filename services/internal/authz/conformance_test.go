// Conformance suite for the authorization security properties in
// docs/superpowers/specs/2026-08-08-agent-authorization-redesign-design.md §7.
//
// These are the CI merge gate. A property that does not pass right here
// calls exactly one of two helpers (conformance_outcome_test.go) instead of
// a bare t.Skip: notBuilt, when the subsystem it needs does not exist
// anywhere in this tree yet, or provenElsewhere, when the property is
// proven in a package this pure, DB-free, network-free suite structurally
// cannot reach (see the purity rule below) — carrying a pointer that
// conformance_pointer_test.go checks against real source on every run, so a
// renamed or deleted proof fails loudly instead of the comment quietly
// going stale. Do not delete a property to make the suite pass:
// TestConformanceSuiteIsComplete catches one deleted from this file, and the
// Makefile's conformance target (not just this test) catches this file
// itself disappearing, which would take that test down with it.
package authz

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// conformanceRan records which C-numbered properties actually executed in
// this run; conformanceNames (bottom of file) names them so a gap can be
// reported by number and by name. conformanceOutcome
// (conformance_outcome_test.go) is the parallel array for WHICH of the
// three outcomes each one landed in — a separate concern: this one is
// "did the function run at all," and stays that way regardless of what
// notBuilt/provenElsewhere do internally.
//
// Populated by markRan, called as the first statement of every TestC*
// below — including the ones that end in notBuilt or provenElsewhere: a
// property that legitimately does not pass here still ran, and
// completeness cares whether the function executed, not whether it
// currently passes. TestConformanceSuiteIsComplete (bottom of file) reads
// this once every TestC* below has had a chance to run. See that test for
// why this exists instead of a TestMain.
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
	notBuilt(t, 5, "Phase 2: requires the PAP override write path")
}

// TestC6_DelegationClampedToPrincipalAuthority is the property Phase 2d
// closes (spec defect D3): a delegation cannot be issued granting authority
// the principal does not hold. It exercises Clamp directly — the actual
// gate CreateDelegation calls (internal/pdpgrpc/delegation.go), not a
// re-implementation of it — the same discipline every other property in
// this file uses (C4 calls ValidateOverride directly, C7 calls
// models.ScopeNarrows directly). clampFixture (clamp_test.go, same package)
// stands in for policy.Probe here for the same reason GrantProbe's own
// probe_test.go needs the real Cedar engine and this file does not: this
// suite is a unit-level, no-DB, no-network gate (see the package doc, and
// C18's own skip note for why an integration-only property stays skipped
// HERE rather than faked with a stub); the live-Cedar, live-Postgres version
// of this exact property is proof10-14 in
// internal/store/store_integration_test.go (build tag integration).
func TestC6_DelegationClampedToPrincipalAuthority(t *testing.T) {
	markRan(6)

	// A principal permitted INTERNAL_MODIFY and only the "Read" tool
	// requests DESTRUCTIVE with two tools, one of which ("Bash") it does not
	// hold — mirroring the D3 attack this closes: a delegation request for
	// DESTRUCTIVE/every-tool from a principal who holds neither.
	f := &clampFixture{
		tiers: map[models.ActionTier]bool{models.ActionTierInternalModify: true},
		tools: map[string]bool{"Read": true, "Bash": false},
	}
	req := RequestedScope{MaxActionTier: models.ActionTierDestructive, Tools: []string{"Read", "Bash"}}

	got, err := Clamp(context.Background(), req, f.allows)
	if err != nil {
		t.Fatalf("C6: Clamp() error = %v, want nil — an over-broad request is narrowed, not rejected (Y4)", err)
	}

	// The artifact is clamped: DESTRUCTIVE was requested, but nothing above
	// the principal's own INTERNAL_MODIFY authority may ever be granted.
	if got.MaxActionTier != models.ActionTierInternalModify {
		t.Fatalf("C6: MaxActionTier = %v, want %v — a delegation must never be issued above the principal's own authority",
			got.MaxActionTier, models.ActionTierInternalModify)
	}
	if !equalTools(got.Tools, []string{"Read"}) {
		t.Fatalf("C6: Tools = %v, want [Read] — the principal does not hold Bash", got.Tools)
	}

	// The clamp is recorded, not silent — an auditor and the caller must
	// both see what was taken away and why (both dimensions here: tier and
	// tool).
	if len(got.Removed) != 2 {
		t.Fatalf("C6: Removed = %+v, want exactly 2 entries (tier DESTRUCTIVE, tool Bash)", got.Removed)
	}

	// The granted scope — narrower than asked, never empty here — is what
	// actually comes back: Y4 is clamp-and-return, not clamp-and-reject. An
	// artifact that silently vanished instead of degrading would fail an
	// agent framework's ordinary "ask generously, receive what's real" flow
	// just as surely as over-granting would compromise it.
	if len(got.Tools) == 0 {
		t.Fatal("C6: Tools is empty — Y4 requires the narrowed grant to be returned, not withheld")
	}
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
	req.PrincipalVerdicts = nil
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
	req.PrincipalVerdicts = nil
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("C13: an absent grant must deny, got %v", got.Effect)
	}
}

func TestC14_PolicyCannotExceedCeiling(t *testing.T) {
	markRan(14)
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectAllow, Reason: "policy grants everything"}}
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

// C16 reads "an action whose audit write fails is denied." It cannot become
// a pass HERE: internal/authz.Decide is a pure function with no database
// handle (see the package doc in types.go), so it has nothing to fail an
// audit write against in the first place — same shape as C18 below.
//
// The property is proven for real by proof6
// ("proof6_failed_audit_append_blocks_the_decision"), a t.Run subtest
// inside TestEndToEnd in internal/store/store_integration_test.go. The
// pointer below names TestEndToEnd itself, not the subtest: verifyPointer
// checks top-level Go function declarations via go/ast, and a t.Run
// subtest name is a string argument evaluated at run time, not a
// declaration the parser can see. Requires the integration build tag and a
// live Postgres (make integration) — go test -race ./... alone does not
// even compile this file.
func TestC16_FailedAuditWriteDeniesAction(t *testing.T) {
	markRan(16)
	provenElsewhere(t, 16, "internal/store", "TestEndToEnd")
}

func TestC17_CryptoShreddingPreservesChain(t *testing.T) {
	markRan(17)
	notBuilt(t, 17, "Phase 2+: blocked on per-tenant key management (spec §8)")
}

// C18 reads "a cross-tenant read is impossible at the data layer, not
// merely absent from queries." It cannot become a pass HERE: RLS is a
// Postgres session property (SET LOCAL app.tenant_id), and internal/authz —
// a pure function with no database handle — has no session to set, let
// alone violate. Same shape as C16 above.
//
// Its reason used to say only "RLS is proven against Postgres in Task 9,"
// naming a task instead of a test, because Task 9's own proof
// (.superpowers/sdd/2026-08-08-phase-0-1-foundation/task-9-report.md) was a
// manual psql session against a throwaway container: real evidence at the
// time, but nothing verifyPointer — or anyone reading this file later —
// could check, which is exactly the kind of claim that goes stale silently.
// Two automated tests have since taken over that job for real:
// TestIntegration_Multi_CrossTenantIsolationAcrossLanguages proves a second
// tenant's policy rows never reach LoadAllPolicies or policy.Multi.Evaluate's
// fold; TestIntegration_Escalation_CrossTenantCannotReadOrApprove proves the
// same for LoadApproval (a cross-tenant read returns nothing) and that a
// cross-tenant UPDATE affects zero rows. Both require the integration build
// tag and a live Postgres (make integration); RLS cannot be exercised any
// other way.
func TestC18_CrossTenantReadImpossible(t *testing.T) {
	markRan(18)
	provenElsewhere(t, 18, "internal/store",
		"TestIntegration_Multi_CrossTenantIsolationAcrossLanguages",
		"TestIntegration_Escalation_CrossTenantCannotReadOrApprove")
}

// C19 reads "with the PDP unreachable and no valid cache entry, every
// surface denies." Its reason used to say "Phase 3: requires the PEP
// client" — stale since Phase 3a: the client shipped, and
// cmd/stratium-pep/hook_test.go's TestRunHook_UnreachablePDP_ExitsTwo
// already proves an unreachable PDP denies, for the hook surface, with a
// named reason ("could not reach"). That is real progress, but it is not
// C19 itself, on two separate axes the property's own wording names:
//
//   - "every surface": spec §3.2 (A2) commits to four first-class surfaces —
//     hook, mcp, proxy, extauthz. Only hook exists;
//     cmd/stratium-pep/main.go's own package doc calls the other three
//     "later surfaces over the same PDP call." A property naming "every
//     surface" is not established by one of four.
//   - "no valid cache entry": this presupposes a cache with entries that can
//     be valid or not. No PEP decision cache exists yet anywhere in this
//     tree — the same absence that keeps C20 (the sibling property about a
//     stale cache entry) skipped below. hook_test.go's own unreachable-PDP
//     case has no cache in the picture at all, so it cannot yet distinguish
//     "no valid entry" from "no cache mechanism to have an entry in."
//
// Classified NOT BUILT, not proven elsewhere: provenElsewhere requires the
// property to hold, in full, somewhere this package cannot reach — but
// three of the four surfaces the property's own wording commits to, and the
// entire cache subsystem, do not exist anywhere in this tree, not just
// here. TestRunHook_UnreachablePDP_ExitsTwo proves a real subset (one
// surface, no cache dimension to even test), not the property C19 actually
// states. Pointing provenElsewhere at it would be precisely the kind of
// claim conformance_pointer_test.go exists to stop: a pointer whose named
// test is real but does not prove what the property says. Converting this
// to a pass would be forcing it just the same: unskip once mcp/proxy/
// extauthz all exist and the decision cache lands, not before.
func TestC19_UnreachablePDPDenies(t *testing.T) {
	markRan(19)
	notBuilt(t, 19, "Phase 4+: the hook surface alone proves this today "+
		"(cmd/stratium-pep/hook_test.go: TestRunHook_UnreachablePDP_ExitsTwo), but C19 says "+
		"'every surface' (hook, mcp, proxy, extauthz — spec §3.2 A2; only hook exists) "+
		"'with no valid cache entry' (no PEP decision cache exists yet — same blocker as C20). "+
		"Requires the remaining three surfaces and the decision cache.")
}

func TestC20_StaleEpochCacheEntryNotServed(t *testing.T) {
	markRan(20)
	notBuilt(t, 20, "Phase 3: requires the PEP decision cache")
}

// C21 reads "escalation routes to the root principal, not an intermediate
// agent." Its reason used to say "Phase 2: requires the approval
// subsystem" — stale as of Phase 5: the approval subsystem now exists
// (this phase's Tasks 1-4), and the property it names is genuinely
// proven — internal/pdpgrpc/escalation_test.go's TestDecide_Escalation_
// CreatesApprovalWithRootPrincipalAsApprover and, more pointedly,
// TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate (a
// depth-2 chain, the only shape that can tell "the root" apart from "the
// last hop" — a depth-0 chain's root IS its only hop) both assert
// resolveEscalation routes a fresh approval's RootPrincipal to
// chain[0].UserID, never an intermediate delegate's identity — exactly
// what the spec cites C21 for (§4.6.1 E7: "the PDP loads the record and
// enforces that its approver is the chain's root principal (C21)").
//
// It cannot become a pass HERE, and that is not a gap: routing approval to
// a root principal is not a concept internal/authz has any way to express.
// authz.Result carries no approver, no RootPrincipal, no Approval at all —
// resolveEscalation and models.Approval, where that concept actually
// lives, sit one layer up in internal/pdpgrpc and pkg/models, which this
// package's own global constraint forbids it from importing
// ("internal/authz stays pure ... may never import internal/policy or
// internal/store" — and pdpgrpc itself imports authz, so the reverse
// would also be circular). Same shape as C16 and C18 above: the property
// is real and proven, just never provable at this package's level — see
// their own skip reasons for the precedent this follows.
func TestC21_EscalationRoutesToRootPrincipal(t *testing.T) {
	markRan(21)
	provenElsewhere(t, 21, "internal/pdpgrpc",
		"TestDecide_Escalation_CreatesApprovalWithRootPrincipalAsApprover",
		"TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate")
}

// C22 reads "escalation timeout denies." Its reason used to say "Phase 2:
// requires the approval subsystem" — stale as of Phase 5: the PEP poll
// loop now exists (this phase's Task 4, cmd/stratium-pep/escalation.go),
// and the property is genuinely proven there —
// TestRunHook_Escalate_TimeoutStillPendingDenies asserts a still-pending
// approval at ApprovalTimeout denies (exit 2), wrapped in a
// goroutine-and-select helper so a "retry forever" regression fails the
// test in under a second rather than hanging until go test's own default
// timeout; TestPollApproval_ContextCancelledMidPoll_
// ReturnsPromptlyAndDenies proves the underlying poll primitive is
// actually interruptible rather than merely slow to notice; and
// TestRunHook_Escalate_PollRespectsInterval_DoesNotBusyWait proves the
// wait between checks is a real wait, not a spin loop that happens to
// also check a deadline.
//
// It cannot become a pass HERE: C22 is a property of blocking and time —
// "the agent blocks there" until the PEP's own timeout (spec §4.6.1 E6) —
// and internal/authz.Decide is a single, synchronous, non-blocking pure
// function with no poll loop, no clock of its own (Now is a parameter,
// per this package's own purity rule), and no PEP to time out in the
// first place. There is no version of this property internal/authz could
// exercise even in principle, unlike C6's Clamp, which IS a function this
// package owns and can call directly. Same shape as C16/C18/C21 above:
// real, proven, at a layer this file cannot reach.
func TestC22_EscalationTimeoutDenies(t *testing.T) {
	markRan(22)
	provenElsewhere(t, 22, "cmd/stratium-pep",
		"TestRunHook_Escalate_TimeoutStillPendingDenies",
		"TestPollApproval_ContextCancelledMidPoll_ReturnsPromptlyAndDenies")
}

// C23 reads "on a non-blocking surface, escalate returns deny plus a
// pending record." Its reason used to say "Phase 4: requires the extauthz
// PEP mode" — stale in the same way C19's old "Phase 3: requires the PEP
// client" was: Phase 4 (remaining surfaces) has since landed, and extauthz
// still does not exist. cmd/stratium-pep/main.go's own package doc still
// calls "mcp", "proxy", and "extauthz" alike "later surfaces over the same
// PDP call" — only "hook" is wired. Same gap C19 already names for "every
// surface" (spec §3.2 A2).
//
// What Phase 5 genuinely closes is narrower than the whole surface: the
// response *mapping* a non-blocking surface would need in order to degrade
// correctly. EFFECT_ESCALATE has nothing a two-valued (allow/deny) surface
// can return, so it must become a denial — but the pending approval's id
// (DecideResponse.approval_id) must survive that translation unchanged, or a
// retry after approval would have nothing to present. That mapping is
// pdpgrpc.DegradeEscalateToDeny, proven directly by its own test
// (internal/pdpgrpc/nonblocking_test.go) against every reachable Effect:
// escalate degrades to deny with the id retained, an ordinary deny
// fabricates no id, allow passes through unchanged, and a defensively
// handled nil response fails closed to deny rather than allow. The response
// Decide already sends every surface already carries what a non-blocking
// surface needs; this is that fact, made explicit and tested — not a forced
// pass on the property C23 actually states.
//
// It cannot become a pass HERE for two independent reasons. The usual one:
// this is a property about a surface's own translation of a response it
// receives, a concept internal/authz's pure decision function has no way to
// express even in principle — same shape as C16/C18/C19/C21/C22's own skips
// in this file. The narrower one is specific to C23: its own wording says
// "on a non-blocking surface" — an actual extauthz mode receiving an actual
// bounded-latency call and actually returning "deny plus a pending record"
// over Envoy's own wire protocol — and no such surface is wired into
// cmd/stratium-pep or anywhere else in this tree. Proving the mapping a
// surface would need is a real, tested fact; it is not the same claim as a
// surface using it. Unskipping this needs the extauthz mode itself, same as
// C19's own remaining gap.
//
// Classified NOT BUILT, same reasoning as C19 above: DegradeEscalateToDeny
// is a real, passing test of a real, useful fact, but it proves a narrower
// claim than "on a non-blocking surface, escalate returns deny plus a
// pending record" — no non-blocking surface exists to make that return.
// provenElsewhere is for a property proven in full elsewhere, not for a
// supporting fact about a property that is not built yet.
func TestC23_NonBlockingSurfaceDegradesToDeny(t *testing.T) {
	markRan(23)
	notBuilt(t, 23, "Phase 5: the response mapping a non-blocking surface needs is proven directly at "+
		"internal/pdpgrpc/nonblocking_test.go (DegradeEscalateToDeny) — EFFECT_ESCALATE degrades to deny "+
		"with approval_id retained for a later retry, exactly what spec E5/§4.7 describes. Still requires "+
		"the extauthz PEP mode itself (spec §3.2 A2; cmd/stratium-pep's own package doc still calls it a "+
		"'later surface' — same gap C19 already names), which remains unbuilt.")
}

func TestC24_ExpiredDelegationDenied(t *testing.T) {
	markRan(24)
	notBuilt(t, 24, "Phase 3: the property is about an expired TOKEN with a live cache "+
		"entry; neither exists yet. Delegation expiry alone is covered by "+
		"TestDelegationLeg_DeniesExpiredHop.")
}

func TestC25_MissingDPoPProofDenies(t *testing.T) {
	markRan(25)
	notBuilt(t, 25, "Phase 2: DPoP verification lives in the PDP transport layer")
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
	if missing := missingProperties(); len(missing) > 0 {
		t.Fatalf("conformance suite is incomplete: %d of 25 properties did not run: %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// missingProperties returns the C-numbers (formatted "Cn (TestName)") that
// have not run, in ascending order, or nil if all 25 have. Shared by
// TestConformanceSuiteIsComplete and TestConformanceTally
// (conformance_outcome_test.go) so both fail the same way if a property
// vanished, instead of the tally test silently reporting a
// confident-looking count computed from incomplete data.
func missingProperties() []string {
	var missing []string
	for n := 1; n <= 25; n++ {
		if !conformanceRan[n] {
			missing = append(missing, fmt.Sprintf("C%d (%s)", n, conformanceNames[n]))
		}
	}
	return missing
}

// TestConformanceTally reports the three-way breakdown a single pass/skip
// count hid: how many of the 25 properties in docs/superpowers/specs/
// 2026-08-08-agent-authorization-redesign-design.md §7 pass right here, how
// many are proven in a package this one cannot import (a checked pointer,
// not a claim — see conformance_outcome_test.go and
// conformance_pointer_test.go), and how many name a subsystem that does not
// exist yet. "14 pass, 11 skip" reads as under half done; this is the
// number that says which half of "not passing here" is actually finished
// work elsewhere.
//
// Declared last in this file, deliberately: it must run after
// TestC1..TestC25 have populated conformanceOutcome, and declaration order
// within one file is the one ordering go test actually guarantees — see
// conformanceOutcome's own doc comment for why this test does not simply
// live next to that variable instead.
//
// Re-checks completeness itself with the same missingProperties()
// TestConformanceSuiteIsComplete uses, rather than assuming that test
// already ran and passed: both are top-level tests in this file, and go
// test does not guarantee one test's pass/fail outcome is visible to
// another, only that both run. A tally computed after a property silently
// failed to run would otherwise report a confident-looking count built on
// missing data.
func TestConformanceTally(t *testing.T) {
	if missing := missingProperties(); len(missing) > 0 {
		t.Fatalf("conformance tally: cannot be trusted, %d of 25 properties did not run: %s",
			len(missing), strings.Join(missing, ", "))
	}

	var pass, elsewhere, notBuiltCount int
	for n := 1; n <= 25; n++ {
		switch conformanceOutcome[n] {
		case outcomePass:
			pass++
		case outcomeProvenElsewhere:
			elsewhere++
		case outcomeNotBuilt:
			notBuiltCount++
		}
	}

	// A cross-check against conformanceOutcome itself, not just against
	// conformanceRan above: the two arrays are populated independently
	// (markRan unconditionally; conformanceOutcome only by notBuilt/
	// provenElsewhere), so this catches a bookkeeping bug — an outcome
	// written outside those two helpers — that completeness alone would
	// not.
	if total := pass + elsewhere + notBuiltCount; total != 25 {
		t.Fatalf("conformance tally: %d pass + %d proven elsewhere + %d not built = %d, want 25 "+
			"(an outcome was recorded outside notBuilt/provenElsewhere/the pass default)",
			pass, elsewhere, notBuiltCount, total)
	}

	t.Logf("conformance tally: %d pass, %d proven elsewhere, %d not built (25 total)", pass, elsewhere, notBuiltCount)
}
