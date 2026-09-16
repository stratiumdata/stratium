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
	"stratium/pkg/permset"
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

// C5 reads, in spec §7's own words, "a tier override from an agent-writable
// source is never honored." It is a D1 property — the component being
// policed must not declare its own authority — and it stayed NOT BUILT for
// thirteen phases behind the reason "Phase 2: requires the PAP override
// write path."
//
// That reason named a support, not the property, and the phase plan
// inherited the confusion: C5 was summarised there as "the PAP override
// write path exists," which is not what §7 says and would have made this a
// pass the moment Task 3 shipped CreateTierOverride. A write path existing
// proves nothing about whether an override from the WRONG writer is
// honored. Read the property, not its skip reason.
//
// Four mechanisms hold it up, and a pointer set naming fewer than all four
// would be an overclaim — which is why provenElsewhere now takes several
// packages (see its own doc comment; C5 is the property that forced it):
//
//  1. No PEP sends declared_tier at all, on any of the four surfaces.
//     There is no agent-supplied tier for the PDP to honor in the first
//     place. Asserted on the wire against a real decoded DecideRequest,
//     once per surface — and, since the mcp live proof, on ONE surface
//     against a real PDP's own record as well. declared_tier is a proto3
//     optional, so absence is a real wire distinction, and
//     internal/pdpgrpc writes it to audit_chain as -1 (auditDeclaredTierAbsent,
//     server.go) precisely because 0 would be REASONING, a real declarable
//     tier. TestIntegration_MCP_E2E_PermittedCallReachesUpstreamAndReturns
//     reads that row back after a live tools/call. That is strictly stronger
//     than the fake-PDP assertion it sits beside: a mutant adding
//     DeclaredTier to decideAndRelay's request and declaring it CORRECTLY
//     (the tier the PDP derives anyway, so no decision changes) is invisible
//     to every other live assertion on that surface and dies only here.
//     The other three surfaces still rest on their unit-level wire
//     assertions alone.
//  2. If one arrived anyway, it is cross-checked rather than trusted:
//     DeriveTier ignores it when deriving (TestDeriveTier_IgnoresDeclaredTier)
//     and CheckDeclaredTier denies an under-declaration
//     (TestCheckDeclaredTier_UnderDeclarationDenies, which is also C1). This
//     mechanism alone lives in THIS package and does pass here — but a
//     property is not proven by its one locally-reachable support.
//  3. The tier_overrides table is writable only by stratium_pap, the admin
//     plane's own role, which is reachable only by an operator holding a
//     verified OIDC token from the customer's IdP. Proven live: the role
//     can write, an unverified caller is refused every route including
//     POST /v1/tier-overrides, and a lowering row inserted DIRECTLY into the
//     table — satisfying the schema's own CHECK, never passing through the
//     PAP — is dropped at read time rather than honored, which is the case
//     that most literally IS this property.
//  4. The PDP holds SELECT on that table and nothing else (T6,
//     migrations/000017_tier_overrides_serving_grant). A PDP that could
//     write one would be exactly the D1 defect.
//
// Not forced to a pass. Three of the four are facts about a wire format, a
// database grant, and a live HTTP surface — none of which internal/authz,
// which has no database handle, no network client, and no ambient clock
// (types.go's package doc), can express even in principle. Same shape as
// C16, C18-C24.
func TestC5_AgentWritableOverrideNotHonored(t *testing.T) {
	markRan(5)
	provenElsewhere(t, 5,
		in("cmd/stratium-pep",
			"TestRunHook_RequestCarriesRawInputAndNoDeclaredTier",
			"TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier",
			"TestCheck_NeverSendsDeclaredTier",
			"TestAuthorize_NeverSendsDeclaredTier"),
		in("internal/authz",
			"TestDeriveTier_IgnoresDeclaredTier",
			"TestCheckDeclaredTier_UnderDeclarationDenies"),
		in("internal/store",
			"TestIntegration_PAPRole_BumpsOnGovernedTableWrites",
			"TestIntegration_StratiumApp_CanReadButCannotWriteTierOverrides",
			"TestIntegration_TierOverride_DirectlyInsertedLoweringRowIsDroppedAtReadTime",
			"TestIntegration_PAPE2E_UnverifiedTokenIsRefusedEverywhere",
			"TestIntegration_MCP_E2E_PermittedCallReachesUpstreamAndReturns"))
}

// TestC6_DelegationClampedToPrincipalAuthority is the property Phase 2d
// closes (spec defect D3): a delegation cannot be issued granting authority
// the principal does not hold. It exercises Clamp directly — the actual
// gate CreateDelegation calls (internal/pdpgrpc/delegation.go), not a
// re-implementation of it — the same discipline every other property in
// this file uses (C4 calls ValidateOverride directly, C7 calls
// permset.ScopeNarrows directly). clampFixture (clamp_test.go, same package)
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
			if permset.ScopeNarrows(base(), child) == "" {
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
	provenElsewhere(t, 16, in("internal/store", "TestEndToEnd"))
}

// C17 was RESTATED on 2026-08-18, not converted and not deleted. Spec §7 now
// reads "a decision's raw input is never retained; only its digest is
// recorded." What it read before was "crypto-shredding a tenant's key renders
// inputs unrecoverable while the chain still verifies."
//
// The old wording presumed this system retains decision inputs encrypted
// under a per-tenant key. IT DOES NOT, AND DELIBERATELY. §4.9 records
// input_digest — a SHA-256 — and never the input, so the inputs the property
// wanted made unrecoverable are unrecoverable already, with no key to hold
// and none to destroy. Never recording is STRONGER than encrypt-then-shred:
// there is no ciphertext to mishandle, no key-destruction procedure to get
// right, and no window in which a leaked key exposes history. The old row
// therefore could not be built as written without first ADDING the retention
// it then protected against — trading the posture for the capability.
//
// §8 assumed otherwise ("§4.9 depends on per-tenant keys for
// crypto-shredding") because it was written before §4.9 was built. That
// premise was overtaken; §8 now records it as resolved rather than pending.
//
// The restated property is not a triviality, and the difference is DRIFT.
// "Never retained" becomes "retained and hopefully protected" the moment
// someone adds an input column for dry-run replay or to debug a support
// ticket, and nothing about that change looks alarming in isolation. The two
// pointers below are drift guards: neither can fail today, both fail the
// moment retention is introduced, and each names the property in its own
// failure message so the person who trips it learns why it matters.
//
// TWO THINGS THIS DOES NOT SOLVE, recorded so the tally cannot be misread as
// closing them:
//
//   - N6, dry-run replay, STAYS BLOCKED. It needs the input to re-derive a
//     tier and a digest cannot supply one. Retiring the old C17 does not
//     unblock it; it confirms the block is a deliberate retention choice
//     rather than a missing subsystem. §8 carries that.
//   - The chain's OTHER tenant-identifying columns — actor, tool_name,
//     action, reason — have no erasure story. That is what a real erasure
//     request targets, and the old C17's wording never covered it either.
//     Now its own §8 entry rather than something this restatement absorbs.
//
// The two key-shaped subsystems in this tree remain unrelated to any of it,
// which is worth keeping because both look relevant from a distance:
// internal/token holds ONE process-wide signing pair (K1) that protects no
// stored plaintext and could not be destroyed per tenant; internal/dpop only
// ever sees a CLIENT's public key, and a jkt is a fingerprint carried inside
// a token, not a key this system holds.
//
// PROVEN ELSEWHERE, not a pass: one guard needs reflection over a type in
// pkg/audit and the other needs a live information_schema read. This package
// has no database handle and does not import pkg/audit.
func TestC17_RawInputIsNeverRetained(t *testing.T) {
	markRan(17)
	provenElsewhere(t, 17,
		in("pkg/audit", "TestEntry_RecordsOnlyADigestOfTheInput"),
		in("internal/store", "TestIntegration_AuditChain_RetainsADigestNeverTheInput"))
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
	provenElsewhere(t, 18, in("internal/store",
		"TestIntegration_Multi_CrossTenantIsolationAcrossLanguages",
		"TestIntegration_Escalation_CrossTenantCannotReadOrApprove"))
}

// C19 reads "with the PDP unreachable and no valid cache entry, every
// surface denies." Its reason has been corrected three times before this:
// from "Phase 3: requires the PEP client" to naming what was left after
// Phase 4+ (hook alone, of four surfaces), then to name three of four once
// mcp and extauthz landed, then — Phase 11 Task 4 — to close the "every
// surface" axis in full while leaving the second axis explicitly open:
//
//   - "every surface" (closed by Phase 11 Task 4): spec §3.2 (A2) commits to
//     four first-class surfaces — hook, mcp, extauthz, proxy. All four exist
//     and are each proven against the real thing they enforce: hook via
//     services/internal/store/cache_e2e_integration_test.go (the real
//     compiled binary exec'd as Claude Code's PreToolUse hook runs it,
//     against a real containerized PDP), extauthz against a real Envoy
//     (services/internal/store/extauthz_integration_test.go), proxy against
//     a real gRPC service (services/internal/store/proxy_integration_test.go),
//     and mcp against a real PDP and a real upstream child process
//     (services/internal/store/mcp_e2e_integration_test.go). There is no
//     fifth surface spec §3.2 names that remains unbuilt.
//
//     WHAT THIS BULLET SAID UNTIL THE mcp LIVE PROOF LANDED, and why it was
//     wrong: "hook and mcp against a real claude session." No such proof
//     existed for mcp, or for hook in that form. The phrase originated in
//     proto/target/v1/target.proto (Phase 11) and was copied from there into
//     this file and into extauthz_integration_test.go's own package doc; both
//     of those still carry it, as do the two generated .pb.go files, and none
//     of the four was ever backed by an artifact naming a claude session. The
//     mcp live-proof plan's own pre-flight established the sharper version of
//     the same fact — no integration test had ever invoked the mcp subcommand
//     at all — which is precisely why that plan exists. The claim is now true
//     for mcp, but through a real containerized PDP and a real child process
//     rather than through a session of any kind.
//
//   - "no valid cache entry" (closed by Phase 13 Task 4, this correction):
//     the PEP decision cache now exists (Phase 13 Tasks 1-3, spec §4.8) and
//     is wired into exactly two of the four surfaces — hook and mcp — by a
//     deliberate ruling (spec §4.8.3 W6, cache.go's own package doc): a
//     cache hit is defined by NOT calling the PDP, and the PDP is the only
//     component that ever verifies a token's signature (K2); on extauthz and
//     proxy the caller IS the party being policed, so a forged token would
//     satisfy every cache condition and be served without ever being
//     checked. That ruling is exactly what keeps "every surface" literally
//     true for all four, not just the two with a cache: on extauthz and
//     proxy, "no valid cache entry" is unconditionally true — there is no
//     code path on either that could ever populate one — so an unreachable
//     PDP already denies by the SAME mechanism their own pre-existing live
//     proofs establish (TestIntegration_Envoy_NoTokenDeniedNoFallback and
//     TestIntegration_Proxy_NoTokenDeniesNoFallback, both internal/store,
//     both unconditional denials with no fallback of any kind — proven
//     before this phase existed, unaffected by anything it added). For hook
//     and mcp the property is no longer vacuous:
//     cache_e2e_integration_test.go (internal/store) proves it against a
//     REAL, containerized PDP that is actually stopped (docker compose
//     stop, never a bad address standing in for one) — once with no cache
//     entry at all (TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies),
//     and once with an entry present but past the required staleness
//     window (TestIntegration_Cache_E2E_PastStalenessWindow_StopsServing —
//     cache.go's own doc comment ties withinStalenessWindow to this exact
//     property, "required config, NO default"). Both deny, driven through
//     the real "hook" subcommand exec'd as a subprocess exactly as Claude
//     Code would run it, not runHook called in-process against a fake PDP.
//
// mcp is not independently re-proven live here: consultCache/
// storeCacheResult (cmd/stratium-pep/local_cache.go) are the ONLY cache
// read and the ONLY cache write this binary ever performs, called
// identically by runHook and decideAndRelay (mcp_authorize.go) — Task 3's
// own report states decideAndRelay "mirrors runHook's consult/store wiring"
// and every mutation applied to that shared logic was caught identically on
// both surfaces' own unit tests. A live proof of the mechanism through one
// of its two identical callers is a live proof of the mechanism itself;
// repeating the identical container-stop choreography a second time through
// mcp's own JSON-RPC transport would exercise the exact same consultCache/
// cacheGetValid code path a second time, not a different one.
//
// Classified PROVEN ELSEWHERE, not a pass: this is a live-stack property —
// a real subprocess, a real session file and cache file on disk, a real
// containerized PDP actually stopped — none of which internal/authz's pure
// Decide function has any way to exercise even in principle (this
// package's own doc comment, types.go: "no database handles, no network
// clients, no ambient clock"). Same shape as C16/C18/C21/C22/C23 above: the
// property is real and now proven, just never provable at this layer.
func TestC19_UnreachablePDPDenies(t *testing.T) {
	markRan(19)
	provenElsewhere(t, 19, in("internal/store",
		"TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies",
		"TestIntegration_Cache_E2E_PastStalenessWindow_StopsServing"))
}

// TestC20_StaleEpochCacheEntryNotServed is C20: an entry cached before a
// revocation epoch bump is not served after it. Skipped from Phase 3 onward
// for the obvious reason — no PEP decision cache existed anywhere in this
// tree to hold a stale entry in the first place — until Phase 13 built one
// (Tasks 1-3, spec §4.8) with epochCurrent (cache.go) as exactly this
// condition's own enforcement: a cached decision's own Epoch must equal
// lastKnownEpoch, the highest epoch already recorded among this PEP's own
// cache file (local_cache.go's maxCacheEpoch — corrected mid-phase from an
// earlier, session-file-frozen source that this very property would have
// caught immediately had a live proof existed at the time; see
// local_cache.go's own "WHERE THE EPOCH COMES FROM" for the full account).
//
// Phase 13 Task 4 is that live proof:
// TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry
// (internal/store/cache_e2e_integration_test.go) caches a real ALLOW under
// a real delegation, revokes that SAME delegation with a raw SQL UPDATE —
// the only way a real revocation happens in this system today, the same
// technique revocation_epoch_e2e_integration_test.go's own proof1 uses to
// bump the epoch in the first place (Phase 12) — and shows the very next
// hook call for that exact request denies, not the stale ALLOW. The revoke
// is deliberately what also flips the request's own real answer, so the
// discriminator is the decision itself (exit code 0 vs. 2), not merely a
// reason string a bug could coincidentally still get right.
//
// Classified PROVEN ELSEWHERE, not a pass, for the identical reason C19
// above is: a real cache file on disk, a real epoch read from a real
// Postgres trigger (Phase 12), and a real subprocess are three things
// internal/authz's pure Decide function has no way to touch, by design
// (types.go's own package doc: "no database handles, no network clients, no
// ambient clock"). The property is real and now proven, just never provable
// at this layer.
func TestC20_StaleEpochCacheEntryNotServed(t *testing.T) {
	markRan(20)
	provenElsewhere(t, 20, in("internal/store", "TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry"))
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
	provenElsewhere(t, 21, in("internal/pdpgrpc",
		"TestDecide_Escalation_CreatesApprovalWithRootPrincipalAsApprover",
		"TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate"))
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
// Extended in Phase 6 Task 3: the pointer named only hook's own tests, which
// was incomplete rather than wrong — the property was already true of a
// second surface the pointer just did not yet name.
// TestDecideAndRelay_EscalationTimeout_Denies (mcp_authorize_test.go) proves
// the identical property for "mcp" — a still-pending approval at
// ApprovalTimeout denies there too, as a correlated JSON-RPC error rather
// than a PreToolUse exit code. It is not a second, independent proof of the
// same fact by coincidence: "mcp" reaches this outcome through the exact
// same resolveApproval/pollApproval (escalation.go) that hook's own tests
// above already exercise, reused unmodified — see this task's report for
// the seam analysis. Naming it here is what makes that true by construction, not
// merely by the two surfaces happening to agree today: a regression in
// resolveApproval's timeout handling now fails a test under BOTH
// hook_test.go and mcp_authorize_test.go, and this pointer is stale again if
// either one is ever renamed without the other being checked.
//
// Extended in Phase 11 Task 4 to name proxy's own two timeout tests, and
// NARROWED BACK to hook and mcp in Phase 15 Task 6 — a change to the
// property's reach, not a renaming, so it is recorded rather than quietly
// applied. Spec §4.7.2 K11 stopped proxy blocking on an escalation at all:
// a BOUND token degrades to a denial naming the pending approval (the
// proof it would wait with is single-use and short-lived, where a human
// approval is neither), and an UNBOUND one is refused outright by K5
// rather than paging a human for a decision that cannot change. proxy
// therefore no longer calls resolveApproval, so it has no escalation
// timeout left to prove, and TestAuthorize_EscalationTimeout_Denies and
// TestHandleStream_EscalationTimeout_DeniesWithoutForwarding were removed
// with the behaviour rather than left asserting a path nothing reaches.
//
// The property itself is untouched and still proven: resolveApproval and
// pollApproval are unchanged, and the three tests below exercise them
// under hook and mcp, which are still blocking surfaces. What changed is
// only which surfaces the property applies to — C22 is about a PEP that
// blocks, and proxy has stopped being one for the credential this phase
// requires. This pointer is stale again if any of the three is renamed.
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
	provenElsewhere(t, 22, in("cmd/stratium-pep",
		"TestRunHook_Escalate_TimeoutStillPendingDenies",
		"TestPollApproval_ContextCancelledMidPoll_ReturnsPromptlyAndDenies",
		"TestDecideAndRelay_EscalationTimeout_Denies"))
}

// C23 reads "on a non-blocking surface, escalate returns deny plus a
// pending record." Its reason went stale twice over: first from "Phase 4:
// requires the extauthz PEP mode" once Phase 5 shipped the response
// *mapping* a non-blocking surface would need (pdpgrpc.DegradeEscalateToDeny,
// proven directly by internal/pdpgrpc/nonblocking_test.go against every
// reachable Effect — escalate degrades to deny with approval_id retained, an
// ordinary deny fabricates no id, allow passes through unchanged, a
// defensive nil fails closed), and a second time once Phase 10 Tasks 1-3
// wired the extauthz mode itself into cmd/stratium-pep without this
// property being reassessed — flagged by both of those tasks' own reports
// and left for Task 4 to settle, per the phase plan.
//
// Phase 10 Task 4 is what closes the remaining gap: extauthz_integration_
// test.go's TestIntegration_Envoy_EscalateDeniesWithFindablePendingApproval_
// ApprovedRetrySucceeds sends an escalating request through a REAL Envoy, in
// front of a REAL stratium-pep extauthz, in front of a REAL stratium-pdp —
// not a constructed CheckRequest — and gets back a 403 carrying a pending
// approval's id in both a response header and the body text; approves that
// row out of band, exactly as the control plane would (the PDP itself has
// no UPDATE grant on approvals, E7); and confirms a retry then succeeds.
// That is "on a non-blocking surface, escalate returns deny plus a pending
// record" proven end to end, not merely the response-mapping fact Phase 5
// proved in isolation — DegradeEscalateToDeny's own first real caller
// (extauthz.go's checkResponseFromDecide) turned out to need no change, but
// a helper being the right shape and a surface actually using it correctly,
// live, are not the same claim, and only the second one is what C23 states.
//
// It still cannot become a pass HERE, for the same reason C16/C18/C19/C21/
// C22 above cannot: this is a property about a surface's own translation of
// a response it receives, over a real wire protocol, a concept
// internal/authz's pure decision function has no way to express even in
// principle. That is a structural fact about this package, unchanged by
// anything Task 4 built — the property is real and now proven, just never
// provable at this layer, the same shape as every other provenElsewhere
// pointer in this file.
func TestC23_NonBlockingSurfaceDegradesToDeny(t *testing.T) {
	markRan(23)
	provenElsewhere(t, 23, in("internal/store",
		"TestIntegration_Envoy_EscalateDeniesWithFindablePendingApproval_ApprovedRetrySucceeds"))
}

// TestC24_ExpiredDelegationDenied is C24: an expired TOKEN is denied even
// when a live CACHE entry exists. As of Phase 9 the token half was already
// real — an expired, signed token denies on its own, with no cache in the
// picture at all (TestDecide_ExpiredToken_Denies, internal/pdpgrpc/
// authenticate_test.go) — but what C24 actually names, a cache entry to
// override, stayed unbuilt until Phase 13 (Tasks 1-3, spec §4.8): W3's
// third condition, tokenNotExpired (cache.go), decodes the CALLER's own
// currently-presented token — not anything the cache entry itself recorded
// — so a credential that has since expired denies even against an
// otherwise-perfect hit, deliberately independent of delegationNotExpired
// (W3's second condition, "C24's time half" per cache.go's own W3 table).
//
// Phase 13 Task 4 is the live proof:
// TestIntegration_Cache_E2E_ExpiredTokenDeniedDespiteValidEntry
// (internal/store/cache_e2e_integration_test.go) mints a real, short-lived
// signed token (a real TTL, not a tampered claim), lets it actually pass its
// own "exp" in wall-clock time, and shows the SAME request that cached a
// live ALLOW moments earlier now denies. pdp-cache is stopped before that
// second call specifically so reissueAndRetryDecide (cmd/stratium-pep/
// reissue.go) cannot mint a fresh token and rescue the call on the fallback
// path — without that, a miss would still reach a live PDP and could come
// back ALLOWED again, proving nothing about the cache's own token check.
//
// Delegation expiry alone (the row itself, independent of any token or
// cache) is covered separately by TestDelegationLeg_DeniesExpiredHop.
//
// Classified PROVEN ELSEWHERE, not a pass, for the identical reason C19 and
// C20 above are: a real signed token actually expiring in wall-clock time,
// a real cache file, and a real stopped container are not things
// internal/authz's pure Decide function has any way to produce or observe
// (types.go's own package doc: "no database handles, no network clients, no
// ambient clock"). The property is real and now proven, just never provable
// at this layer.
func TestC24_ExpiredDelegationDenied(t *testing.T) {
	markRan(24)
	provenElsewhere(t, 24, in("internal/store", "TestIntegration_Cache_E2E_ExpiredTokenDeniedDespiteValidEntry"))
}

// C25's reason was re-checked the same way in Phase 14 Task 8 and REWRITTEN
// in Phase 15 Task 2, because the version before this one asserted a
// grep-checkable falsehood — "the string DPoP appears nowhere in services/ or
// proto/ outside this file" — which stopped being true when Task 1 landed
// internal/dpop and is doubly untrue now that proto/pdp/v1/pdp.proto carries
// dpop_jwk. A skip reason that states a verifiable fact and is wrong gets
// read as fact by whoever audits this suite next, so it is corrected here
// rather than left for the task that will delete it.
//
// RE-CHECKED AND REWRITTEN AGAIN in Phase 15 Task 5, under the rule the
// paragraph above states: the previous text asserted "DecideRequest carries
// no proof and no surface refuses an unbound token," and both halves are now
// false. Task 4 added dpop_proof/observed_method/observed_uri and made Decide
// verify a proof and deny a bound token presented without one; Task 5 made
// extauthz refuse an unbound token (K5). Leaving that sentence in place would
// be exactly the stale-fact-read-as-fact failure this entry has already had
// twice.
//
// RE-READ A THIRD TIME AND CONVERTED in Phase 15 Task 7. The notBuilt reason
// this entry carried until now — "proxy neither forwards a proof nor refuses
// an unbound token" — went stale in the OPPOSITE direction the moment Task 6
// landed: proxy now does both. That is the third time this one entry has
// stated a checkable fact that later became false, which is why the ruling
// below is written against the property's own sentence rather than against a
// summary of what the tree currently contains.
//
// WHAT C25 ACTUALLY ASSERTS, and what it does not. §7's row reads "a
// delegation token without a valid DPoP proof is denied when the token is
// sender-constrained," and §4.7.2 glosses it in as many words: it "covers a
// bound token presented without a proof." K5's converse — an UNBOUND token
// refused on the network surfaces — is a different sentence, and §4.7.2 says
// so explicitly ("K5 adds the converse"). Both of K5's live proofs exist
// (TestIntegration_Envoy_UnboundTokenRefusedEvenWhenPermitted and
// TestIntegration_Proxy_UnboundTokenRefusedEvenWhenPermitted) and NEITHER is
// named below. Padding this pointer with them would make C25 look better
// supported by counting a property it does not state — the exact overclaim
// this file has spent the phase correcting.
//
// THE POINTER SET, and why each name is load-bearing:
//
//   - internal/pdpgrpc names the three ways a proof fails to be valid at the
//     only layer that decides it (K2: the PDP verifies, nothing else does) —
//     absent (TestDecide_BoundTokenWithNoProof_Denies, errNoProof itself),
//     signed by the wrong key, and naming a different request. All three are
//     literally "a token without a VALID proof," and a pointer naming only
//     the absent case would check the narrowest reading of C25's own word.
//   - internal/store names the two surfaces the property is specified for,
//     live: a real bound token minted by a real containerized PDP, carried by
//     a real Envoy and a real gRPC proxy, refused when the proof is missing,
//     each with a control request proving the SAME token WITH a proof is
//     forwarded. Added by this task; they are what closes the gap between
//     "the PDP produces this denial" and "a caller actually receives it."
//
// Not named, deliberately: cmd/stratium-pep's own TestCheck_/TestAuthorize_/
// TestHandleStream_BoundTokenWithNoProof_* prove the surfaces relay the PDP's
// reason VERBATIM against a fake PDP — a message-quality property, and one
// the two live proofs above now subsume for C25's purposes. Also not named:
// K8's single-use jti (TestIntegration_Proxy_ReplayedProofRefused,
// TestIntegration_Decide_ReplayedProof_Denies). A spent proof is arguably
// "not valid" too, but K8 is its own requirement and folding it in here would
// blur which sentence this row is accountable for.
//
// The test names above and below are ILLUSTRATIVE and UNCHECKED — they record
// which properties were deliberately kept out of the pointer, not what holds
// this row up. Only the names inside provenElsewhere are AST-verified, and a
// rename there fails the gate. If one of these drifts, the exclusion reasoning
// still stands; do not promote a prose name into the pointer to "fix" it. This
// entry's reason went stale three times before it was ever converted, twice in
// the direction of claiming more than was built.
//
// PROVEN ELSEWHERE, NOT A PASS, and not a close call. C25 is a property about
// a TOKEN — its signature, its cnf.jkt confirmation claim, and a detached
// JWS proving possession of the key that claim names. internal/authz has no
// token. Not "does not check one": authz.Request (types.go) has no token
// field, no credential of any kind, and this package imports no JWT library,
// because Decide is a pure function that receives already-loaded facts (this
// package's own doc comment: "no database handles, no network clients, no
// ambient clock"). Token verification, matchProof, and the spent-jti store
// all live in internal/pdpgrpc, which imports THIS package — so the reverse
// dependency a local proof would need is a genuine build cycle, not merely a
// purity violation. Same shape as C16/C18/C19/C20/C21/C22/C23/C24 above.
func TestC25_MissingDPoPProofDenies(t *testing.T) {
	markRan(25)
	provenElsewhere(t, 25,
		in("internal/pdpgrpc",
			"TestDecide_BoundTokenWithNoProof_Denies",
			"TestDecide_ProofSignedByADifferentKey_Denies",
			"TestDecide_ProofNamingADifferentRequest_Denies"),
		in("internal/store",
			"TestIntegration_Envoy_BoundTokenWithNoProofRefused",
			"TestIntegration_Proxy_BoundTokenWithNoProofRefused"))
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
	17: "TestC17_RawInputIsNeverRetained",
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
