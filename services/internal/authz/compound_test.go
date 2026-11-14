package authz

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

func request() Request {
	agent := agentInfo(models.TrustTierPlatformTrusted, nil)
	root := delegation(0, models.ActionTierDestructive, nil)
	linkChain("tenant-a", agent.ID, root)
	return Request{
		TenantID:          "tenant-a",
		Principal:         Principal{Subject: "alice@example.com"},
		Agent:             agent,
		Chain:             []*models.Delegation{root},
		Action:            Action{Tool: "Read", Verb: "read"},
		Now:               authzNow,
		PrincipalVerdicts: []PolicyVerdict{{Effect: EffectAllow}},
	}
}

func config() Config {
	return Config{Tiers: TierTable{}, Trust: DefaultTrustTable(), MaxDepth: 5}
}

func TestDecide_AllowsWhenAllLegsAllow(t *testing.T) {
	if got := Decide(request(), config()); got.Effect != EffectAllow {
		t.Fatalf("all legs allow should allow, got %v: %s", got.Effect, got.Reason)
	}
}

// Every leg is evaluated and reported. (C11)
func TestDecide_ReportsAllThreeLegs(t *testing.T) {
	got := Decide(request(), config())
	for name, leg := range map[string]LegResult{
		"principal": got.Principal, "agent": got.Agent, "delegation": got.Delegation,
	} {
		if leg.Effect != EffectAllow {
			t.Errorf("leg %s should be ALLOW, got %v", name, leg.Effect)
		}
	}
}

// A principal decision left at its zero value denies. This is the defect that
// made the previous compound decision silently two-legged. (C11, C13)
func TestDecide_UnevaluatedPrincipalDenies(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = nil
	got := Decide(req, config())
	if got.Effect != EffectDeny {
		t.Fatalf("an unevaluated principal leg must deny, got %v", got.Effect)
	}
	if got.DeniedLeg != "principal" {
		t.Fatalf("denial should be attributed to principal, got %q", got.DeniedLeg)
	}
	// Nil, not a zero-value &PolicyVerdict{}: "no policy spoke" and "a policy
	// denied" are different facts, and papering over the difference would
	// forge attribution to a policy that was never evaluated.
	if got.Deciding != nil {
		t.Fatalf("default-deny with no verdict at all must leave Deciding nil, got %+v", got.Deciding)
	}
}

// Result names the verdict the reason was attributed to — not just the
// folded LegResult — so an auditor can trace a decision to a specific
// policy. (Phase 2b Task 2)
//
// Result.PrincipalVerdicts (every verdict consulted, in order) used to be
// asserted here too. It was deleted: nothing in production ever read it —
// pdpgrpc's appendAudit/toResponse both read Deciding alone — and the one
// thing it might have been for (recovering a verdict that lost the fold) is
// now served by the purpose-built UnevaluatedPolicyIDs aggregate below, not
// by re-deriving it from the raw slice.
func TestDecide_ReportsDeciding(t *testing.T) {
	req := request()
	allow := PolicyVerdict{Effect: EffectAllow, Reason: "granted", Source: "rego", PolicyID: "p-2"}
	deny := PolicyVerdict{Effect: EffectDeny, Reason: "blocked", Source: "cedar", PolicyID: "p-1"}
	req.PrincipalVerdicts = []PolicyVerdict{allow, deny}

	got := Decide(req, config())

	// reflect.DeepEqual, not !=: PolicyVerdict gained a []string field
	// (UnevaluatedPolicyIDs), which makes it non-comparable with ==.
	if got.Deciding == nil || !reflect.DeepEqual(*got.Deciding, deny) {
		t.Fatalf("Deciding must name the verdict the reason was attributed to, got %+v", got.Deciding)
	}
}

// The property this whole change exists for: UnevaluatedPolicyIDs must
// survive even when the verdict that carries it LOSES FoldVerdicts' own
// tie-break. Source is the language name and cedar sorts before rego, so an
// orphaned "rego" verdict alongside any Cedar verdict never becomes
// Deciding — reading this field off Deciding alone (rather than aggregating
// the whole slice) would silently lose it in exactly this shape, which is
// also why it is the one TestIntegration_Live_OrphanLanguageDeniesNamingIt
// (internal/store, live over gRPC) exists to prove end to end.
func TestDecide_UnevaluatedPolicyIDsSurviveLosingTheFold(t *testing.T) {
	req := request()
	cedarDeny := PolicyVerdict{Effect: EffectDeny, Reason: "forbidden", Source: "cedar", PolicyID: "cedar-1"}
	regoOrphan := PolicyVerdict{
		Effect:               EffectDeny,
		Source:               "rego",
		Reason:               "principal: no rego engine registered; cannot evaluate 2 rego policies for this tenant",
		UnevaluatedPolicyIDs: []string{"rego-2", "rego-1"},
	}
	req.PrincipalVerdicts = []PolicyVerdict{cedarDeny, regoOrphan}

	got := Decide(req, config())

	if got.Deciding == nil || got.Deciding.Source != "cedar" {
		t.Fatalf("Deciding = %+v, want the cedar verdict (cedar sorts before rego, so it wins the tie-break)", got.Deciding)
	}
	want := []string{"rego-1", "rego-2"}
	if !slices.Equal(got.UnevaluatedPolicyIDs, want) {
		t.Errorf("UnevaluatedPolicyIDs = %v, want %v — the orphaned rego ids must survive even though cedar decided",
			got.UnevaluatedPolicyIDs, want)
	}
}

// UnevaluatedPolicyIDs must come back sorted and deduplicated regardless of
// the order verdicts arrived in or whether more than one verdict names the
// same id — required determinism, not a cosmetic nicety: pkg/audit.Entry.
// Hash commits to this exact value, so a run that reordered it between two
// otherwise-identical decisions would fork the audit hash chain.
func TestDecide_UnevaluatedPolicyIDsSortedAndDeduplicated(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{
		{Effect: EffectDeny, Source: "rego", UnevaluatedPolicyIDs: []string{"z-policy", "a-policy"}},
		{Effect: EffectDeny, Source: "xacml", UnevaluatedPolicyIDs: []string{"a-policy", "m-policy"}},
	}

	got := Decide(req, config())

	want := []string{"a-policy", "m-policy", "z-policy"}
	if !slices.Equal(got.UnevaluatedPolicyIDs, want) {
		t.Fatalf("UnevaluatedPolicyIDs = %v, want %v (sorted, deduplicated)", got.UnevaluatedPolicyIDs, want)
	}
}

// An ordinary decision — no orphaned or unprepared language involved —
// must leave UnevaluatedPolicyIDs empty, not populated with zero-valued
// noise, so its presence in an audit row is a genuine signal.
func TestDecide_UnevaluatedPolicyIDsEmptyWhenNothingOrphaned(t *testing.T) {
	got := Decide(request(), config())
	if len(got.UnevaluatedPolicyIDs) != 0 {
		t.Fatalf("UnevaluatedPolicyIDs = %v, want empty: request()'s fixture has no orphaned or unprepared language",
			got.UnevaluatedPolicyIDs)
	}
}

// Any single deny overrides. (C12)
func TestDecide_AnyDenyOverrides(t *testing.T) {
	cases := map[string]func(*Request){
		"principal":  func(r *Request) { r.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectDeny, Reason: "no"}} },
		"agent":      func(r *Request) { r.Agent.Enabled = false },
		"delegation": func(r *Request) { r.Chain[0].Revoked = true },
	}
	for leg, mutate := range cases {
		t.Run(leg, func(t *testing.T) {
			req := request()
			mutate(&req)
			got := Decide(req, config())
			if got.Effect != EffectDeny {
				t.Fatalf("%s deny must override, got %v", leg, got.Effect)
			}
			if got.DeniedLeg != leg {
				t.Fatalf("expected denied_leg %q, got %q", leg, got.DeniedLeg)
			}
		})
	}
}

// An allowing policy cannot exceed the delegation ceiling — the legs are
// independent AND terms. (C14)
func TestDecide_PolicyCannotExceedCeiling(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectAllow, Reason: "policy grants everything"}}
	req.Chain = linkChain(req.TenantID, req.Agent.ID, delegation(0, models.ActionTierReadOnly, nil))
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.Effect != EffectDeny || got.DeniedLeg != "delegation" {
		t.Fatalf("policy must not exceed the ceiling, got %v/%s", got.Effect, got.DeniedLeg)
	}
}

// A fabricated chain must never reach ALLOW merely because Decide trusts
// whatever slice it is handed: mixed tenants, a fabricated depth, an orphan
// parent pointer, and an acting delegation issued to a different agent than
// the requester. This is the exact shape of chain a review probe once got
// ALLOW from — the reason ValidateChain exists.
func TestDecide_RejectsFabricatedChain(t *testing.T) {
	req := request() // req.TenantID == "tenant-a"

	root := delegation(0, models.ActionTierDestructive, nil)
	root.TenantID = "tenant-b"
	root.RootDelegationID = root.ID

	orphanParent := uuid.New()
	fabricated := delegation(9, models.ActionTierDestructive, nil) // fabricated depth
	fabricated.TenantID = "tenant-c"
	fabricated.RootDelegationID = root.ID
	fabricated.ParentDelegationID = &orphanParent // points nowhere
	fabricated.AgentID = uuid.New()               // a different agent than the requester

	req.Chain = []*models.Delegation{root, fabricated}
	got := Decide(req, config())
	if got.Effect != EffectDeny {
		t.Fatalf("a fabricated chain must deny, got %v", got.Effect)
	}
	if got.DeniedLeg != "delegation" {
		t.Fatalf("a fabricated chain must be attributed to the delegation leg, got %q", got.DeniedLeg)
	}
}

func TestDecide_UnderDeclaredTierDenies(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete", DeclaredTier: tierPtr(models.ActionTierReadOnly)}
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("under-declaration must deny, got %v", got.Effect)
	}
}

// The derived tier is always reported so audit records what was enforced.
func TestDecide_ReportsDerivedTier(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	if got := Decide(req, config()); got.DerivedTier != models.ActionTierDestructive {
		t.Fatalf("expected DESTRUCTIVE, got %v", got.DerivedTier)
	}
}

func TestDecide_UnknownActionDenies(t *testing.T) {
	req := request()
	req.Action = Action{Tool: "Weird", Verb: "frobnicate"}
	cfg := config()
	cfg.Tiers.DenyUnknown = true
	if got := Decide(req, cfg); got.Effect != EffectDeny {
		t.Fatalf("an unclassifiable action must deny, got %v", got.Effect)
	}
}

// A bare escalate — no companion allow — is sufficient to escalate. Escalate
// is a grant with a condition attached ("allow, pending human approval"), so
// it satisfies default-deny on its own (FoldVerdicts step 2).
func TestDecide_EscalatePropagatesWhenNothingDenies(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectEscalate, Reason: "approval required"}}
	if got := Decide(req, config()); got.Effect != EffectEscalate {
		t.Fatalf("expected ESCALATE, got %v", got.Effect)
	}
}

// Deny-overrides applies to every non-allow, including escalate.
func TestDecide_DenyBeatsEscalate(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectEscalate, Reason: "approval required"}}
	req.Agent.Enabled = false
	if got := Decide(req, config()); got.Effect != EffectDeny {
		t.Fatalf("deny must beat escalate, got %v", got.Effect)
	}
}

// The two tests above prove Decide's own combining logic — the loop in
// compound.go that surfaces escalate once nothing denies — using a
// PolicyVerdict built by hand. That has been true, and tested, since before
// this field existed: FoldVerdicts and Decide have always known what to do
// with EffectEscalate once something hands them one. What has never existed
// until this delegation field is a real, non-fabricated PRODUCER of one — a
// domain object an operator actually persists, not a literal a test
// constructs. This test is the first one in the suite that reaches
// EFFECT_ESCALATE by driving genuine input (a models.Delegation with
// EscalateAt set) through the real chain: DelegationLeg computes the leg,
// Decide's existing escalate loop (unchanged by this phase) picks it up.
// Both halves worked correctly the first time this was exercised end to
// end — see the Phase 5 Task 1 report for the full account.
func TestDecide_DelegationEscalateAtReachesResultThroughRealPath(t *testing.T) {
	req := request()
	// request()'s root delegation caps at DESTRUCTIVE (4); EXTERNAL_COMMS
	// (3) sets a threshold strictly below that ceiling, so the band is
	// [3,4] — a real (not degenerate) two-tier band, not just a single
	// point equal to the ceiling.
	req.Chain[0].EscalateAt = tierPtr(models.ActionTierExternalComms)
	req.Action = Action{Tool: "Bash", Verb: "delete"} // derives DESTRUCTIVE (4); see TestDecide_ReportsDerivedTier

	got := Decide(req, config())
	if got.Effect != EffectEscalate {
		t.Fatalf("expected ESCALATE from a real delegation threshold, got %v: %s", got.Effect, got.Reason)
	}
	if got.Delegation.Effect != EffectEscalate {
		t.Fatalf("the delegation leg itself must report ESCALATE, got %v", got.Delegation.Effect)
	}
	if got.Reason == "" {
		t.Fatal("an escalate must carry a reason, same as a denial does")
	}
	// Escalate is not a denial: a caller reading DeniedLeg/DeniedAtDepth
	// instead of Effect must not mistake this for one.
	if got.DeniedLeg != "" {
		t.Fatalf("DeniedLeg = %q, want empty: escalate is not attributed as a denial", got.DeniedLeg)
	}
	if got.DeniedAtDepth != -1 {
		t.Fatalf("DeniedAtDepth = %d, want -1: escalate is not a denial", got.DeniedAtDepth)
	}
}

// A chain denial reports the depth; a non-chain denial leaves it at -1.
func TestDecide_DeniedAtDepth(t *testing.T) {
	req := request()
	req.Chain = linkChain(req.TenantID, req.Agent.ID,
		delegation(0, models.ActionTierDestructive, nil),
		delegation(1, models.ActionTierReadOnly, nil),
	)
	req.Action = Action{Tool: "Bash", Verb: "delete"}
	got := Decide(req, config())
	if got.DeniedAtDepth != 1 {
		t.Fatalf("expected depth 1, got %d", got.DeniedAtDepth)
	}

	req2 := request()
	req2.Agent.Enabled = false
	if got := Decide(req2, config()); got.DeniedAtDepth != -1 {
		t.Fatalf("a non-chain denial must leave depth at -1, got %d", got.DeniedAtDepth)
	}
}

// A denial always carries a reason — an empty one is useless in an audit record.
func TestDecide_DenialAlwaysHasReason(t *testing.T) {
	req := request()
	req.PrincipalVerdicts = []PolicyVerdict{{Effect: EffectDeny}} // no reason supplied
	if got := Decide(req, config()); got.Reason == "" {
		t.Fatal("a denial must always carry a reason")
	}
}

// TestDeriveTierDenial pins the exact shape Decide's own DeriveTier-error
// branch relies on (see TestDecide_UnknownActionDenies below, which proves
// Decide actually produces this through the real code path) — and the shape
// pdpgrpc/server.go's own pre-derivation now calls this same function to
// build, rather than inventing a second, divergent DENY-and-audit path. See
// that file's Decide method doc comment for why a second call site exists at
// all: the policy engine needs the tier before Decide can be called, since
// Decide takes the already-evaluated principal verdicts as an input.
func TestDeriveTierDenial(t *testing.T) {
	err := errors.New("boom: could not classify this action")
	got := DeriveTierDenial(err)

	if got.Effect != EffectDeny {
		t.Errorf("Effect = %v, want EffectDeny", got.Effect)
	}
	if got.DeniedLeg != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q (the tier ceiling is structural, never policy-configurable)", got.DeniedLeg, "delegation")
	}
	if got.Reason != err.Error() {
		t.Errorf("Reason = %q, want %q", got.Reason, err.Error())
	}
	if got.Delegation.Effect != EffectDeny || got.Delegation.Reason != err.Error() {
		t.Errorf("Delegation = %+v, want {Effect: EffectDeny, Reason: %q}", got.Delegation, err.Error())
	}
	if got.DeniedAtDepth != -1 {
		t.Errorf("DeniedAtDepth = %d, want -1 (not a chain-position denial)", got.DeniedAtDepth)
	}
	if got.Deciding != nil {
		t.Errorf("Deciding = %+v, want nil: no policy verdict was ever consulted on this path", got.Deciding)
	}
}
