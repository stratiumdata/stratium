package authz

import (
	"testing"

	"github.com/google/uuid"

	"stratium/pkg/models"
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

// Result surfaces every verdict consulted, in order, and names the one the
// reason was attributed to — not just the folded LegResult — so an auditor
// can trace a decision to a specific policy. (Phase 2b Task 2)
func TestDecide_ReportsPrincipalVerdictsAndDeciding(t *testing.T) {
	req := request()
	allow := PolicyVerdict{Effect: EffectAllow, Reason: "granted", Source: "rego", PolicyID: "p-2"}
	deny := PolicyVerdict{Effect: EffectDeny, Reason: "blocked", Source: "cedar", PolicyID: "p-1"}
	req.PrincipalVerdicts = []PolicyVerdict{allow, deny}

	got := Decide(req, config())

	if len(got.PrincipalVerdicts) != 2 || got.PrincipalVerdicts[0] != allow || got.PrincipalVerdicts[1] != deny {
		t.Fatalf("PrincipalVerdicts must be every verdict consulted, in the order supplied, got %+v", got.PrincipalVerdicts)
	}
	if got.Deciding == nil || *got.Deciding != deny {
		t.Fatalf("Deciding must name the verdict the reason was attributed to, got %+v", got.Deciding)
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
