package authz

import (
	"testing"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

func agentInfo(trust models.AgentTrustTier, tools []string) AgentInfo {
	return AgentInfo{ID: uuid.New(), TrustTier: trust, Enabled: true, AllowedTools: tools}
}

func TestAgentLeg_AllowsSufficientTrust(t *testing.T) {
	a := agentInfo(models.TrustTierCertified, []string{"Bash"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierExternalComms, DefaultTrustTable()); got.Effect != EffectAllow {
		t.Fatalf("certified agent should perform tier 3, got %v: %s", got.Effect, got.Reason)
	}
}

func TestAgentLeg_DeniesInsufficientTrust(t *testing.T) {
	a := agentInfo(models.TrustTierRegistered, []string{"Bash"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierDestructive, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("registered agent must not perform tier 4, got %v", got.Effect)
	}
}

func TestAgentLeg_DeniesToolNotAllowed(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, []string{"Read"})
	if got := AgentLeg(a, Action{Tool: "Bash"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("tool outside the allowlist must deny, got %v", got.Effect)
	}
}

// A disabled or suspended agent denies regardless of trust. (C10)
func TestAgentLeg_DeniesDisabledAgent(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, nil)
	a.Enabled = false
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("disabled agent must deny, got %v", got.Effect)
	}
}

func TestAgentLeg_DeniesSuspendedAgent(t *testing.T) {
	a := agentInfo(models.TrustTierPlatformTrusted, nil)
	a.Suspended = true
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectDeny {
		t.Fatalf("suspended agent must deny, got %v", got.Effect)
	}
}

// An empty allowlist is unrestricted, matching Agent.HasTool and
// Delegation.HasTool. The delegation leg is the real constraint.
func TestAgentLeg_EmptyToolListUnrestricted(t *testing.T) {
	a := agentInfo(models.TrustTierCertified, nil)
	if got := AgentLeg(a, Action{Tool: "anything"}, models.ActionTierReadOnly, DefaultTrustTable()); got.Effect != EffectAllow {
		t.Fatalf("an empty allowlist should not restrict, got %v: %s", got.Effect, got.Reason)
	}
}

// The trust table is data, so a tenant may require more trust than default.
func TestAgentLeg_TenantTableCanRaiseRequirement(t *testing.T) {
	strict := TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{
		models.ActionTierReadOnly: models.TrustTierCertified,
	}}
	a := agentInfo(models.TrustTierRegistered, nil)
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierReadOnly, strict); got.Effect != EffectDeny {
		t.Fatalf("a stricter tenant table must deny, got %v", got.Effect)
	}
}

// A tier absent from the table demands the highest trust rather than permitting.
func TestAgentLeg_MissingTierEntryFailsClosed(t *testing.T) {
	empty := TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{}}
	a := agentInfo(models.TrustTierCertified, nil)
	if got := AgentLeg(a, Action{Tool: "Read"}, models.ActionTierDestructive, empty); got.Effect != EffectDeny {
		t.Fatalf("a missing table entry must fail closed, got %v", got.Effect)
	}
}

func TestDefaultTrustTable_CoversEveryActionTier(t *testing.T) {
	table := DefaultTrustTable()
	for tier := models.ActionTierReasoning; tier <= models.ActionTierDestructive; tier++ {
		if _, ok := table.Required[tier]; !ok {
			t.Errorf("default trust table has no entry for %s", tier)
		}
	}
}
