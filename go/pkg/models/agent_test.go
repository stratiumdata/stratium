package models

import (
	"testing"
)

func TestAgentTrustTier_String(t *testing.T) {
	tests := []struct {
		tier AgentTrustTier
		want string
	}{
		{TrustTierUnverified, "unverified"},
		{TrustTierRegistered, "registered"},
		{TrustTierCertified, "certified"},
		{TrustTierPlatformTrusted, "platform-trusted"},
		{AgentTrustTier(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("AgentTrustTier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

func TestActionTier_String(t *testing.T) {
	tests := []struct {
		tier ActionTier
		want string
	}{
		{ActionTierReasoning, "reasoning"},
		{ActionTierReadOnly, "read-only"},
		{ActionTierInternalModify, "internal-modify"},
		{ActionTierExternalComms, "external-comms"},
		{ActionTierDestructive, "destructive"},
		{ActionTier(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.tier.String(); got != tt.want {
			t.Errorf("ActionTier(%d).String() = %q, want %q", tt.tier, got, tt.want)
		}
	}
}

func TestAgent_MaxActionTier(t *testing.T) {
	agent := &Agent{
		AllowedActions: []ActionTier{ActionTierReadOnly, ActionTierInternalModify, ActionTierReasoning},
	}
	if got := agent.MaxActionTier(); got != ActionTierInternalModify {
		t.Errorf("MaxActionTier() = %v, want %v", got, ActionTierInternalModify)
	}

	emptyAgent := &Agent{AllowedActions: []ActionTier{}}
	if got := emptyAgent.MaxActionTier(); got != ActionTierReasoning {
		t.Errorf("MaxActionTier() for empty = %v, want %v", got, ActionTierReasoning)
	}
}

func TestAgent_HasTool(t *testing.T) {
	agent := &Agent{
		AllowedTools: []string{"read_file", "write_file", "search"},
	}

	if !agent.HasTool("read_file") {
		t.Error("HasTool(read_file) should be true")
	}
	if agent.HasTool("delete_file") {
		t.Error("HasTool(delete_file) should be false")
	}
}
