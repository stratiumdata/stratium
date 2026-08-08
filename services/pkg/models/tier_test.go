package models

import (
	"errors"
	"testing"
)

// Tier values are ordinal — the whole authorization model compares them with
// < and >. A reordering silently changes every ceiling in the system.
func TestActionTier_Ordering(t *testing.T) {
	ordered := []ActionTier{
		ActionTierReasoning,
		ActionTierReadOnly,
		ActionTierInternalModify,
		ActionTierExternalComms,
		ActionTierDestructive,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("action tiers must strictly increase: %v >= %v", ordered[i-1], ordered[i])
		}
	}
	if ActionTierReasoning != 0 {
		t.Fatal("ActionTierReasoning must be 0 — the least-privileged default")
	}
}

func TestAgentTrustTier_Ordering(t *testing.T) {
	ordered := []AgentTrustTier{
		TrustTierUnverified,
		TrustTierRegistered,
		TrustTierCertified,
		TrustTierPlatformTrusted,
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1] >= ordered[i] {
			t.Fatalf("trust tiers must strictly increase: %v >= %v", ordered[i-1], ordered[i])
		}
	}
	if TrustTierUnverified != 0 {
		t.Fatal("TrustTierUnverified must be 0 — an unpopulated agent is untrusted")
	}
}

func TestActionTier_String(t *testing.T) {
	cases := map[ActionTier]string{
		ActionTierReasoning:      "REASONING",
		ActionTierReadOnly:       "READ_ONLY",
		ActionTierInternalModify: "INTERNAL_MODIFY",
		ActionTierExternalComms:  "EXTERNAL_COMMS",
		ActionTierDestructive:    "DESTRUCTIVE",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("ActionTier(%d).String() = %q, want %q", tier, got, want)
		}
	}
}

// An out-of-range tier must render distinguishably rather than as a valid name,
// so a corrupt value cannot masquerade as READ_ONLY in an audit record.
func TestActionTier_StringOutOfRange(t *testing.T) {
	if got := ActionTier(99).String(); got == "READ_ONLY" || got == "" {
		t.Fatalf("out-of-range tier rendered as %q", got)
	}
}

func TestAgentTrustTier_String(t *testing.T) {
	cases := map[AgentTrustTier]string{
		TrustTierUnverified:      "UNVERIFIED",
		TrustTierRegistered:      "REGISTERED",
		TrustTierCertified:       "CERTIFIED",
		TrustTierPlatformTrusted: "PLATFORM_TRUSTED",
	}
	for tier, want := range cases {
		if got := tier.String(); got != want {
			t.Errorf("AgentTrustTier(%d).String() = %q, want %q", tier, got, want)
		}
	}
}

// Values arriving over the wire must be range-checked, not cast.
func TestParseActionTier(t *testing.T) {
	for i := 0; i <= 4; i++ {
		if _, err := ParseActionTier(i); err != nil {
			t.Errorf("ParseActionTier(%d) should succeed: %v", i, err)
		}
	}
	for _, bad := range []int{-1, 5, 99} {
		if _, err := ParseActionTier(bad); !errors.Is(err, ErrInvalidTier) {
			t.Errorf("ParseActionTier(%d) should reject, got %v", bad, err)
		}
	}
}
