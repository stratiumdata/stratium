// Package models holds Stratium's domain types.
//
// Tier values are ordinal and compared with < and >. Their numeric order is
// load-bearing: it defines every ceiling in the authorization model. The zero
// value of each is the least-privileged member, so an unpopulated struct is
// never accidentally privileged.
package models

import (
	"errors"
	"fmt"
)

// ErrInvalidTier indicates a tier value outside the defined range.
var ErrInvalidTier = errors.New("tier value out of range")

// ActionTier is the sensitivity of an attempted action.
type ActionTier int

const (
	ActionTierReasoning      ActionTier = 0 // no side effects
	ActionTierReadOnly       ActionTier = 1 // reads data
	ActionTierInternalModify ActionTier = 2 // mutates internal state
	ActionTierExternalComms  ActionTier = 3 // reaches outside the trust boundary
	ActionTierDestructive    ActionTier = 4 // irreversible or financially binding
)

func (t ActionTier) String() string {
	switch t {
	case ActionTierReasoning:
		return "REASONING"
	case ActionTierReadOnly:
		return "READ_ONLY"
	case ActionTierInternalModify:
		return "INTERNAL_MODIFY"
	case ActionTierExternalComms:
		return "EXTERNAL_COMMS"
	case ActionTierDestructive:
		return "DESTRUCTIVE"
	default:
		return fmt.Sprintf("INVALID_ACTION_TIER(%d)", int(t))
	}
}

// ParseActionTier range-checks a wire value. Casting an untrusted int directly
// to ActionTier would admit values outside the lattice.
func ParseActionTier(v int) (ActionTier, error) {
	if v < int(ActionTierReasoning) || v > int(ActionTierDestructive) {
		return ActionTierReasoning, fmt.Errorf("%w: action tier %d", ErrInvalidTier, v)
	}
	return ActionTier(v), nil
}

// AgentTrustTier is how much an agent is trusted by the platform.
type AgentTrustTier int

const (
	TrustTierUnverified      AgentTrustTier = 0
	TrustTierRegistered      AgentTrustTier = 1
	TrustTierCertified       AgentTrustTier = 2
	TrustTierPlatformTrusted AgentTrustTier = 3
)

func (t AgentTrustTier) String() string {
	switch t {
	case TrustTierUnverified:
		return "UNVERIFIED"
	case TrustTierRegistered:
		return "REGISTERED"
	case TrustTierCertified:
		return "CERTIFIED"
	case TrustTierPlatformTrusted:
		return "PLATFORM_TRUSTED"
	default:
		return fmt.Sprintf("INVALID_TRUST_TIER(%d)", int(t))
	}
}
