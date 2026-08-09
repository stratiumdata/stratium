package authz

import (
	"fmt"

	"stratium/pkg/models"
)

// TrustTable maps an action tier to the minimum agent trust tier that may
// perform it. The comparison is structural; the table is data, so a tenant can
// require more trust than the default — never less (spec §4.3).
type TrustTable struct {
	Required map[models.ActionTier]models.AgentTrustTier
}

// DefaultTrustTable is the shipped mapping.
func DefaultTrustTable() TrustTable {
	return TrustTable{Required: map[models.ActionTier]models.AgentTrustTier{
		models.ActionTierReasoning:      models.TrustTierUnverified,
		models.ActionTierReadOnly:       models.TrustTierUnverified,
		models.ActionTierInternalModify: models.TrustTierRegistered,
		models.ActionTierExternalComms:  models.TrustTierCertified,
		models.ActionTierDestructive:    models.TrustTierPlatformTrusted,
	}}
}

// requiredTrust returns the minimum trust for an action tier. A tier absent
// from the table returns the highest requirement — an unmapped tier fails
// closed rather than permitting.
func (t TrustTable) requiredTrust(a models.ActionTier) models.AgentTrustTier {
	if req, ok := t.Required[a]; ok {
		return req
	}
	return models.TrustTierPlatformTrusted
}

// AgentLeg evaluates the acting agent's own authority: enabled, trusted enough
// for this tier, and permitted this tool.
//
// derived is the server-computed tier; the declared value never reaches here.
func AgentLeg(agent AgentInfo, a Action, derived models.ActionTier, table TrustTable) LegResult {
	if !agent.Enabled {
		return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf("agent %s is disabled", agent.ID)}
	}
	if agent.Suspended {
		return LegResult{Effect: EffectDeny, Reason: fmt.Sprintf("agent %s is suspended", agent.ID)}
	}

	if required := table.requiredTrust(derived); agent.TrustTier < required {
		return LegResult{Effect: EffectDeny,
			Reason: fmt.Sprintf("agent trust tier %s insufficient for action tier %s (requires %s)",
				agent.TrustTier, derived, required)}
	}

	if a.Tool != "" && len(agent.AllowedTools) > 0 {
		found := false
		for _, tool := range agent.AllowedTools {
			if tool == a.Tool {
				found = true
				break
			}
		}
		if !found {
			return LegResult{Effect: EffectDeny,
				Reason: fmt.Sprintf("tool %q not in agent allowed_tools", a.Tool)}
		}
	}

	return LegResult{Effect: EffectAllow}
}
