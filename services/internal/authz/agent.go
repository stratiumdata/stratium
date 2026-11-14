package authz

import (
	"fmt"

	"github.com/stratiumdata/stratium/pkg/models"
)

// TrustTable maps an action tier to the minimum agent trust tier that may
// perform it. The comparison is structural; the table itself is plain data.
//
// Spec §4.3 describes this table as subject to the same raise-only override
// mechanism as the action-tier table, but that is aspirational, not built:
// there is no ValidateTrustTable or equivalent, so nothing today stops a
// tenant-supplied table from requiring LESS trust than DefaultTrustTable.
// Spec §8 lists "Trust-tier table overrides" as an open item ("confirm or
// reverse") for exactly this reason.
// TODO(phase-2): decide per spec section 8. If raise-only is confirmed, add
// write-time validation analogous to ValidateOverride. Until then
// TestDefaultTrustTableIsTheOnlyConstructionSite (trusttable_guard_test.go)
// keeps the gap latent by failing the build on a second construction site.
type TrustTable struct {
	Required map[models.ActionTier]models.AgentTrustTier
}

// DefaultTrustTable is the shipped mapping.
//
// The admin console states these floors in prose, on the agent form's Trust
// tier field (clients/ui/src/screens/agents.tsx): "REGISTERED for
// INTERNAL_MODIFY, CERTIFIED for EXTERNAL_COMMS, PLATFORM_TRUSTED for
// DESTRUCTIVE. UNVERIFIED reaches only REASONING and READ_ONLY." Change a row
// here and that sentence starts misinforming an operator about a security
// floor, with nothing to catch it -- prose is not compilable. Update it in the
// same commit.
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
