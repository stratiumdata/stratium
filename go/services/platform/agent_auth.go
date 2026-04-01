package platform

import (
	"stratium/features"
)

// evaluateCompoundDecision evaluates agent authorization as part of GetDecision.
// Returns nil if agent-auth is disabled or no agent attributes are present.
func (s *Server) evaluateCompoundDecision(req *GetDecisionRequest, userDecision *DecisionResult) *CompoundDecision {
	if !features.ShouldEnableAgentAuth() {
		return nil
	}

	// Check if this is an agent-authorized request
	hasAgentAttrs := req.AgentAttributes != nil && req.AgentAttributes.AgentId != ""
	hasChain := len(req.AgentChain) > 0

	if !hasAgentAttrs && !hasChain {
		return nil
	}

	compound := &CompoundDecision{
		UserDecision: userDecision.Decision,
		UserReason:   userDecision.Reason,
		DeniedAtDepth: -1,
	}

	// If user is denied, short-circuit — no need to evaluate agent/delegation
	if userDecision.Decision == Decision_DECISION_DENY {
		compound.DeniedAtDepth = -1 // User level, before chain
		compound.DeniedPrincipal = "user"
		return compound
	}

	// Single-agent evaluation
	if hasAgentAttrs && !hasChain {
		agentAllowed, agentReason := evaluateAgentAttributes(req.AgentAttributes, req.DelegationContext)
		if agentAllowed {
			compound.AgentDecision = Decision_DECISION_ALLOW
		} else {
			compound.AgentDecision = Decision_DECISION_DENY
			compound.AgentReason = agentReason
			compound.DeniedAtDepth = 0
			compound.DeniedPrincipal = "agent:" + req.AgentAttributes.AgentId
		}

		delegationAllowed, delegationReason := evaluateDelegationContext(req.DelegationContext, req.ResourceAttributes)
		if delegationAllowed {
			compound.DelegationDecision = Decision_DECISION_ALLOW
		} else {
			compound.DelegationDecision = Decision_DECISION_DENY
			compound.DelegationReason = delegationReason
			if compound.DeniedAtDepth < 0 {
				compound.DeniedAtDepth = 0
				compound.DeniedPrincipal = "delegation:" + req.DelegationContext.DelegationId
			}
		}

		return compound
	}

	// Chain evaluation
	if hasChain {
		compound.ChainDecisions = make([]*ChainHopDecision, 0, len(req.AgentChain))

		for i, agentAttrs := range req.AgentChain {
			var delegationCtx *DelegationContext
			if i < len(req.DelegationChain) {
				delegationCtx = req.DelegationChain[i]
			}

			hopDecision := &ChainHopDecision{
				Depth:        int32(i),
				AgentId:      agentAttrs.AgentId,
			}
			if delegationCtx != nil {
				hopDecision.DelegationId = delegationCtx.DelegationId
			}

			// Evaluate agent at this hop
			agentAllowed, agentReason := evaluateAgentAttributes(agentAttrs, delegationCtx)
			if agentAllowed {
				hopDecision.AgentDecision = Decision_DECISION_ALLOW
			} else {
				hopDecision.AgentDecision = Decision_DECISION_DENY
				hopDecision.AgentReason = agentReason
				if compound.DeniedAtDepth < 0 {
					compound.DeniedAtDepth = int32(i)
					compound.DeniedPrincipal = "agent:" + agentAttrs.AgentId
				}
			}

			// Evaluate delegation scope at this hop
			if delegationCtx != nil {
				delegationAllowed, delegationReason := evaluateDelegationContext(delegationCtx, req.ResourceAttributes)
				if delegationAllowed {
					hopDecision.DelegationDecision = Decision_DECISION_ALLOW
				} else {
					hopDecision.DelegationDecision = Decision_DECISION_DENY
					hopDecision.DelegationReason = delegationReason
					if compound.DeniedAtDepth < 0 {
						compound.DeniedAtDepth = int32(i)
						compound.DeniedPrincipal = "delegation:" + delegationCtx.DelegationId
					}
				}
			}

			compound.ChainDecisions = append(compound.ChainDecisions, hopDecision)

			// Short-circuit on first DENY
			if compound.DeniedAtDepth >= 0 {
				break
			}
		}
	}

	return compound
}

// evaluateAgentAttributes checks if an agent is authorized for the requested action.
func evaluateAgentAttributes(agent *AgentAttributes, delegation *DelegationContext) (bool, string) {
	if agent == nil {
		return true, ""
	}

	if delegation == nil {
		return true, ""
	}

	// Check trust tier against action tier
	requiredTier := requiredTrustTierForAction(delegation.ActionTier)
	if agent.TrustTier < requiredTier {
		return false, "agent trust tier insufficient for requested action tier"
	}

	// Check tool is in agent's allowed tools
	if delegation.ToolName != "" && len(agent.AllowedTools) > 0 {
		found := false
		for _, tool := range agent.AllowedTools {
			if tool == delegation.ToolName {
				found = true
				break
			}
		}
		if !found {
			return false, "tool not in agent allowed_tools"
		}
	}

	return true, ""
}

// evaluateDelegationContext checks if the delegation scope permits the action.
func evaluateDelegationContext(delegation *DelegationContext, resourceAttrs map[string]string) (bool, string) {
	if delegation == nil {
		return true, ""
	}

	// Classification cap enforcement
	if len(delegation.ClassificationCaps) > 0 && len(resourceAttrs) > 0 {
		resourceHierarchy := resourceAttrs["hierarchy"]
		resourceClassification := resourceAttrs["classification"]

		if resourceHierarchy != "" && resourceClassification != "" {
			cap, hasCap := delegation.ClassificationCaps[resourceHierarchy]
			if hasCap {
				// Simplified comparison — full hierarchy matching deferred to validators
				capLevel := classificationLevel(cap)
				resourceLevel := classificationLevel(resourceClassification)
				if resourceLevel > capLevel {
					return false, "resource classification exceeds delegation cap for " + resourceHierarchy
				}
			}
		}
	}

	return true, ""
}

// requiredTrustTierForAction maps action tiers to minimum trust tiers.
func requiredTrustTierForAction(actionTier ActionTier) AgentTrustTier {
	switch {
	case actionTier <= ActionTier_ACTION_TIER_READ_ONLY:
		return AgentTrustTier_AGENT_TRUST_TIER_UNVERIFIED
	case actionTier == ActionTier_ACTION_TIER_INTERNAL_MODIFY:
		return AgentTrustTier_AGENT_TRUST_TIER_REGISTERED
	case actionTier == ActionTier_ACTION_TIER_EXTERNAL_COMMS:
		return AgentTrustTier_AGENT_TRUST_TIER_CERTIFIED
	default:
		return AgentTrustTier_AGENT_TRUST_TIER_PLATFORM_TRUSTED
	}
}

// classificationLevel returns a numeric level for simplified comparison.
func classificationLevel(classification string) int {
	switch classification {
	case "UNCLASSIFIED", "PUBLIC":
		return 0
	case "RESTRICTED", "INTERNAL":
		return 1
	case "CONFIDENTIAL":
		return 2
	case "SECRET", "HIGHLY-CONFIDENTIAL":
		return 3
	case "TOP-SECRET":
		return 4
	default:
		return 0
	}
}
