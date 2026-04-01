/**
 * scope-validator.js
 *
 * Validates that the scope requested in CLAUDE.md does not exceed what
 * Stratium PAP has registered for this agent.
 *
 * This prevents a developer from editing their CLAUDE.md to grant themselves
 * more access than their agent is entitled to. The PAP is authoritative;
 * CLAUDE.md can only narrow scope, not widen it.
 *
 * Called from session-init.js before creating the delegation.
 */

'use strict';

const { restCall } = require('./grpc-client');

/**
 * @typedef {object} ValidationResult
 * @property {boolean} valid
 * @property {string[]} violations - List of human-readable violation descriptions
 * @property {object} effectiveScope - The actual scope to use (PAP-capped)
 */

/**
 * Fetch the registered agent policy from PAP.
 *
 * @param {import('./grpc-client').RestCallOptions} restOpts
 * @param {string} agentId
 * @returns {{ allowed_tools: string[], max_tier: number }}
 */
function fetchAgentPolicy(restOpts, agentId) {
  const response = restCall(restOpts, 'GET', `/api/v1/agents/${agentId}`);
  return {
    allowed_tools: response.allowed_tools || response.agent?.allowed_tools || [],
    max_tier:      response.max_tier      ?? response.agent?.max_tier ?? 4,
  };
}

/**
 * Validate the requested CLAUDE.md scope against the PAP-registered agent policy.
 *
 * Violations:
 *   - Requested max_action_tier > agent's registered max_tier
 *   - Requested approved_tools contains tools not in agent's allowed_tools
 *     (only checked when agent has a non-empty allowed_tools list)
 *
 * In all cases, violations are logged but scope is automatically capped to
 * the PAP-authorized maximum rather than blocking the session. This ensures
 * the enforcement is the compound Stratium decision (user × agent × delegation),
 * not just the pre-flight check.
 *
 * @param {import('./grpc-client').RestCallOptions} restOpts
 * @param {string} agentId
 * @param {object} requestedScope - Scope from CLAUDE.md (normalized by claude-md-parser)
 * @returns {ValidationResult}
 */
function validateScope(restOpts, agentId, requestedScope) {
  const violations = [];
  const effectiveScope = Object.assign({}, requestedScope);

  let agentPolicy;
  try {
    agentPolicy = fetchAgentPolicy(restOpts, agentId);
  } catch (err) {
    // PAP unreachable — return the requested scope unchanged with a warning.
    // The actual enforcement will happen at the ExecuteAction call.
    return {
      valid: true,
      violations: [`[warn] Could not fetch agent policy from PAP: ${err.message}`],
      effectiveScope: requestedScope,
    };
  }

  // ── Tier cap check ─────────────────────────────────────────────────────────
  if (requestedScope.max_action_tier > agentPolicy.max_tier) {
    const tierLabels = ['REASONING','READ_ONLY','INTERNAL_MODIFY','EXTERNAL_COMMS','DESTRUCTIVE'];
    violations.push(
      `CLAUDE.md requests max_action_tier=${tierLabels[requestedScope.max_action_tier] || requestedScope.max_action_tier} ` +
      `but agent is registered with max_tier=${tierLabels[agentPolicy.max_tier] || agentPolicy.max_tier}. ` +
      `Capping to agent's registered tier.`
    );
    effectiveScope.max_action_tier = agentPolicy.max_tier;
  }

  // ── Approved tools check ───────────────────────────────────────────────────
  // Only enforced when the agent has a non-empty allowed_tools list in PAP.
  // An empty list means "all tools" — no restriction to validate against.
  if (agentPolicy.allowed_tools.length > 0 && requestedScope.approved_tools.length > 0) {
    const unauthorizedTools = requestedScope.approved_tools.filter(
      tool => !agentPolicy.allowed_tools.includes(tool)
    );

    if (unauthorizedTools.length > 0) {
      violations.push(
        `CLAUDE.md requests tools not registered in agent policy: [${unauthorizedTools.join(', ')}]. ` +
        `Removing unauthorized tools from effective scope.`
      );
      effectiveScope.approved_tools = requestedScope.approved_tools.filter(
        tool => agentPolicy.allowed_tools.includes(tool)
      );
    }
  }

  return {
    valid:          violations.length === 0,
    violations,
    effectiveScope,
  };
}

module.exports = { validateScope, fetchAgentPolicy };
