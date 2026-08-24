// display.ts holds the pure functions the screens format with. They live
// apart from the components for one reason: policyEffect below is the only
// rule in this application that would be a correctness bug rather than a
// cosmetic one if it were wrong, and it is much easier to test as a function
// than as a rendered table cell.

/**
 * Languages whose stored `effect` column is meaningful.
 *
 * services/internal/store/policy.go refuses a write whose effect disagrees
 * with what the policy text declares — but only for languages whose engine
 * implements its `effectDeclarer` interface, which is exactly these two:
 *
 *   - cedar: every statement begins with permit or forbid, and the engine
 *     accepts exactly one statement per stored policy.
 *   - json:  the schema has a literal top-level "effect" key.
 *
 * For rego and xacml a single stored policy can define rules of BOTH
 * effects, resolved only once request data is known, so `effect` is pinned to
 * the fixed sentinel "deny" (multiValuedLanguageEffect) and says nothing
 * whatever about the policy. Phase 4a removed the column from the decision
 * read path naming this exact screen: "trusting this column at read time
 * would let a PAP screen listing policies show the opposite of what the
 * policy does."
 *
 * Duplicated here rather than served by the API because it is a property of
 * the four engines, fixed by policies.language's own CHECK constraint, not a
 * per-deployment setting — and because the safe direction of a mistake is the
 * one this list produces: a language missing from it is rendered as
 * "evaluated", which claims nothing.
 */
const DECLARED_EFFECT_LANGUAGES = new Set(['cedar', 'json'])

export type PolicyEffect =
  | { kind: 'declared'; effect: string }
  | { kind: 'evaluated'; reason: string }

/**
 * What, if anything, this screen may say a policy's effect is.
 *
 * An unknown language falls to 'evaluated', deliberately: a language this
 * build has never heard of is one whose effect column carries unknown
 * meaning, and the only honest render for unknown meaning is to not claim
 * one. Never the other way around.
 */
export function policyEffect(language: string, effect: string): PolicyEffect {
  if (DECLARED_EFFECT_LANGUAGES.has(language)) return { kind: 'declared', effect }
  return {
    kind: 'evaluated',
    reason:
      `a ${language} policy can define rules of both effects, resolved only when a ` +
      `request is evaluated — the stored effect column is a fixed placeholder for this ` +
      `language and is not shown`,
  }
}

/** Whether an operator may choose this language's stored `effect`.
 *
 *  For cedar and json the store checks the column against what the text
 *  declares and refuses a disagreement. For rego and xacml it refuses
 *  anything except multiValuedLanguageEffect ("deny") outright
 *  (ErrEffectNotDeclarable) -- so an effect selector on those languages would
 *  offer two options of which one is a guaranteed rejection. */
export function declaresEffect(language: string): boolean {
  return DECLARED_EFFECT_LANGUAGES.has(language)
}

/** models.ActionTier.String(), for the numeric tier the API sends. An
 *  out-of-range value is shown as itself rather than silently floored to
 *  REASONING, which is what an invalid tier must never be mistaken for. */
export const ACTION_TIERS = ['REASONING', 'READ_ONLY', 'INTERNAL_MODIFY', 'EXTERNAL_COMMS', 'DESTRUCTIVE']

export function actionTier(tier: number | null | undefined): string {
  if (tier === null || tier === undefined) return '—'
  return ACTION_TIERS[tier] ?? `INVALID_ACTION_TIER(${tier})`
}

/** models.AgentTrustTier. Same out-of-range discipline as actionTier. */
export const TRUST_TIERS = ['UNVERIFIED', 'REGISTERED', 'CERTIFIED', 'PLATFORM_TRUSTED']

export function trustTier(tier: number): string {
  return TRUST_TIERS[tier] ?? `INVALID_TRUST_TIER(${tier})`
}

/** A timestamp an operator can read, in their own locale and zone. An empty
 *  or unparseable value renders as an em dash rather than "Invalid Date". */
export function timestamp(value: string | null | undefined): string {
  if (!value) return '—'
  const d = new Date(value)
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString()
}

/** A digest is 64 hex characters; a table cell is not. Shown head-and-tail so
 *  two different digests are still distinguishable at a glance, with the full
 *  value available via the cell's title attribute. */
export function shortDigest(hex: string): string {
  return hex.length <= 16 ? hex : `${hex.slice(0, 8)}…${hex.slice(-8)}`
}

/** An empty tool list means unrestricted, for both Agent and Delegation —
 *  see models.Agent.HasTool. Rendering it as "" would read as "no tools
 *  allowed", the exact opposite. */
export function toolList(tools: string[] | null | undefined): string {
  return tools && tools.length > 0 ? tools.join(', ') : 'unrestricted'
}

/**
 * The options a tier dropdown offers for a value already stored.
 *
 * Normally just the tier names, in tier order, so the option's index IS the
 * tier. When the stored value is out of range the list gains that value's own
 * INVALID_… rendering and the control selects it — because a <select> whose
 * value matches no option displays the FIRST one, which would tell an operator
 * an agent is UNVERIFIED, or a tool REASONING, when it is neither.
 *
 * This is the same rule actionTier and trustTier already apply above: an
 * out-of-range value is shown as itself and never silently floored. The
 * operator has to choose a real tier deliberately rather than being shown one
 * that was never stored.
 */
function tierOptions(names: string[], render: string): string[] {
  return names.includes(render) ? names : [...names, render]
}

export function actionTierOptions(stored: number): string[] {
  return tierOptions(ACTION_TIERS, actionTier(stored))
}

export function trustTierOptions(stored: number): string[] {
  return tierOptions(TRUST_TIERS, trustTier(stored))
}
