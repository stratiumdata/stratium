import { describe, expect, it } from 'vitest'

import { actionTier, policyEffect, shortDigest, timestamp, toolList, trustTier } from './display'

// The load-bearing one. Phase 4a removed the effect column from the decision
// read path naming this exact screen: "trusting this column at read time
// would let a PAP screen listing policies show the opposite of what the
// policy does." For rego and xacml the column is pinned to the sentinel
// "deny" and means nothing at all, so a screen that rendered it would tell an
// operator a permissive policy denies.
describe('policyEffect', () => {
  it('reports the stored effect for languages that declare one', () => {
    expect(policyEffect('cedar', 'allow')).toEqual({ kind: 'declared', effect: 'allow' })
    expect(policyEffect('cedar', 'deny')).toEqual({ kind: 'declared', effect: 'deny' })
    expect(policyEffect('json', 'allow')).toEqual({ kind: 'declared', effect: 'allow' })
  })

  it('refuses to report an effect for rego and xacml, whatever the column says', () => {
    // "deny" is the exact sentinel the store writes for these two languages.
    // A permissive Rego module carries it just the same, which is why it must
    // never reach a screen.
    for (const language of ['rego', 'xacml']) {
      const result = policyEffect(language, 'deny')
      expect(result.kind).toBe('evaluated')
      expect(result).not.toHaveProperty('effect')
    }
    // Even an "allow" that somehow reached the client is not shown: the
    // decision is about the LANGUAGE, never about the value.
    expect(policyEffect('rego', 'allow').kind).toBe('evaluated')
  })

  it('treats an unknown language as undeclarable, not as declarable', () => {
    // The safe direction. A language this build has never heard of has an
    // effect column of unknown meaning, and the only honest render for
    // unknown meaning is to claim nothing.
    expect(policyEffect('some-future-language', 'allow').kind).toBe('evaluated')
    expect(policyEffect('', 'allow').kind).toBe('evaluated')
  })
})

describe('actionTier', () => {
  it('names every tier in the lattice', () => {
    expect([0, 1, 2, 3, 4].map(actionTier)).toEqual([
      'REASONING',
      'READ_ONLY',
      'INTERNAL_MODIFY',
      'EXTERNAL_COMMS',
      'DESTRUCTIVE',
    ])
  })

  it('never silently floors an out-of-range tier to REASONING', () => {
    // REASONING is tier 0 and the least privileged value in the lattice.
    // Rendering an invalid tier as REASONING would show the most dangerous
    // possible misreading of a corrupt row.
    expect(actionTier(9)).toBe('INVALID_ACTION_TIER(9)')
    expect(actionTier(-1)).toBe('INVALID_ACTION_TIER(-1)')
  })

  it('renders a null tier as an em dash, which is what the catalog uses for per-invocation', () => {
    expect(actionTier(null)).toBe('—')
    expect(actionTier(undefined)).toBe('—')
  })
})

describe('trustTier', () => {
  it('names the four trust tiers and flags anything else', () => {
    expect([0, 1, 2, 3].map(trustTier)).toEqual(['UNVERIFIED', 'REGISTERED', 'CERTIFIED', 'PLATFORM_TRUSTED'])
    expect(trustTier(7)).toBe('INVALID_TRUST_TIER(7)')
  })
})

describe('toolList', () => {
  it('renders an empty list as unrestricted, never as blank', () => {
    // models.Agent.HasTool / Delegation.HasTool both read an empty list as
    // "every tool". A blank cell would read as the exact opposite.
    expect(toolList([])).toBe('unrestricted')
    expect(toolList(null)).toBe('unrestricted')
    expect(toolList(undefined)).toBe('unrestricted')
    expect(toolList(['Bash', 'Read'])).toBe('Bash, Read')
  })
})

describe('timestamp', () => {
  it('renders an absent value as an em dash and an unparseable one as itself', () => {
    expect(timestamp(null)).toBe('—')
    expect(timestamp('')).toBe('—')
    expect(timestamp('not a date')).toBe('not a date')
  })

  it('formats a real timestamp', () => {
    expect(timestamp('2026-08-15T10:00:00Z')).not.toBe('—')
    expect(timestamp('2026-08-15T10:00:00Z')).not.toContain('Invalid')
  })
})

describe('shortDigest', () => {
  it('keeps both ends so two different digests stay distinguishable', () => {
    const a = 'a'.repeat(56) + 'deadbeef'
    const b = 'b'.repeat(56) + 'deadbeef'
    expect(shortDigest(a)).not.toBe(shortDigest(b))
    expect(shortDigest(a)).toContain('deadbeef')
  })

  it('leaves a short value alone', () => {
    expect(shortDigest('abc')).toBe('abc')
  })
})
