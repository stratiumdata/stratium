import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type Policy } from '../api'
import { PoliciesScreen } from './policies'

afterEach(() => {
  vi.restoreAllMocks()
})

function policy(over: Partial<Policy>): Policy {
  return {
    id: crypto.randomUUID(),
    name: 'a policy',
    description: '',
    language: 'cedar',
    policy_content: '',
    effect: 'allow',
    version: 1,
    enabled: true,
    created_at: '2026-08-15T10:00:00Z',
    updated_at: '2026-08-15T10:00:00Z',
    ...over,
  }
}

describe('PoliciesScreen', () => {
  // The brief's own required test. Phase 4a: "trusting this column at read
  // time would let a PAP screen listing policies show the opposite of what
  // the policy does." Both languages carry the fixed sentinel "deny" in the
  // effect column regardless of what their rules actually do.
  it('renders a Rego and an XACML policy without claiming an effect', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([
      policy({ name: 'rego-policy', language: 'rego', effect: 'deny' }),
      policy({ name: 'xacml-policy', language: 'xacml', effect: 'deny' }),
    ])

    render(<PoliciesScreen />)
    await screen.findByText('rego-policy')
    expect(screen.getByText('xacml-policy')).toBeInTheDocument()

    // Two rows, two "determined at evaluation" cells, and nowhere on the
    // screen does the word deny (or allow) appear as this policy's effect.
    expect(screen.getAllByText('determined at evaluation')).toHaveLength(2)
    expect(screen.queryByText('deny')).not.toBeInTheDocument()
    expect(screen.queryByText('allow')).not.toBeInTheDocument()
  })

  it('does show the effect for cedar and json, where the column is checked against the text', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([
      policy({ name: 'cedar-policy', language: 'cedar', effect: 'allow' }),
      policy({ name: 'json-policy', language: 'json', effect: 'deny' }),
    ])

    render(<PoliciesScreen />)
    await screen.findByText('cedar-policy')
    expect(screen.getByText('allow')).toBeInTheDocument()
    expect(screen.getByText('deny')).toBeInTheDocument()
    expect(screen.queryByText('determined at evaluation')).not.toBeInTheDocument()
  })

  it('says so when the tenant has no policies, rather than showing an empty table', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    render(<PoliciesScreen />)
    expect(await screen.findByText('No policies.')).toBeInTheDocument()
  })
})
