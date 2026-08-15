import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Delegation, type Policy } from './api'
import { DelegationsScreen, PoliciesScreen } from './screens'

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

function delegation(over: Partial<Delegation> = {}): Delegation {
  return {
    id: '11111111-1111-1111-1111-111111111111',
    user_id: 'operator@example.com',
    agent_id: '22222222-2222-2222-2222-222222222222',
    approved_tools: [],
    max_action_tier: 3,
    purpose: 'testing',
    expires_at: '2026-09-01T10:00:00Z',
    created_at: '2026-08-15T10:00:00Z',
    revoked: false,
    root_delegation_id: '11111111-1111-1111-1111-111111111111',
    depth: 0,
    ...over,
  }
}

describe('DelegationsScreen', () => {
  // N14 at the component level: the button is not conditioned on any role,
  // because this application does not know or decide roles. The server-side
  // half of the same property — a viewer really is refused — is proven in
  // services/cmd/stratium-pap/delegations_test.go with this client bypassed.
  it('offers revoke to every signed-in operator and shows the server refusal verbatim', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    // A real APIError, so this exercises the same describeError branch a
    // genuine 403 from the admin plane takes.
    const revoke = vi
      .spyOn(api, 'revokeDelegation')
      .mockRejectedValue(new APIError(403, 'forbidden'))

    render(<DelegationsScreen />)
    const button = await screen.findByRole('button', { name: 'Revoke' })

    button.click()
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('11111111-1111-1111-1111-111111111111'))
    // The refusal is surfaced, not swallowed and not pre-empted.
    await screen.findByRole('alert')
  })

  it('lists revoked delegations too, so a revocation can be confirmed', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([
      delegation({ revoked: true, revoked_at: '2026-08-15T11:00:00Z' }),
    ])

    render(<DelegationsScreen />)
    expect(await screen.findByText('revoked')).toBeInTheDocument()
    // Nothing to revoke twice.
    expect(screen.queryByRole('button', { name: 'Revoke' })).not.toBeInTheDocument()
  })

  it('renders an empty tool list as unrestricted', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation({ approved_tools: [] })])
    render(<DelegationsScreen />)
    expect(await screen.findByText('unrestricted')).toBeInTheDocument()
  })
})
