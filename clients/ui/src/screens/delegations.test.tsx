import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Delegation } from '../api'
import { DelegationsScreen } from './delegations'

afterEach(() => {
  vi.restoreAllMocks()
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
