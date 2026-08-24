import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Agent, type Delegation } from '../api'
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
    // Faithful to the wire: the server always sends these. A fixture that
    // omitted them would let a test assert the absence of something that was
    // never present.
    chain_agent_ids: ['22222222-2222-2222-2222-222222222222'],
    classification_caps: {},
    resource_constraints: {},
    ...over,
  }
}

const ROOT_AGENT = '99999999-9999-9999-9999-999999999999'
const LEAF_AGENT = '22222222-2222-2222-2222-222222222222'

function agent(over: Partial<Agent> = {}): Agent {
  return {
    id: LEAF_AGENT, name: 'worker', provider: 'example', model_id: 'm',
    trust_tier: 2, enabled: true, suspended: false, allowed_tools: [],
    created_at: '2026-08-15T10:00:00Z', updated_at: '2026-08-15T10:00:00Z',
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

  it('shows the agent name rather than its id', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    expect(await screen.findByText('worker')).toBeInTheDocument()
    expect(screen.queryByText(LEAF_AGENT)).not.toBeInTheDocument()
  })

  // A deleted agent, or a failed agents request, must not blank the cell or
  // invent "unknown" -- the raw id is still what an operator can search for.
  it('falls back to the id when the agent is not known', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockRejectedValue(new APIError(500, 'boom'))

    render(<DelegationsScreen />)
    expect(await screen.findByText(LEAF_AGENT)).toBeInTheDocument()
  })

  // ChainAgentIDs is built root-first with this delegation's own agent
  // appended last. Rendering it reversed would invert who delegated to whom.
  it('renders the chain root first, by name', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([
      delegation({ depth: 1, chain_agent_ids: [ROOT_AGENT, LEAF_AGENT] }),
    ])
    vi.spyOn(api, 'agents').mockResolvedValue([
      agent({ id: ROOT_AGENT, name: 'orchestrator' }), agent(),
    ])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))

    expect(await screen.findByText(/orchestrator\s+→\s+worker/)).toBeInTheDocument()
  })

  it('opens the detail modal from the keyboard, not only the mouse', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    const row = await screen.findByRole('button', { name: /Delegation for worker/ })
    fireEvent.keyDown(row, { key: 'Enter' })

    expect(await screen.findByText('Delegation id')).toBeInTheDocument()
  })

  // Revoke and "show me this delegation" are different intents. Without
  // stopPropagation the row handler fires too and the modal covers the result.
  it('does not open the modal when Revoke is pressed', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    const revoke = vi.spyOn(api, 'revokeDelegation').mockResolvedValue(delegation({ revoked: true }))

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }))

    await waitFor(() => expect(revoke).toHaveBeenCalled())
    expect(screen.queryByText('Delegation id')).not.toBeInTheDocument()
  })

  it('says plainly when a delegation is a root and has no caps', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))

    expect(await screen.findByText(/this is a root delegation/i)).toBeInTheDocument()
    expect(screen.getByText(/no classification ceiling/i)).toBeInTheDocument()
  })

  // The browser emits `close` for Escape without the component's involvement,
  // so a Modal that only handled its own button would leave the caller's
  // state saying the modal was still open.
  it('dismisses on Escape, and the caller learns about it', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation()])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))
    expect(await screen.findByText('Delegation id')).toBeInTheDocument()

    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByText('Delegation id')).not.toBeInTheDocument())
  })

  // A delegation has no name, so parent and root were three rows of hex. They
  // are references INTO this same list, so each resolves to its agent and
  // purpose -- with the id kept, because this modal is the only place it is
  // shown and it is what a revoke call or an audit grep needs.
  it('labels parent and root by agent and purpose, keeping the id', async () => {
    const root = delegation({
      id: 'aaaaaaaa-0000-0000-0000-000000000001',
      agent_id: ROOT_AGENT, purpose: 'depth-hook example', depth: 0,
      root_delegation_id: 'aaaaaaaa-0000-0000-0000-000000000001',
      chain_agent_ids: [ROOT_AGENT],
    })
    const child = delegation({
      id: 'bbbbbbbb-0000-0000-0000-000000000002',
      agent_id: LEAF_AGENT, purpose: 'depth-hook example', depth: 1,
      parent_delegation_id: root.id, root_delegation_id: root.id,
      chain_agent_ids: [ROOT_AGENT, LEAF_AGENT],
    })
    vi.spyOn(api, 'delegations').mockResolvedValue([root, child])
    vi.spyOn(api, 'agents').mockResolvedValue([
      agent({ id: ROOT_AGENT, name: 'orchestrator' }), agent(),
    ])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))

    // Parent and root are the same delegation here, so the label appears twice
    // -- once for each row -- plus once for the child's own id row.
    expect(await screen.findAllByText(/orchestrator · “depth-hook example”/)).toHaveLength(2)
    expect(screen.getByText(/worker · “depth-hook example”/)).toBeInTheDocument()
    // ...and every id is still on screen.
    expect(screen.getAllByText(root.id).length).toBeGreaterThan(0)
    expect(screen.getByText(child.id)).toBeInTheDocument()
  })

  // purpose is free text and some rows leave it empty. The label degrades to
  // the agent alone rather than rendering an empty pair of quotes.
  it('omits the quoted purpose when a delegation has none', async () => {
    vi.spyOn(api, 'delegations').mockResolvedValue([delegation({ purpose: '' })])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))
    await screen.findByText('Delegation id')

    // The agent alone, with no separator and -- the actual bug this guards --
    // no empty pair of quotes where a purpose would have gone.
    expect(screen.queryByText(/·/)).not.toBeInTheDocument()
    expect(screen.queryByText(/“\s*”/)).not.toBeInTheDocument()
  })

  // A reference we cannot resolve gets the id alone. Inventing a label for a
  // delegation not in the list would be worse than the bare id the caller had.
  it('shows the id alone when a reference cannot be resolved', async () => {
    const orphan = 'cccccccc-0000-0000-0000-000000000003'
    vi.spyOn(api, 'delegations').mockResolvedValue([
      delegation({ depth: 1, parent_delegation_id: orphan }),
    ])
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])

    render(<DelegationsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /Delegation for worker/ }))
    expect(await screen.findByText(orphan)).toBeInTheDocument()

    // Asserting the id is present is not enough: an invented label would sit
    // BESIDE the id and still pass that. The Parent row must contain the id
    // and nothing else.
    const row = screen.getByText('Parent').parentElement
    expect(row?.textContent?.replace('Parent', '').trim()).toBe(orphan)
  })
})
