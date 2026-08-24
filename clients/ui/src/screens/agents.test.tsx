import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Agent, type AgentCapsView } from '../api'
import { AgentsScreen } from './agents'

afterEach(() => { vi.restoreAllMocks() })

function agent(over: Partial<Agent> = {}): Agent {
  return {
    id: '99999999-9999-9999-9999-999999999999',
    name: 'claude-code',
    provider: 'anthropic',
    model_id: 'claude-opus-5',
    trust_tier: 2,
    enabled: true,
    suspended: false,
    allowed_tools: ['Read', 'Grep'],
    created_at: '2026-08-23T10:00:00Z',
    updated_at: '2026-08-23T10:00:00Z',
    ...over,
  }
}

// AgentCapsView carries four advisory fields beyond classification_caps, all
// required on the wire. This factory keeps every mockResolvedValue below a
// real, fully-shaped response -- the same convention every other fixture
// function in this suite already follows -- rather than the bare partial
// maps a hand-written literal would need to omit fields from.
function capsView(over: Partial<AgentCapsView> = {}): AgentCapsView {
  return {
    agent_id: agent().id,
    classification_caps: {},
    catch_all: {},
    unsatisfiable_tools: [],
    live_delegations: 0,
    applies: 'at next issuance',
    ...over,
  }
}

describe('AgentsScreen', () => {
  // store.UpdateAgent passes eight parameters and classification_caps is not
  // one of them: it is read back via RETURNING and never written. A field
  // for it here would accept input, save without error, and change
  // nothing -- an operator believing they had tightened a security ceiling
  // that never moved.
  it('offers no caps field on the agent form itself', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    await screen.findByLabelText('Name')
    expect(screen.queryByLabelText('Classification caps')).not.toBeInTheDocument()
  })

  it('does not send classification_caps in the agent body', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    const update = vi.spyOn(api, 'updateAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'renamed' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(update).toHaveBeenCalled())
    const call = update.mock.calls[0]
    if (call === undefined) throw new Error('updateAgent was not called')
    const [, body] = call
    expect(body).not.toHaveProperty('classification_caps')
    // ...and it is a full replace, so everything else IS there.
    expect(body).toMatchObject({
      name: 'renamed', provider: 'anthropic', model_id: 'claude-opus-5',
      trust_tier: 2, enabled: true, suspended: false, allowed_tools: ['Read', 'Grep'],
    })
  })

  it('writes caps through the sub-resource route', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView({ classification_caps: { nato: 'CONFIDENTIAL' } }))
    const putCaps = vi.spyOn(api, 'putAgentCaps')
      .mockResolvedValue(capsView({ classification_caps: { nato: 'SECRET' } }))

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    fireEvent.change(await screen.findByDisplayValue('CONFIDENTIAL'), { target: { value: 'SECRET' } })
    screen.getByRole('button', { name: 'Save caps' }).click()

    await waitFor(() => expect(putCaps).toHaveBeenCalledWith(
      '99999999-9999-9999-9999-999999999999', { nato: 'SECRET' },
    ))
  })

  // An empty map is the off switch; any entry makes unlabelled resources deny.
  // "no caps" and "caps set to nothing" are the same wire value and must read
  // the same on screen.
  // live_delegations is "the delegations this cap does NOT affect. A warning,
  // not a confirmation." Caps are copied onto a delegation at issuance, so an
  // operator lowering a ceiling during an incident must not believe they have
  // stopped something that is still running.
  it('warns that live delegations keep the previous cap until reissued', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: { nato: 'SECRET' }, catch_all: { nato: 'PUBLIC' },
      unsatisfiable_tools: [], live_delegations: 3, applies: 'at next issuance',
    })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    expect(await screen.findByText(/3/)).toBeInTheDocument()
    expect(screen.getByText(/at next issuance/i)).toBeInTheDocument()
  })

  // For an unrestricted agent the list covers CATALOGUED tools only -- there is
  // no finite set to scan. An empty list must not read as "everything is fine".
  it('does not claim an unrestricted agent has no unsatisfiable tools', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent({ allowed_tools: [] })])
    vi.spyOn(api, 'agent').mockResolvedValue(agent({ allowed_tools: [] }))
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: { nato: 'SECRET' }, catch_all: { nato: 'PUBLIC' },
      unsatisfiable_tools: [], live_delegations: 0, applies: 'at next issuance',
    })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    expect(await screen.findByText(/uncatalogued tools cannot be listed/i)).toBeInTheDocument()
  })

  // The refusal is an acknowledgement gate. It must be shown in the server's
  // own words, and overriding it must be a separate deliberate act.
  it('offers an explicit override only after the server refuses an uncovered hierarchy', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: {}, catch_all: {},
      unsatisfiable_tools: [], live_delegations: 0, applies: 'at next issuance',
    })
    const put = vi.spyOn(api, 'putAgentCaps').mockRejectedValue(
      new APIError(400, 'hierarchy "nato" has no catch-all rule: POST /v1/resource-label-rules with prefix "" first, or pass ?allow_uncovered=true'),
    )

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    fireEvent.change(await screen.findByLabelText('Hierarchy'), { target: { value: 'nato' } })
    fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'SECRET' } })
    screen.getByRole('button', { name: 'Add' }).click()
    ;(await screen.findByRole('button', { name: 'Save caps' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('no catch-all rule')
    // Not sent with the override on the first attempt -- no third argument
    // at all, the same call shape as the plain-save test above.
    expect(put).toHaveBeenCalledWith(agent().id, { nato: 'SECRET' })

    ;(await screen.findByRole('button', { name: 'Apply anyway (uncovered)' })).click()
    await waitFor(() => expect(put).toHaveBeenLastCalledWith(agent().id, { nato: 'SECRET' }, true))
  })

  it('says an empty cap set means no ceiling is enforced', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    expect(await screen.findByText(/no classification ceiling is enforced/i)).toBeInTheDocument()
  })
})
