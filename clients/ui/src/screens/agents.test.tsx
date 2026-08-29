import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Agent, type AgentCapsView, type AgentConstraintsView } from '../api'
import { AgentsScreen } from './agents'

afterEach(() => { vi.restoreAllMocks() })

// classification_caps defaults to a real value, the way GET /v1/agents/{id}
// actually responds (services/internal/store/agent.go's UpdateAgent doc:
// "read back from the row via RETURNING"). A fixture that always omitted it
// would make the strip-before-update test pass whether or not the strip
// exists -- see agents.test.tsx's "does not send classification_caps in the
// agent body" below.
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
    classification_caps: { nato: 'CONFIDENTIAL' },
    // Carried for the same reason classification_caps is: GET returns it, so
    // a fixture omitting it would make the strip-before-update test below
    // pass whether or not the strip exists.
    resource_constraints: { id_prefix: '/workspace/' },
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
    // agent() now carries classification_caps -- the way a real GET
    // responds -- so this is a real strip, not an assertion that a field
    // absent from the mock stayed absent.
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView({ classification_caps: { nato: 'CONFIDENTIAL' } }))
    const update = vi.spyOn(api, 'updateAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    // The caps panel -- fed by the separate GET .../classification-caps
    // route, not the agent body -- shows the stored value untouched, proof
    // this test is exercising a live draft and a live panel, not a mock
    // that happens to have nothing to strip.
    expect(await screen.findByDisplayValue('CONFIDENTIAL')).toBeInTheDocument()

    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'renamed' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(update).toHaveBeenCalled())
    const call = update.mock.calls[0]
    if (call === undefined) throw new Error('updateAgent was not called')
    const [, body] = call
    // The seeded draft DOES carry caps, because GET returns them (agent()'s
    // default)...
    // ...and the PUT body must not, because UpdateAgent silently ignores the
    // field: a value sent here would save without error and change nothing.
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
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
    vi.spyOn(api, 'agentCaps').mockResolvedValue({
      agent_id: agent().id, classification_caps: { nato: 'SECRET' }, catch_all: { nato: 'PUBLIC' },
      unsatisfiable_tools: [], live_delegations: 3, applies: 'at next issuance',
    })

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    // Matched on caps-specific wording: the scope panel below renders its own
    // "at next issuance" warning for its own sub-resource, so a bare
    // /at next issuance/ would now match both paragraphs.
    expect(await screen.findByText(/3 live delegation/)).toBeInTheDocument()
    expect(screen.getByText(/previous cap/i)).toBeInTheDocument()
  })

  // For an unrestricted agent the list covers CATALOGUED tools only -- there is
  // no finite set to scan. An empty list must not read as "everything is fine".
  it('does not claim an unrestricted agent has no unsatisfiable tools', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent({ allowed_tools: [] })])
    vi.spyOn(api, 'agent').mockResolvedValue(agent({ allowed_tools: [] }))
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
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
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
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

  // The clobber guard re-fetches and compares the whole object against the
  // snapshot taken when the panel opened. classification_caps is written
  // through its own route (CapsSection/putAgentCaps), not through this PUT,
  // so a cap changing between snapshot and save is not a colleague's
  // concurrent edit of the agent -- it must not trip the guard.
  it('saves the agent even when classification_caps changed underneath it', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent')
      .mockResolvedValueOnce(agent()) // edit()'s snapshot GET
      .mockResolvedValueOnce(agent({ classification_caps: { nato: 'SECRET' } })) // save()'s clobber-check GET
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView({ classification_caps: { nato: 'CONFIDENTIAL' } }))
    const update = vi.spyOn(api, 'updateAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'renamed' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(update).toHaveBeenCalled())
    expect(screen.queryByText(/changed while you were editing/)).not.toBeInTheDocument()
  })

  // setOfferOverride(true) must fire only for the coverage refusal itself,
  // not for any save failure -- an operator clicking through a 502 must not
  // send ?allow_uncovered=true, which the server would read as acknowledging
  // a coverage refusal that was never issued.
  it('does not offer the override for an unrelated save failure', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    // Mocked so the scope panel below loads cleanly: an unmocked fetch there
    // renders its own ErrorBanner, and findByRole('alert') would return that
    // instead of the caps failure this test is about.
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
    vi.spyOn(api, 'putAgentCaps').mockRejectedValue(new APIError(502, 'bad gateway'))

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    ;(await screen.findByRole('button', { name: 'Save caps' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('bad gateway')
    expect(screen.queryByRole('button', { name: 'Apply anyway (uncovered)' })).not.toBeInTheDocument()
  })

  // Clearing removes the whole classification ceiling in one click -- the
  // loosening direction, the one destructive action on this branch that had
  // no confirmation at all.
  it('confirms before clearing all caps, and explains what clearing means', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView({ classification_caps: { nato: 'SECRET' } }))
    const del = vi.spyOn(api, 'deleteAgentCaps').mockResolvedValue(undefined)

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    ;(await screen.findByRole('button', { name: 'Clear all caps' })).click()

    expect(del).not.toHaveBeenCalled()
    const confirmRow = await screen.findByRole('alertdialog')
    expect(confirmRow).toHaveTextContent(/no classification ceiling is enforced/i)

    screen.getByRole('button', { name: 'Yes, clear all caps' }).click()
    await waitFor(() => expect(del).toHaveBeenCalledWith(agent().id))
  })

  it('says an empty cap set means no ceiling is enforced', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()
    expect(await screen.findByText(/no classification ceiling is enforced/i)).toBeInTheDocument()
  })

  it('offers trust tiers by name and sends the number they stand for', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([])
    const create = vi.spyOn(api, 'createAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    await screen.findByText('No agents.')
    screen.getByRole('button', { name: 'New agent' }).click()

    const select = await screen.findByLabelText('Trust tier')
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(['UNVERIFIED', 'REGISTERED', 'CERTIFIED', 'PLATFORM_TRUSTED'])

    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'a' } })
    fireEvent.change(select, { target: { value: 'CERTIFIED' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ name: 'a', trust_tier: 2 }),
    ))
  })

  // A <select> whose value matches no option renders the FIRST one. Without
  // the stored value appearing among the options, an agent stored at a tier
  // this build does not know would be displayed as UNVERIFIED -- a security
  // field showing a value that was never stored. display.ts already holds this
  // rule for the read path ("shown as itself rather than silently floored").
  it('shows an out-of-range stored tier as itself, never as UNVERIFIED', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent({ trust_tier: 7 })])
    vi.spyOn(api, 'agent').mockResolvedValue(agent({ trust_tier: 7 }))
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())

    render(<AgentsScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    const select = await screen.findByLabelText('Trust tier')
    expect((select as HTMLSelectElement).value).toBe('INVALID_TRUST_TIER(7)')
    expect((select as HTMLSelectElement).value).not.toBe('UNVERIFIED')
  })
})

// AgentConstraintsView carries three advisory fields beyond the map itself,
// all required on the wire -- same convention as capsView above.
function constraintsView(over: Partial<AgentConstraintsView> = {}): AgentConstraintsView {
  return {
    agent_id: agent().id,
    resource_constraints: {},
    unsatisfiable_tools: [],
    live_delegations: 0,
    applies: 'at next issuance',
    ...over,
  }
}

describe('AgentsScreen scope panel', () => {
  it('does not send resource_constraints in the agent body', async () => {
    // The agent PUT ignores the column (it is absent from updateAgentQuery's
    // SET clause), so sending it back would read as a write that silently did
    // nothing -- and, worse, would make a scope changed through its own route
    // look like a colleague's concurrent edit to the clobber guard, which
    // compares exactly what gets sent.
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(
      constraintsView({ resource_constraints: { id_prefix: '/workspace/' } }))
    const update = vi.spyOn(api, 'updateAgent').mockResolvedValue(agent())

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))
    fireEvent.click(await screen.findByRole('button', { name: /^save$/i }))

    await waitFor(() => { expect(update).toHaveBeenCalled() })
    const call = update.mock.calls[0]
    if (call === undefined) throw new Error('updateAgent was not called')
    const [, body] = call
    expect(body).not.toHaveProperty('resource_constraints')
    expect(body).not.toHaveProperty('classification_caps')
  })

  it('shows the stored scope and saves a new one', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(
      constraintsView({ resource_constraints: { id_prefix: '/workspace/' } }))
    const put = vi.spyOn(api, 'putAgentConstraints').mockResolvedValue(
      constraintsView({ resource_constraints: { id_prefix: '/workspace/src/' } }))

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))

    const input = await screen.findByLabelText(/scope prefix/i)
    expect(input).toHaveValue('/workspace/')

    fireEvent.change(input, { target: { value: '/workspace/src/' } })
    fireEvent.click(screen.getByRole('button', { name: /save scope/i }))

    await waitFor(() => {
      expect(put).toHaveBeenCalledWith(agent().id, { id_prefix: '/workspace/src/' })
    })
  })

  it('refuses a prefix with no trailing slash before calling the server', async () => {
    // The server refuses this too (validateResourceConstraints). Catching it
    // here as well is not duplication for its own sake: without the trailing
    // slash, "/workspace" also matches "/workspace-evil/secrets.txt", and an
    // operator is better told that while looking at the field than after a
    // round trip.
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
    const put = vi.spyOn(api, 'putAgentConstraints').mockResolvedValue(constraintsView())

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))

    fireEvent.change(await screen.findByLabelText(/scope prefix/i),
      { target: { value: '/workspace' } })
    fireEvent.click(screen.getByRole('button', { name: /save scope/i }))

    expect(await screen.findByText(/must end in/i)).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
  })

  it('renders the server refusal verbatim when it disagrees', async () => {
    // Client-side validation is a courtesy; the server stays authoritative.
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(constraintsView())
    vi.spyOn(api, 'putAgentConstraints').mockRejectedValue(
      new APIError(400, 'store: invalid resource constraint: id_prefix "/x/" must not contain ".."'))

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))
    fireEvent.change(await screen.findByLabelText(/scope prefix/i),
      { target: { value: '/x/' } })
    fireEvent.click(screen.getByRole('button', { name: /save scope/i }))

    expect(await screen.findByText(/must not contain/i)).toBeInTheDocument()
  })

  it('clears the scope only behind a confirmation', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(
      constraintsView({ resource_constraints: { id_prefix: '/workspace/' } }))
    const del = vi.spyOn(api, 'deleteAgentConstraints').mockResolvedValue(undefined)

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))
    fireEvent.click(await screen.findByRole('button', { name: /clear scope/i }))

    // Clearing is the loosening direction, so it is gated the same way
    // clearing caps is -- the click above only opens the prompt.
    expect(del).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole('button', { name: /yes, clear the scope/i }))
    await waitFor(() => { expect(del).toHaveBeenCalledWith(agent().id) })
  })

  it('warns that live delegations are unaffected', async () => {
    vi.spyOn(api, 'agents').mockResolvedValue([agent()])
    vi.spyOn(api, 'agent').mockResolvedValue(agent())
    vi.spyOn(api, 'agentCaps').mockResolvedValue(capsView())
    vi.spyOn(api, 'agentConstraints').mockResolvedValue(
      constraintsView({ live_delegations: 2, applies: 'at next issuance' }))

    render(<AgentsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: /edit/i }))

    // Scope-specific wording: the caps panel above renders its own
    // "at next issuance" warning, so match what only this panel says.
    expect(await screen.findByText(/previous scope/i)).toBeInTheDocument()
    expect(screen.getByText(/2 live delegations/)).toBeInTheDocument()
  })
})
