import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, APIError, type Policy } from '../api'
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

describe('PoliciesScreen editor', () => {
  // The mock deliberately does NOT return this build's real four languages in
  // their real order. A test that mocks ['cedar','json','rego','xacml'] cannot
  // tell "reads the server's list" from "hardcodes the same four values" --
  // both render identically. A subset in a different order can only come from
  // the response.
  it('offers the languages the server reports, not a hardcoded list', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['rego', 'cedar'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()

    const select = await screen.findByLabelText('Language')
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(['rego', 'cedar'])
  })

  // For rego and xacml the store refuses any effect except "deny"
  // (ErrEffectNotDeclarable). A selector there would offer a guaranteed 4xx.
  // BLANK holds language: '' and languages arrive asynchronously. A draft that
  // reaches the panel with '' renders "A  policy can define rules of both
  // effects" -- declaresEffect('') is false and the name interpolates empty.
  it('never opens an editor on the empty language', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'rego'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()

    const select = await screen.findByLabelText('Language')
    expect((select as HTMLSelectElement).value).toBe('cedar')
    expect(screen.queryByText(/^A\s+policy can define/)).not.toBeInTheDocument()
  })

  // An empty list means either "not loaded" or "this build registers no
  // engines". Neither permits authoring, and a form with an empty selector
  // invites a save that cannot succeed.
  it('offers no New policy button when the build registers no engines', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue([])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    expect(await screen.findByText(/no policy engines registered/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'New policy' })).not.toBeInTheDocument()
  })

  it('offers no effect choice for a language that cannot declare one', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'rego'])

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()

    const select = await screen.findByLabelText('Language')
    expect(screen.getByLabelText('Effect')).toBeInTheDocument()

    fireEvent.change(select, { target: { value: 'rego' } })

    await waitFor(() => expect(screen.queryByLabelText('Effect')).not.toBeInTheDocument())
    expect(screen.getByText(/resolved only when a request is evaluated/i)).toBeInTheDocument()
  })

  // The literal brief test for this behaviour never actually switches
  // languages, and BLANK.effect is already 'deny' -- so it would pass even
  // with the pinning logic deleted. This version sets the effect to 'allow'
  // while cedar is selected (declaresEffect('cedar') === true, so the
  // selector is present) and THEN switches to rego, so a missing pin is
  // caught: without it the draft would still carry 'allow' into the save.
  it('sends deny as the effect for a language that cannot declare one', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar', 'rego'])
    const create = vi.spyOn(api, 'createPolicy').mockResolvedValue(policy({}))

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()

    fireEvent.change(await screen.findByLabelText('Effect'), { target: { value: 'allow' } })
    fireEvent.change(await screen.findByLabelText('Language'), { target: { value: 'rego' } })
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'p' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ language: 'rego', effect: 'deny' }),
    ))
  })

  // validate fails CLOSED: an unparseable candidate is a 400 carrying the
  // engine's message, not a 200 with valid:false. The engine's words are the
  // only useful part.
  it('shows the engine’s own message when validation refuses', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'validatePolicy').mockRejectedValue(
      new APIError(400, 'cedar: unexpected token at line 2'),
    )

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    screen.getByRole('button', { name: 'New policy' }).click()
    ;(await screen.findByRole('button', { name: 'Validate' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('unexpected token at line 2')
  })

  // The two legs answer different questions and can disagree: a policy correct
  // in isolation may be overridden or made redundant by an existing one. That
  // divergence is the most valuable thing this endpoint reports.
  it('renders both legs and says so when they disagree', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'testPolicy').mockResolvedValue({
      isolated: { effect: 'deny', reason: 'classification SECRET exceeds cap' },
      with_existing_policies: { effect: 'allow', reason: 'permitted by policy 3f2a', policy_id: '3f2a' },
      tier: { value: 1, source: 'declared' },
      legs_evaluated: { principal: true, agent: true, delegation: true },
    })

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()
    ;(await screen.findByRole('button', { name: 'Test' })).click()
    ;(await screen.findByRole('button', { name: 'Run test' })).click()

    expect(await screen.findByText(/classification SECRET exceeds cap/)).toBeInTheDocument()
    expect(screen.getByText(/permitted by policy 3f2a/)).toBeInTheDocument()
    // The divergence must be called out, not left for the reader to spot.
    expect(screen.getByText(/differ/i)).toBeInTheDocument()
  })

  // The brief's own version of this test mocked testPolicy with a single
  // flat {effect, reason, source, policy_id} object -- PolicyTestVerdict's
  // shape, the very type this task replaces. Fact 5 requires the real
  // envelope ({isolated, with_existing_policies, tier, legs_evaluated}), and
  // `npm run build` typechecks test files too (tsconfig.app.json includes
  // "src"), so that literal mock would not compile. Reshaped to the real
  // response while keeping the original intent -- a leg's effect and reason
  // render together -- and given the two legs distinct reasons so the
  // assertion matches exactly one element instead of two.
  it('renders the test verdict, effect and reason together', async () => {
    vi.spyOn(api, 'policies').mockResolvedValue([])
    vi.spyOn(api, 'policyLanguages').mockResolvedValue(['cedar'])
    vi.spyOn(api, 'testPolicy').mockResolvedValue({
      isolated: {
        effect: 'deny', reason: 'resource classification SECRET exceeds cap CONFIDENTIAL',
      },
      with_existing_policies: {
        effect: 'deny', reason: 'confirmed by policy p1', source: 'policy', policy_id: 'p1',
      },
      tier: { value: 1, source: 'derived' },
      legs_evaluated: { principal: true, agent: false, delegation: false },
    })

    render(<PoliciesScreen />)
    await screen.findByText('No policies.')
    ;(await screen.findByRole('button', { name: 'New policy' })).click()
    ;(await screen.findByRole('button', { name: 'Test' })).click()
    ;(await screen.findByRole('button', { name: 'Run test' })).click()

    expect(await screen.findByText(/exceeds cap CONFIDENTIAL/)).toBeInTheDocument()
  })
})
