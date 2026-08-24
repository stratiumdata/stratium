import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type ResourceLabelRule } from '../api'
import { LabelRulesScreen } from './label-rules'

afterEach(() => { vi.restoreAllMocks() })

function rule(over: Partial<ResourceLabelRule> = {}): ResourceLabelRule {
  return {
    id: '33333333-3333-3333-3333-333333333333',
    tenant_id: 'acme',
    prefix: '/secret-',
    hierarchy: 'nato',
    level: 'SECRET',
    ...over,
  }
}

describe('LabelRulesScreen', () => {
  it('says so when the tenant has no rules, rather than showing an empty table', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([])
    render(<LabelRulesScreen />)
    expect(await screen.findByText('No resource label rules.')).toBeInTheDocument()
  })

  // "" is a prefix of every resource id: R7's tenant-wide catch-all, and the
  // documented cure for "a cap was enabled and now everything denies". A blank
  // cell would read as a missing value.
  it('renders an empty prefix as the catch-all rather than as blank', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule({ prefix: '', level: 'PUBLIC' })])
    render(<LabelRulesScreen />)
    expect(await screen.findByText(/matches every resource/i)).toBeInTheDocument()
  })

  // The rule this screen exists to protect. migrations/000019 deliberately
  // omits a length(prefix) > 0 CHECK; a required-field validator here would
  // re-add in the browser the constraint the schema author refused to add.
  it('saves a rule whose prefix is empty', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([])
    const create = vi.spyOn(api, 'createResourceLabelRule').mockResolvedValue(rule({ prefix: '' }))

    render(<LabelRulesScreen />)
    await screen.findByText('No resource label rules.')
    screen.getByRole('button', { name: 'New rule' }).click()

    fireEvent.change(await screen.findByLabelText('Hierarchy'), { target: { value: 'nato' } })
    fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'PUBLIC' } })

    screen.getByRole('button', { name: 'Save' }).click()

    // Every field, and prefix present as "" rather than absent.
    await waitFor(() => expect(create).toHaveBeenCalledWith({
      id: '', tenant_id: '', prefix: '', hierarchy: 'nato', level: 'PUBLIC',
    }))
  })

  it('warns that deleting the catch-all makes unlabelled resources deny', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule({ prefix: '' })])
    render(<LabelRulesScreen />)

    ;(await screen.findByRole('button', { name: 'Delete' })).click()
    expect(await screen.findByText(/unlabelled resources will deny/i)).toBeInTheDocument()
  })

  // useEditor's edit() rejection sets error but leaves draft null, so the
  // panel that normally shows editor.error never opens. A failed GET here --
  // the row deleted by a colleague, a 500, a network blip -- must still say
  // something, not silently do nothing.
  it('shows the GET failure when Edit fails to load a row', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule()])
    vi.spyOn(api, 'resourceLabelRule').mockRejectedValue(new APIError(500, 'boom'))

    render(<LabelRulesScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('boom')
  })

  // N14: the button is not conditioned on a role, and the refusal is shown.
  it('offers delete to every operator and surfaces the server refusal', async () => {
    vi.spyOn(api, 'resourceLabelRules').mockResolvedValue([rule()])
    vi.spyOn(api, 'deleteResourceLabelRule').mockRejectedValue(
      new APIError(403, 'this action requires role admin; your token carries editor'),
    )

    render(<LabelRulesScreen />)
    ;(await screen.findByRole('button', { name: 'Delete' })).click()
    // findByRole, not getByRole: a raw DOM .click() (unlike fireEvent.click)
    // does not force React 19's createRoot to flush synchronously, so the
    // ConfirmRow this click renders is not yet in the tree the instant
    // .click() returns. findByRole polls until it is.
    ;(await screen.findByRole('button', { name: 'Delete rule' })).click()

    expect(await screen.findByRole('alert')).toHaveTextContent('requires role admin')
  })
})
