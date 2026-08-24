import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type TierOverride } from '../api'
import { TierOverridesScreen } from './tier-overrides'

afterEach(() => { vi.restoreAllMocks() })

function override(over: Partial<TierOverride> = {}): TierOverride {
  return {
    id: '77777777-7777-7777-7777-777777777777',
    tool_or_verb: 'Bash',
    action_tier: 4,
    builtin_tier: 2,
    created_at: '2026-08-23T10:00:00Z',
    created_by: 'operator@example.com',
    ...over,
  }
}

describe('TierOverridesScreen', () => {
  // The store ignores ID, TenantID, BuiltinTier, CreatedAt and CreatedBy on
  // input and sets them authoritatively -- BuiltinTier specifically must never
  // be operator-supplied. An input for one would accept a value that is
  // discarded without complaint.
  it('offers no input for the server-owned fields', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([override()])
    vi.spyOn(api, 'tierOverride').mockResolvedValue(override())

    render(<TierOverridesScreen />)
    ;(await screen.findByRole('button', { name: 'Edit' })).click()

    await screen.findByLabelText('Tool or verb')
    expect(screen.queryByLabelText('Builtin tier')).not.toBeInTheDocument()
    expect(screen.queryByLabelText('Created by')).not.toBeInTheDocument()
  })

  it('shows the builtin tier beside the override, so the operator sees what is being overridden', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([override({ action_tier: 4, builtin_tier: 2 })])
    render(<TierOverridesScreen />)
    // actionTier() renders the names, not the numbers.
    expect(await screen.findByText('DESTRUCTIVE')).toBeInTheDocument()
    expect(screen.getByText('INTERNAL_MODIFY')).toBeInTheDocument()
  })

  it('sends every editable field on save', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([])
    const create = vi.spyOn(api, 'createTierOverride').mockResolvedValue(override())

    render(<TierOverridesScreen />)
    await screen.findByText('No tier overrides.')
    screen.getByRole('button', { name: 'New override' }).click()

    fireEvent.change(await screen.findByLabelText('Tool or verb'), { target: { value: 'Write' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ tool_or_verb: 'Write', action_tier: 0 }),
    ))
  })

  it('offers action tiers by name and sends the number they stand for', async () => {
    vi.spyOn(api, 'tierOverrides').mockResolvedValue([])
    const create = vi.spyOn(api, 'createTierOverride').mockResolvedValue(override())

    render(<TierOverridesScreen />)
    await screen.findByText('No tier overrides.')
    screen.getByRole('button', { name: 'New override' }).click()

    const select = await screen.findByLabelText('Action tier')
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(['REASONING', 'READ_ONLY', 'INTERNAL_MODIFY', 'EXTERNAL_COMMS', 'DESTRUCTIVE'])

    fireEvent.change(await screen.findByLabelText('Tool or verb'), { target: { value: 'Write' } })
    fireEvent.change(select, { target: { value: 'DESTRUCTIVE' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ tool_or_verb: 'Write', action_tier: 4 }),
    ))
  })
})
