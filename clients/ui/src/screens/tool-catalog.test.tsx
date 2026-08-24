import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, type ToolCatalogEntry } from '../api'
import { ToolCatalogScreen } from './tool-catalog'

afterEach(() => { vi.restoreAllMocks() })

function entry(over: Partial<ToolCatalogEntry> = {}): ToolCatalogEntry {
  return {
    id: '88888888-8888-8888-8888-888888888888',
    tool_name: 'Read',
    action_tier: 1,
    verb: 'read',
    resource_field: 'file_path',
    ...over,
  }
}

describe('ToolCatalogScreen', () => {
  // The PAP exposes no DELETE /v1/tool-catalog/{id}. A button here would 404.
  it('offers no delete, because the API has none', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([entry()])
    render(<ToolCatalogScreen />)
    await screen.findByText('Read')
    expect(screen.queryByRole('button', { name: 'Delete' })).not.toBeInTheDocument()
  })

  // null and 0 are different: null means "derive the tier", 0 means REASONING.
  // A numeric input defaulting to zero would silently pin every new tool to
  // the lowest tier.
  it('sends action_tier as null when the tier is derived, never as 0', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    fireEvent.change(await screen.findByLabelText('Tool name'), { target: { value: 'Glob' } })
    // "Derive the tier" is checked by default.
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ tool_name: 'Glob', action_tier: null }),
    ))
  })

  // "" is not "unset" for these two: they are *string with omitempty in Go, so
  // "" arrives as a non-nil pointer to the empty string and satisfies both the
  // store's `ActionTier == nil && CommandField == nil` guard and the database's
  // tool_catalog_tier_or_command_field CHECK. The row stored then means "derive
  // the tier from the field named empty-string" -- an invalid entry that both
  // guards were written to prevent.
  it('omits an empty command_field rather than sending an empty string', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    fireEvent.change(await screen.findByLabelText('Tool name'), { target: { value: 'Glob' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalled())
    const call = create.mock.calls[0]
    if (!call) throw new Error('createToolCatalogEntry was not called')
    const sent = call[0] as unknown as Record<string, unknown>
    expect('command_field' in sent && sent.command_field === '').toBe(false)
    expect('resource_field' in sent && sent.resource_field === '').toBe(false)
  })

  // The control shows names and the wire carries numbers. Driving it by name
  // and asserting the number is what proves the two stay in step -- a mapping
  // that silently drifted would send the wrong tier under the right label.
  it('sends a number once the tier is set explicitly', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    const create = vi.spyOn(api, 'createToolCatalogEntry').mockResolvedValue(entry())

    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    ;(await screen.findByLabelText('Derive the tier from the command')).click()
    fireEvent.change(screen.getByLabelText('Action tier'), { target: { value: 'EXTERNAL_COMMS' } })
    screen.getByRole('button', { name: 'Save' }).click()

    await waitFor(() => expect(create).toHaveBeenCalledWith(
      expect.objectContaining({ action_tier: 3 }),
    ))
  })

  it('offers the tier names, not raw numbers', async () => {
    vi.spyOn(api, 'toolCatalog').mockResolvedValue([])
    render(<ToolCatalogScreen />)
    await screen.findByText('No tool catalog entries.')
    screen.getByRole('button', { name: 'New entry' }).click()

    ;(await screen.findByLabelText('Derive the tier from the command')).click()
    const select = screen.getByLabelText('Action tier')
    expect(Array.from((select as HTMLSelectElement).options).map((o) => o.value))
      .toEqual(['REASONING', 'READ_ONLY', 'INTERNAL_MODIFY', 'EXTERNAL_COMMS', 'DESTRUCTIVE'])
  })
})
