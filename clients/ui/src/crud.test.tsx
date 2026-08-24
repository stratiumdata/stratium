import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { useEditor } from './crud'

interface Row { id: string; name: string }

function harness(over: Partial<Parameters<typeof useEditor<Row>>[0]> = {}) {
  const res = {
    get: vi.fn((id: string) => Promise.resolve({ id, name: 'stored' })),
    create: vi.fn((v: Row) => Promise.resolve(v)),
    update: vi.fn((_id: string, v: Row) => Promise.resolve(v)),
    onSaved: vi.fn(),
    ...over,
  }
  return { res, hook: renderHook(() => useEditor<Row>(res)) }
}

describe('useEditor', () => {
  // The list row may be stale, and PUT is a full replace: seeding the form
  // from the row would write back whatever the list happened to hold.
  it('seeds the draft from a fresh GET, not from the caller', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).toEqual({ id: 'r1', name: 'stored' }))
    expect(res.get).toHaveBeenCalledWith('r1')
  })

  it('sends the whole draft on save, not the patched fields', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    act(() => hook.result.current.patch({ name: 'edited' }))
    act(() => { hook.result.current.save() })
    await waitFor(() => expect(res.onSaved).toHaveBeenCalledTimes(1))

    expect(res.update).toHaveBeenCalledWith('r1', { id: 'r1', name: 'edited' })
  })

  // Two operators, one resource, no If-Match on the API. Without this the
  // second save silently discards the first.
  it('refuses to save when the stored object moved under the edit', async () => {
    let stored: Row = { id: 'r1', name: 'stored' }
    const { res, hook } = harness({ get: vi.fn(() => Promise.resolve(stored)) })

    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    stored = { id: 'r1', name: 'somebody else got here first' }
    act(() => hook.result.current.patch({ name: 'mine' }))
    act(() => { hook.result.current.save() })
    await waitFor(() => expect(hook.result.current.error).toMatch(/changed while you were editing/))

    expect(res.update).not.toHaveBeenCalled()
  })

  it('reports the server refusal verbatim rather than swallowing it', async () => {
    const { hook } = harness({
      update: vi.fn(() => Promise.reject(new Error('this action requires role admin; your token carries viewer'))),
    })
    act(() => hook.result.current.edit('r1'))
    await waitFor(() => expect(hook.result.current.draft).not.toBeNull())

    act(() => { hook.result.current.save() })
    await waitFor(() => expect(hook.result.current.error).toContain('requires role admin'))
  })

  it('creates without a guard read, since there is nothing yet to clobber', async () => {
    const { res, hook } = harness()
    act(() => hook.result.current.create({ id: '', name: 'new' }))
    act(() => { hook.result.current.save() })
    await waitFor(() => expect(res.create).toHaveBeenCalledWith({ id: '', name: 'new' }))

    expect(res.get).not.toHaveBeenCalled()
  })
})
