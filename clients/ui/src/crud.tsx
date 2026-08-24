// crud.ts holds the data-loading hooks every screen shares. Split out of
// screens.tsx when those screens grew editors: the loading behaviour is the
// one part that genuinely is identical across all seven, and it is the part
// most easily broken by a well-meaning edit to one screen.

import { useCallback, useEffect, useState } from 'react'

import { describeError } from './api'

interface ListState<T> {
  rows: T[] | null
  error: string | null
}

/** Loads a list on mount, and again whenever reload() is called. `rows ===
 *  null` means "not loaded yet" — distinct from `[]`, which means the tenant
 *  genuinely has none. The API guarantees that distinction: every list
 *  endpoint returns [] and never null.
 *
 *  reload bumps a counter rather than re-running the effect body directly, so
 *  no setState happens synchronously inside the effect — the cascading-render
 *  pattern react-hooks/set-state-in-effect exists to catch. A reload leaves
 *  the previous rows on screen until the new ones arrive, which is what an
 *  operator who just clicked Revoke wants to see. */
export function useList<T>(load: () => Promise<T[]>): ListState<T> & { reload: () => void } {
  const [state, setState] = useState<ListState<T>>({ rows: null, error: null })
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    let live = true
    load().then(
      (rows) => {
        if (live) setState({ rows, error: null })
      },
      (err: unknown) => {
        if (live) setState({ rows: [], error: describeError(err) })
      },
    )
    return () => {
      live = false
    }
  }, [load, generation])

  const reload = useCallback(() => setGeneration((g) => g + 1), [])
  return { ...state, reload }
}

export function Loading() {
  return <p className="text-sm text-muted-foreground">Loading…</p>
}

export interface Editor<T> {
  draft: T | null
  editingID: string | null
  error: string | null
  busy: boolean
  create: (blank: T) => void
  edit: (id: string) => void
  patch: (fields: Partial<T>) => void
  save: () => void
  close: () => void
}

/**
 * Holds one resource's draft.
 *
 * Two properties matter and neither is obvious:
 *
 * 1. `edit` seeds from a fresh GET, never from the list row handed in. Every
 *    PUT on this API is a full replace, so a draft seeded from a stale row
 *    writes that row's staleness back over whatever is stored.
 *
 * 2. `save` re-reads before an update and refuses if the stored object moved.
 *    The PAP has no If-Match and Version is server-owned, so the only
 *    alternative is silently discarding a colleague's edit. The comparison is
 *    a whole-object one rather than a timestamp: ResourceLabelRule,
 *    TierOverride and ToolCatalogEntry carry no updated_at to compare. Both
 *    sides are server JSON parsed the same way, so key order matches and
 *    JSON.stringify is a sound comparison here.
 *
 * The guard narrows the window; it does not close it. Two saves inside one
 * round-trip still race, and closing that needs If-Match in the API.
 *
 * `res` is an object literal at every call site, so it is a new reference
 * each render. Wrap it in useMemo in the screen, or the `edit` callback
 * churns.
 */
export function useEditor<T>(res: {
  get: (id: string) => Promise<T>
  create: (value: T) => Promise<T>
  update: (id: string, value: T) => Promise<T>
  onSaved: () => void
}): Editor<T> {
  const [draft, setDraft] = useState<T | null>(null)
  const [snapshot, setSnapshot] = useState<T | null>(null)
  const [editingID, setEditingID] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const close = useCallback(() => {
    setDraft(null); setSnapshot(null); setEditingID(null); setError(null)
  }, [])

  const create = useCallback((blank: T) => {
    setDraft(blank); setSnapshot(null); setEditingID(null); setError(null)
  }, [])

  const edit = useCallback((id: string) => {
    setError(null); setBusy(true); setEditingID(id)
    res.get(id).then(
      (fresh) => { setDraft(fresh); setSnapshot(fresh); setBusy(false) },
      (err: unknown) => { setError(describeError(err)); setBusy(false) },
    )
  }, [res])

  const patch = useCallback((fields: Partial<T>) => {
    setDraft((d) => (d === null ? d : { ...d, ...fields }))
  }, [])

  const save = useCallback(async () => {
    if (draft === null) return
    setBusy(true); setError(null)
    try {
      if (editingID === null) {
        await res.create(draft)
      } else {
        const fresh = await res.get(editingID)
        if (JSON.stringify(fresh) !== JSON.stringify(snapshot)) {
          setError('this changed while you were editing — close and reopen to see the current version')
          return
        }
        await res.update(editingID, draft)
      }
      res.onSaved()
      setDraft(null); setSnapshot(null); setEditingID(null)
    } catch (err: unknown) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }, [draft, editingID, res, snapshot])

  return {
    draft, editingID, error, busy, create, edit, patch, close,
    // save resolves once its awaits settle -- a caller that wants to know
    // when a save finishes may await it, same as `edit` above resolves on
    // its own schedule. It never rejects: every branch is inside
    // try/catch/finally and reports through `error`, so there is nothing
    // for a fire-and-forget JSX handler to swallow.
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    save,
  }
}
