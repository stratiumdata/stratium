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
