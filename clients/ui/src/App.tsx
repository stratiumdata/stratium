// App.tsx is the shell: fetch the PAP's public configuration, sign in, pick a
// screen. Nothing more, on purpose.
//
// No router. Six screens with no deep links and no shareable URLs do not need
// one, and a URL-driven route would be the one thing in this application
// tempted to survive a reload — which, given the token cannot (N12), would
// only produce a bookmarked screen that immediately asks you to sign in.

import { useEffect, useState } from 'react'

import { describeError, fetchUIConfig } from './api'
import { isAuthenticated, signIn, signOut, type UIConfig } from './auth'
import {
  AgentsScreen,
  ApprovalsScreen,
  DelegationsScreen,
  PoliciesScreen,
  TierOverridesScreen,
  ToolCatalogScreen,
} from './screens'
import { Button, ErrorBanner } from './ui'
import { cn } from './lib'

const SCREENS = [
  { id: 'policies', label: 'Policies', Screen: PoliciesScreen },
  { id: 'agents', label: 'Agents', Screen: AgentsScreen },
  { id: 'tier-overrides', label: 'Tier overrides', Screen: TierOverridesScreen },
  { id: 'tool-catalog', label: 'Tool catalog', Screen: ToolCatalogScreen },
  { id: 'approvals', label: 'Approvals', Screen: ApprovalsScreen },
  { id: 'delegations', label: 'Delegations', Screen: DelegationsScreen },
] as const

export default function App() {
  const [config, setConfig] = useState<UIConfig | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Not derived from isAuthenticated() on every render: that function reads a
  // module variable React cannot subscribe to, so a state flag is what makes
  // a completed sign-in actually repaint.
  const [signedIn, setSignedIn] = useState(isAuthenticated())
  const [busy, setBusy] = useState(false)
  const [screen, setScreen] = useState<(typeof SCREENS)[number]['id']>('policies')

  useEffect(() => {
    fetchUIConfig().then(setConfig, (err: unknown) => setError(describeError(err)))
  }, [])

  const onSignIn = async () => {
    if (!config) return
    setError(null)
    setBusy(true)
    try {
      // Called straight from the click handler: the popup this opens needs a
      // user gesture, and anything awaited before window.open costs it. The
      // discovery fetch inside signIn is the one exception browsers tolerate
      // in practice; a blocked popup is reported, never worked around.
      await signIn(config)
      setSignedIn(isAuthenticated())
    } catch (err) {
      setError(describeError(err))
    } finally {
      setBusy(false)
    }
  }

  const Active = SCREENS.find((s) => s.id === screen)?.Screen ?? PoliciesScreen

  return (
    <div className="mx-auto min-h-screen max-w-7xl px-6 py-8">
      <header className="mb-6 flex flex-wrap items-center justify-between gap-4 border-b border-border pb-4">
        <div>
          <h1 className="text-xl font-semibold">Stratium admin</h1>
          <p className="text-sm text-muted-foreground">
            Agent authorization control plane
            {config ? ` — signed in against ${config.issuer}` : ''}
          </p>
        </div>
        {signedIn ? (
          <Button
            variant="outline"
            onClick={() => {
              signOut()
              setSignedIn(false)
            }}
          >
            Sign out
          </Button>
        ) : (
          <Button onClick={() => void onSignIn()} disabled={!config || busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </Button>
        )}
      </header>

      {error ? <ErrorBanner>{error}</ErrorBanner> : null}

      {signedIn ? (
        <>
          <nav className="mb-6 flex flex-wrap gap-1" aria-label="Screens">
            {SCREENS.map((s) => (
              <button
                key={s.id}
                type="button"
                aria-current={s.id === screen ? 'page' : undefined}
                onClick={() => setScreen(s.id)}
                className={cn(
                  'rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
                  s.id === screen ? 'bg-primary text-primary-foreground' : 'hover:bg-accent',
                )}
              >
                {s.label}
              </button>
            ))}
          </nav>
          <Active />
        </>
      ) : (
        <p className="max-w-2xl text-sm text-muted-foreground">
          Sign in with your organisation's identity provider to continue. Your token is held
          in memory for this tab only — it is never written to browser storage, so reloading
          this page signs you out.
        </p>
      )}
    </div>
  )
}
