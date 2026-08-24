// App.tsx is the shell: fetch the PAP's public configuration, sign in, pick a
// screen. Nothing more, on purpose.
//
// No router. Six screens with no deep links and no shareable URLs do not need
// one, and a URL-driven route would be the one thing in this application
// tempted to survive a reload — which, given the token cannot (N12), would
// only produce a bookmarked screen that immediately asks you to sign in.

import { useEffect, useState, useSyncExternalStore } from 'react'

import { describeError, fetchUIConfig } from './api'
import {
  discover,
  isAuthenticated,
  signIn,
  signOut,
  subscribeAuthChange,
  type Discovery,
  type UIConfig,
} from './auth'
import {
  AgentsScreen,
  ApprovalsScreen,
  DelegationsScreen,
  LabelRulesScreen,
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
  { id: 'label-rules', label: 'Label rules', Screen: LabelRulesScreen },
  { id: 'approvals', label: 'Approvals', Screen: ApprovalsScreen },
  { id: 'delegations', label: 'Delegations', Screen: DelegationsScreen },
] as const

export default function App() {
  const [config, setConfig] = useState<UIConfig | null>(null)
  const [discovery, setDiscovery] = useState<Discovery | null>(null)
  const [error, setError] = useState<string | null>(null)
  // Subscribed, not a one-time useState(isAuthenticated()): that function
  // reads a module variable in auth.ts, and a snapshot taken once goes stale
  // the moment anything outside a click changes it. That is exactly what
  // onUnauthorized (auth.ts, called from api.ts on a 401) used to do -- null
  // the token and leave a local flag true, so the shell kept its signed-in
  // chrome over a session that had already ended. Every writer of the token
  // notifies now, so every one of them repaints the shell the same way.
  const signedIn = useSyncExternalStore(subscribeAuthChange, isAuthenticated)
  const [busy, setBusy] = useState(false)
  const [screen, setScreen] = useState<(typeof SCREENS)[number]['id']>('policies')

  useEffect(() => {
    fetchUIConfig().then(
      (cfg) => {
        setConfig(cfg)
        // Chained here, on mount, rather than awaited inside signIn: an
        // await before window.open spends the user-activation token the
        // popup needs, and Safari blocks the popup as a result. See
        // auth.ts's signIn for the full reasoning.
        discover(cfg.issuer).then(setDiscovery, (err: unknown) => setError(describeError(err)))
      },
      (err: unknown) => setError(describeError(err)),
    )
  }, [])

  const onSignIn = async () => {
    if (!config || !discovery) return
    setError(null)
    setBusy(true)
    try {
      // Called straight from the click handler: the popup this opens needs a
      // user gesture. config and discovery are both already resolved (mount
      // effect, above), so nothing here awaits anything before signIn's own
      // window.open.
      await signIn(config, discovery)
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
          <Button variant="outline" onClick={() => signOut()}>
            Sign out
          </Button>
        ) : (
          <Button onClick={() => void onSignIn()} disabled={!config || !discovery || busy}>
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
