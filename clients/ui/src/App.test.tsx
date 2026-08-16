// App.test.tsx exercises the shell's own auth wiring: sign in through the
// real popup flow, then the exact regression item 2 of the Phase 14
// deferred-minor backlog fixed. onUnauthorized() (auth.ts) used to null the
// token and leave App's signed-in flag untouched, so an expired-token
// response left signed-in chrome -- nav, an active screen -- on the page
// with every screen now erroring 401. App derives its signed-in flag from
// auth.ts via useSyncExternalStore, so onUnauthorized repaints the shell the
// same way signIn and signOut always did.

import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import App from './App'
import { onUnauthorized, signOut, type UIConfig } from './auth'

const config: UIConfig = {
  issuer: 'https://idp.example.com',
  client_id: 'stratium-pap-ui',
  audience: 'stratium-pap',
  scope: 'openid profile email',
}

const discovery = {
  authorization_endpoint: 'https://idp.example.com/authorize',
  token_endpoint: 'https://idp.example.com/oauth/token',
}

/** Routes every fetch a full sign-in makes: the UI's own config, the
 *  issuer's discovery document, the token exchange, and the Policies screen's
 *  own list call that fires the moment the shell becomes signed in. */
function mockFetch() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : input.toString()
    if (url.endsWith('/ui-config')) {
      return Promise.resolve(new Response(JSON.stringify(config), { status: 200 }))
    }
    if (url.includes('.well-known/openid-configuration')) {
      return Promise.resolve(new Response(JSON.stringify(discovery), { status: 200 }))
    }
    if (url === discovery.token_endpoint) {
      return Promise.resolve(
        new Response(JSON.stringify({ access_token: 'operator-token' }), { status: 200 }),
      )
    }
    if (url.endsWith('/v1/policies')) {
      return Promise.resolve(new Response('[]', { status: 200 }))
    }
    return Promise.reject(new Error(`unexpected fetch: ${url}`))
  })
}

/** Completes the popup leg of signIn the instant window.open is called, the
 *  same way callback.html posting back would -- mirrors auth.test.ts's own
 *  fakePopup. */
function mockPopup() {
  vi.spyOn(window, 'open').mockImplementation((url) => {
    const state = new URL(String(url)).searchParams.get('state') ?? ''
    queueMicrotask(() =>
      window.dispatchEvent(
        new MessageEvent('message', {
          data: { source: 'stratium-oidc-callback', code: 'the-code', state },
          origin: window.location.origin,
        }),
      ),
    )
    return { closed: false, close: vi.fn() } as unknown as Window
  })
}

afterEach(() => {
  signOut()
  vi.restoreAllMocks()
})

describe('the shell and an expired token (item 2 of the Phase 14 deferred-minor backlog)', () => {
  it('returns to the signed-out shell when onUnauthorized fires mid-session', async () => {
    mockFetch()
    mockPopup()

    render(<App />)

    const signInButton = await screen.findByRole('button', { name: 'Sign in' })
    await waitFor(() => expect(signInButton).not.toBeDisabled())
    signInButton.click()

    // Signed in: "Sign out" and the screen nav are on the page.
    await screen.findByRole('button', { name: 'Sign out' })
    expect(screen.getByRole('navigation', { name: 'Screens' })).toBeInTheDocument()

    // The event this fix is about: an API call's 401 reaches onUnauthorized
    // with no click, no reload -- nothing else driving App to notice.
    onUnauthorized()

    // The shell must reflect it on its own: signed-out chrome back, not
    // stale nav left over a screen that would now 401 on every request.
    await screen.findByRole('button', { name: 'Sign in' })
    expect(screen.queryByRole('navigation', { name: 'Screens' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Sign out' })).not.toBeInTheDocument()
  })
})
