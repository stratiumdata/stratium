import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  authHeader, isAuthenticated, preparePkce, redirectURI, signIn, signOut, type UIConfig,
} from './auth'

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

/** RFC 7636 base64url, reimplemented here rather than imported from auth.ts:
 *  this proves the real bytes crypto.subtle.digest produced, not that
 *  auth.ts's own encoder agrees with itself. */
function base64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The S256 code_challenge RFC 7636 defines for verifier, computed
 *  independently of auth.ts's own private s256(). */
async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

/** A popup stand-in that replies with the state it was asked for, as
 *  callback.html would. */
function fakePopup(reply: (state: string) => Record<string, unknown> | null) {
  const popup = { closed: false, close: vi.fn(() => (popup.closed = true)) }
  vi.spyOn(window, 'open').mockImplementation((url) => {
    const state = new URL(String(url)).searchParams.get('state') ?? ''
    const message = reply(state)
    if (message) {
      // postMessage is async in a browser; a microtask is close enough and
      // keeps the test synchronous to reason about.
      queueMicrotask(() =>
        window.dispatchEvent(
          new MessageEvent('message', { data: message, origin: window.location.origin }),
        ),
      )
    }
    return popup as unknown as Window
  })
  return popup
}

// discovery is passed into signIn directly now (item 1: hoisted out of
// signIn and into App.tsx's mount effect, so signIn stays synchronous up to
// window.open), so this mock has only ever needed to answer the token
// endpoint since that change.
function mockFetch(token: Record<string, unknown> = { access_token: 'operator-token' }) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : input.toString()
    if (url === discovery.token_endpoint) {
      return Promise.resolve(new Response(JSON.stringify(token), { status: 200 }))
    }
    return Promise.reject(new Error(`unexpected fetch: ${url}`))
  })
}

afterEach(() => {
  signOut()
  vi.restoreAllMocks()
})

describe('signIn', () => {
  it('completes PKCE and holds the token in memory', async () => {
    mockFetch()
    fakePopup((state) => ({ source: 'stratium-oidc-callback', code: 'the-code', state }))

    expect(isAuthenticated()).toBe(false)
    await signIn(config, discovery, await preparePkce())

    expect(isAuthenticated()).toBe(true)
    expect(authHeader()).toEqual({ Authorization: 'Bearer operator-token' })
  })

  it('sends a real S256 challenge, never the verifier itself', async () => {
    const fetchSpy = mockFetch()
    let authorizeURL = ''
    vi.spyOn(window, 'open').mockImplementation((url) => {
      authorizeURL = String(url)
      const state = new URL(authorizeURL).searchParams.get('state') ?? ''
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

    await signIn(config, discovery, await preparePkce())

    const params = new URL(authorizeURL).searchParams
    expect(params.get('response_type')).toBe('code')
    expect(params.get('code_challenge_method')).toBe('S256')
    expect(params.get('redirect_uri')).toBe(redirectURI())
    // Verified against an independent SHA-256 computation, not merely
    // "differs from the verifier": any non-hash transform (e.g. "plain",
    // which sets the challenge equal to the verifier and silently removes
    // PKCE's whole protection) would pass a bare inequality check without
    // being S256 at all.
    const challenge = params.get('code_challenge') ?? ''
    const body = (fetchSpy.mock.calls.at(-1)?.[1] as RequestInit).body as URLSearchParams
    const verifier = body.get('code_verifier') ?? ''
    expect(verifier).not.toBe('')
    expect(challenge).toBe(await s256(verifier))
  })

  it('never requests offline_access, so no refresh token is ever minted', async () => {
    mockFetch()
    let authorizeURL = ''
    vi.spyOn(window, 'open').mockImplementation((url) => {
      authorizeURL = String(url)
      const state = new URL(authorizeURL).searchParams.get('state') ?? ''
      queueMicrotask(() =>
        window.dispatchEvent(
          new MessageEvent('message', {
            data: { source: 'stratium-oidc-callback', code: 'c', state },
            origin: window.location.origin,
          }),
        ),
      )
      return { closed: false, close: vi.fn() } as unknown as Window
    })

    await signIn(config, discovery, await preparePkce())
    expect(new URL(authorizeURL).searchParams.get('scope')).not.toContain('offline_access')
  })

  it('rejects a callback whose state does not match the request', async () => {
    mockFetch()
    fakePopup(() => ({ source: 'stratium-oidc-callback', code: 'attacker-code', state: 'wrong' }))

    await expect(signIn(config, discovery, await preparePkce())).rejects.toThrow(/state mismatch/)
    expect(isAuthenticated()).toBe(false)
  })

  it('ignores a message from another origin', async () => {
    mockFetch()
    const popup = { closed: false, close: vi.fn() }
    vi.spyOn(window, 'open').mockImplementation((url) => {
      const state = new URL(String(url)).searchParams.get('state') ?? ''
      queueMicrotask(() => {
        // A different origin's window posting a perfectly-shaped, correctly-
        // stated message must be ignored outright.
        window.dispatchEvent(
          new MessageEvent('message', {
            data: { source: 'stratium-oidc-callback', code: 'evil', state },
            origin: 'https://evil.example.com',
          }),
        )
        // Then the popup closes without ever having delivered anything valid.
        popup.closed = true
      })
      return popup as unknown as Window
    })

    await expect(signIn(config, discovery, await preparePkce())).rejects.toThrow(/closed before completing/)
    expect(isAuthenticated()).toBe(false)
  })

  it('reports a blocked popup rather than falling back to anything', async () => {
    mockFetch()
    vi.spyOn(window, 'open').mockReturnValue(null)

    // The message must say what to do, because the alternative — a redirect
    // flow — needs storage, which N12 forbids outright.
    await expect(signIn(config, discovery, await preparePkce())).rejects.toThrow(/Allow pop-ups/)
    expect(isAuthenticated()).toBe(false)
  })

  it('does not authenticate when the token endpoint returns no access_token', async () => {
    mockFetch({ id_token: 'an id token is not an access token' })
    fakePopup((state) => ({ source: 'stratium-oidc-callback', code: 'c', state }))

    await expect(signIn(config, discovery, await preparePkce())).rejects.toThrow(/no access_token/)
    expect(isAuthenticated()).toBe(false)
  })

  // THE bug this signature exists to prevent. signIn used to derive the S256
  // challenge itself -- `code_challenge: await s256(verifier)` -- which put an
  // await before window.open and spent the user-activation token the popup
  // needs. Safari blocks the popup outright; the error it produces says "allow
  // pop-ups", sending the operator to fix a setting that was never wrong.
  //
  // Asserting synchronously, on a promise deliberately not awaited, is the
  // only way to state it: if anything in signIn awaits before window.open,
  // the call has not happened yet when this line runs.
  it('opens the popup synchronously, with nothing awaited first', async () => {
    mockFetch()
    const popup = { closed: false, close: vi.fn() }
    const open = vi.spyOn(window, 'open').mockReturnValue(popup as unknown as Window)

    const pkce = { verifier: 'v'.repeat(32), state: 'st', challenge: 'ch' }
    // Deliberately not awaited yet -- the assertion below is the whole point.
    // It is settled at the end of the test rather than left dangling: an
    // in-flight signIn keeps a message listener and a close-poll alive, and
    // those leak into whichever test runs next.
    const flow = signIn(config, discovery, pkce)

    expect(open).toHaveBeenCalledTimes(1)
    // ...and the challenge it carries is the prepared one, not a fresh derive.
    const url = new URL((open.mock.calls[0]?.[0] as string) ?? '')
    expect(url.searchParams.get('code_challenge')).toBe('ch')
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('state')).toBe('st')

    popup.closed = true
    await expect(flow).rejects.toThrow(/closed before completing/)
  })

  it('derives a real S256 challenge, distinct from the verifier', async () => {
    const a = await preparePkce()
    const b = await preparePkce()
    expect(a.challenge).not.toBe(a.verifier)
    expect(a.verifier).not.toBe(b.verifier)
    expect(a.state).not.toBe(b.state)
    // base64url: no +, /, or = padding.
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]+$/)
  })

})

describe('the token never reaches browser storage (N12)', () => {
  it('leaves localStorage and sessionStorage untouched across a full sign-in', async () => {
    mockFetch()
    fakePopup((state) => ({ source: 'stratium-oidc-callback', code: 'the-code', state }))

    const setLocal = vi.spyOn(Storage.prototype, 'setItem')
    await signIn(config, discovery, await preparePkce())

    expect(isAuthenticated()).toBe(true)
    expect(setLocal).not.toHaveBeenCalled()
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
    expect(document.cookie).toBe('')
  })

  it('forgets the token on signOut, which is what a page reload also does', () => {
    signOut()
    expect(isAuthenticated()).toBe(false)
    expect(authHeader()).toBeNull()
  })
})
