import { afterEach, describe, expect, it, vi } from 'vitest'

import { authHeader, isAuthenticated, redirectURI, signIn, signOut, type UIConfig } from './auth'

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

function mockFetch(token: Record<string, unknown> = { access_token: 'operator-token' }) {
  return vi.spyOn(globalThis, 'fetch').mockImplementation((input: RequestInfo | URL) => {
    const url = input instanceof Request ? input.url : input.toString()
    if (url.includes('.well-known/openid-configuration')) {
      return Promise.resolve(new Response(JSON.stringify(discovery), { status: 200 }))
    }
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
    await signIn(config)

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

    await signIn(config)

    const params = new URL(authorizeURL).searchParams
    expect(params.get('response_type')).toBe('code')
    expect(params.get('code_challenge_method')).toBe('S256')
    expect(params.get('redirect_uri')).toBe(redirectURI())
    // "plain" would make the challenge equal the verifier, which is the one
    // mistake that silently removes PKCE's whole protection.
    const challenge = params.get('code_challenge') ?? ''
    const body = (fetchSpy.mock.calls.at(-1)?.[1] as RequestInit).body as URLSearchParams
    const verifier = body.get('code_verifier') ?? ''
    expect(verifier).not.toBe('')
    expect(challenge).not.toBe(verifier)
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

    await signIn(config)
    expect(new URL(authorizeURL).searchParams.get('scope')).not.toContain('offline_access')
  })

  it('rejects a callback whose state does not match the request', async () => {
    mockFetch()
    fakePopup(() => ({ source: 'stratium-oidc-callback', code: 'attacker-code', state: 'wrong' }))

    await expect(signIn(config)).rejects.toThrow(/state mismatch/)
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

    await expect(signIn(config)).rejects.toThrow(/closed before completing/)
    expect(isAuthenticated()).toBe(false)
  })

  it('reports a blocked popup rather than falling back to anything', async () => {
    mockFetch()
    vi.spyOn(window, 'open').mockReturnValue(null)

    // The message must say what to do, because the alternative — a redirect
    // flow — needs storage, which N12 forbids outright.
    await expect(signIn(config)).rejects.toThrow(/Allow pop-ups/)
    expect(isAuthenticated()).toBe(false)
  })

  it('does not authenticate when the token endpoint returns no access_token', async () => {
    mockFetch({ id_token: 'an id token is not an access token' })
    fakePopup((state) => ({ source: 'stratium-oidc-callback', code: 'c', state }))

    await expect(signIn(config)).rejects.toThrow(/no access_token/)
    expect(isAuthenticated()).toBe(false)
  })
})

describe('the token never reaches browser storage (N12)', () => {
  it('leaves localStorage and sessionStorage untouched across a full sign-in', async () => {
    mockFetch()
    fakePopup((state) => ({ source: 'stratium-oidc-callback', code: 'the-code', state }))

    const setLocal = vi.spyOn(Storage.prototype, 'setItem')
    await signIn(config)

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
