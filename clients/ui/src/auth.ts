// auth.ts is the operator's OIDC login: Authorization Code with PKCE,
// against the customer's own IdP, with the resulting access token held in a
// module-scope variable and nowhere else.
//
// N12 — the token lives in memory only. There is no localStorage, no
// sessionStorage, no cookie, and no IndexedDB anywhere in this file or this
// application. That is not caution for its own sake: this token can approve
// any escalation and revoke every delegation in the tenant, so any XSS in
// this UI that can read a storage API owns the tenant's authorization for as
// long as the token lives. A variable in a module closure is not readable by
// an injected <script> that does not already have arbitrary code execution in
// this same realm — and if it does, it can simply call the API directly, so
// storage buys the attacker persistence across page loads that memory does
// not. Refreshing the page loses the token and re-authenticates. That is the
// designed behaviour, not a defect to smooth over.
//
// WHY A POPUP AND NOT A TOP-LEVEL REDIRECT. PKCE requires the code_verifier
// generated before the authorization request to still be available when the
// code comes back. A top-level redirect destroys the page — and with it every
// in-memory variable — so a redirect flow has no way to keep the verifier
// except in a storage API. There is no third option: it is popup, or storage,
// or no PKCE. This file picks the popup. The opener window never navigates,
// so `pending` below survives, and the popup lands on callback.html (same
// origin, served by the PAP from the same embedded filesystem as this app)
// which posts the code back and closes.
//
// The costs are real and accepted:
//   - The flow must start from a user gesture (the Sign in button), or the
//     browser blocks the popup. This is why nothing here auto-starts on load.
//   - A blocked popup is reported as an error, never retried as a redirect.
//     A "fall back to a redirect" branch would need storage, which is the
//     thing this file exists not to do.
//
// Implicit flow is not an option at any point: it is deprecated, and it
// returns the token in the URL fragment, where it reaches browser history and
// (without the no-referrer meta tag in index.html) Referer headers.

/** Public, non-secret configuration the PAP serves at /ui-config. */
export interface UIConfig {
  issuer: string
  client_id: string
  audience: string
  scope: string
}

/** The subset of the IdP's discovery document this flow needs. */
interface Discovery {
  authorization_endpoint: string
  token_endpoint: string
}

// THE token. Module scope, never exported directly, never written anywhere
// else. `authHeader` below is the only way out of this module for its value.
let accessToken: string | null = null

// The PKCE verifier and CSRF state for an authorization request that is
// currently in flight. Cleared as soon as the code comes back, so a second
// login attempt can never be completed with a first attempt's verifier.
let pending: { verifier: string; state: string } | null = null

export function isAuthenticated(): boolean {
  return accessToken !== null
}

/**
 * The Authorization header for an API call, or null when not signed in.
 * Returning the header rather than the raw token keeps the number of places
 * that touch the credential to one.
 */
export function authHeader(): Record<string, string> | null {
  return accessToken === null ? null : { Authorization: `Bearer ${accessToken}` }
}

/** Forgets the token. Same effect as reloading the page. */
export function signOut(): void {
  accessToken = null
  pending = null
}

/**
 * Called when the API answers 401: the token expired or was revoked at the
 * IdP. Dropping it puts the app back at the Sign in button rather than
 * retrying with a credential now known to be dead.
 */
export function onUnauthorized(): void {
  accessToken = null
}

/** base64url without padding, per RFC 7636. */
function base64url(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function randomString(byteLength: number): string {
  return base64url(crypto.getRandomValues(new Uint8Array(byteLength)))
}

/** S256, the only code_challenge_method this client offers. "plain" would
 *  make the challenge equal to the verifier, which defeats the point. */
async function s256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

async function discover(issuer: string): Promise<Discovery> {
  // The issuer's own discovery document, rather than IdP-specific endpoint
  // paths guessed from the issuer URL: every conformant OIDC provider serves
  // this, and guessing is how a client ends up working against one vendor.
  const res = await fetch(`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`)
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`)
  const doc: unknown = await res.json()
  const d = doc as Partial<Discovery>
  if (!d.authorization_endpoint || !d.token_endpoint) {
    throw new Error('OIDC discovery document is missing authorization_endpoint or token_endpoint')
  }
  return { authorization_endpoint: d.authorization_endpoint, token_endpoint: d.token_endpoint }
}

/** The redirect URI: callback.html on this origin, served by the PAP out of
 *  the same embedded filesystem as this page. Must be registered with the
 *  IdP for the client, exactly as spelled here. */
export function redirectURI(): string {
  return `${window.location.origin}/callback.html`
}

/**
 * Waits for callback.html to post {code, state} back, or for the popup to be
 * closed without completing.
 *
 * Two checks before a message is believed, both mandatory: the origin must be
 * this exact origin (any other window on the page can postMessage to us), and
 * the state must equal the one generated for THIS request (CSRF, and it is
 * also what stops a stale second popup from completing a first login).
 */
function awaitCode(popup: Window, state: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const settle = (fn: () => void) => {
      window.removeEventListener('message', onMessage)
      clearInterval(closedPoll)
      fn()
    }
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return
      const data = event.data as { source?: string; code?: string; state?: string; error?: string }
      if (data?.source !== 'stratium-oidc-callback') return
      if (data.state !== state) {
        settle(() => reject(new Error('OIDC state mismatch: the response does not belong to this request')))
        return
      }
      if (data.error) {
        settle(() => reject(new Error(`the identity provider refused the request: ${data.error}`)))
        return
      }
      if (!data.code) {
        settle(() => reject(new Error('the identity provider returned no authorization code')))
        return
      }
      const code = data.code
      settle(() => resolve(code))
    }
    window.addEventListener('message', onMessage)
    // A user who closes the popup must not leave the app waiting forever on
    // a promise that can no longer settle.
    const closedPoll = setInterval(() => {
      if (popup.closed) settle(() => reject(new Error('sign-in window was closed before completing')))
    }, 500)
  })
}

/**
 * Runs the whole flow and stores the access token in memory. Must be called
 * from a user gesture; see the popup note in this file's header.
 *
 * No refresh token is requested (offline_access is deliberately absent from
 * the default scope): a refresh token is a longer-lived credential than the
 * access token it mints, and this application has nowhere to put one that is
 * safer than where it puts the access token. Losing the session on reload is
 * the accepted cost.
 */
export async function signIn(config: UIConfig): Promise<void> {
  const { authorization_endpoint, token_endpoint } = await discover(config.issuer)

  const verifier = randomString(32)
  const state = randomString(16)
  pending = { verifier, state }

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: config.client_id,
    redirect_uri: redirectURI(),
    scope: config.scope,
    state,
    code_challenge: await s256(verifier),
    code_challenge_method: 'S256',
  })
  // Sent only when configured. IdPs that mint a JWT access token per API
  // (Auth0-shaped) need it, or the token they return carries an `aud` the
  // PAP will refuse; IdPs that key on scope instead ignore it.
  if (config.audience) params.set('audience', config.audience)

  const popup = window.open(
    `${authorization_endpoint}?${params.toString()}`,
    'stratium-oidc',
    'width=520,height=680,noopener=no',
  )
  if (!popup) {
    pending = null
    throw new Error(
      'the sign-in window was blocked. Allow pop-ups for this site and try again — ' +
        'this application will not fall back to a flow that stores your token.',
    )
  }

  try {
    const code = await awaitCode(popup, state)
    const current = pending
    if (!current || current.state !== state) throw new Error('sign-in state was discarded mid-flow')

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectURI(),
      client_id: config.client_id,
      code_verifier: current.verifier,
    })
    // A public client: no client_secret, because a secret shipped to a
    // browser is not a secret. PKCE is what replaces it.
    const res = await fetch(token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!res.ok) throw new Error(`token exchange failed: ${res.status}`)
    const token = (await res.json()) as { access_token?: string }
    if (!token.access_token) throw new Error('token endpoint returned no access_token')
    accessToken = token.access_token
  } finally {
    // Always, on success and on every failure: a verifier that outlives its
    // one exchange is a verifier a later, unrelated code could be redeemed
    // with.
    pending = null
    if (!popup.closed) popup.close()
  }
}
