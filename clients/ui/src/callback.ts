// The OIDC redirect target's entire logic. Runs in the popup auth.ts opened,
// posts the authorization code back to the opener, and closes.
//
// targetOrigin is this exact origin, never '*': a wildcard would deliver the
// authorization code to whatever site happened to have opened this window.
// The opener performs the mirror-image check on event.origin.
//
// The code is never exchanged here and nothing is written to any storage API
// — this file has no code_verifier to exchange it with, by design (N12).

const params = new URLSearchParams(window.location.search)
const opener = window.opener as Window | null
opener?.postMessage(
  {
    source: 'stratium-oidc-callback',
    code: params.get('code') ?? undefined,
    state: params.get('state') ?? undefined,
    error: params.get('error') ?? undefined,
  },
  window.location.origin,
)
window.close()
