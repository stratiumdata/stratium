// screens/ holds one file per admin screen. This was a single screens.tsx
// while every screen was a list and a table; each now carries an editor,
// its own field rules, and its own tests, and the shapes stopped being
// near-identical. index.ts exists so App.tsx has one import site.
//
// N14 binds every screen in this directory. They render what the API
// returned, and ANY action one of them offers is offered unconditionally —
// never hidden, greyed, or pre-flighted against a role — because whether this
// operator may perform it is the server's answer to give, not a screen's
// guess. A viewer sees the button and gets a 403 carrying the server's own
// words, which is why ui.tsx's ErrorBanner shows those words verbatim.
//
// This note was the header of the single screens.tsx these files came from,
// where it could say "the one action offered (revoke)". Six of these screens
// are gaining actions, so it lives here instead: generalised, and in the one
// file every screen author passes through.

export { PoliciesScreen } from './policies'
export { AgentsScreen } from './agents'
export { TierOverridesScreen } from './tier-overrides'
export { ToolCatalogScreen } from './tool-catalog'
export { ApprovalsScreen } from './approvals'
export { DelegationsScreen } from './delegations'
