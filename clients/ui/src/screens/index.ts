// screens/ holds one file per admin screen. This was a single screens.tsx
// while every screen was a list and a table; each now carries an editor,
// its own field rules, and its own tests, and the shapes stopped being
// near-identical. index.ts exists so App.tsx has one import site.

export { PoliciesScreen } from './policies'
export { AgentsScreen } from './agents'
export { TierOverridesScreen } from './tier-overrides'
export { ToolCatalogScreen } from './tool-catalog'
export { ApprovalsScreen } from './approvals'
export { DelegationsScreen } from './delegations'
