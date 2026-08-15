// api.ts is this application's only HTTP client for the PAP. The Go types it
// mirrors live in services/pkg/models; every field name here is that type's
// own json tag.
//
// N14 — nothing in this file, or anywhere in this application, decides what
// an operator may do. Every request goes to the server with the operator's
// own token and the server refuses it or does not; a 403 here is reported,
// never pre-empted. See services/cmd/stratium-pap/{approvals,delegations}
// _test.go's TestViewer_CanListButCannotDecide / _CannotRevoke for the proof
// that those refusals hold with this client bypassed entirely.

import { authHeader, onUnauthorized, type UIConfig } from './auth'

/** models.Policy */
export interface Policy {
  id: string
  name: string
  description: string
  language: string
  policy_content: string
  effect: string
  version: number
  enabled: boolean
  created_at: string
  updated_at: string
}

/** models.Agent */
export interface Agent {
  id: string
  name: string
  provider: string
  model_id: string
  trust_tier: number
  enabled: boolean
  suspended: boolean
  allowed_tools: string[]
  created_at: string
  updated_at: string
}

/** models.TierOverride */
export interface TierOverride {
  id: string
  tool_or_verb: string
  action_tier: number
  builtin_tier: number
  created_at: string
  created_by: string
}

/** models.ToolCatalogEntry */
export interface ToolCatalogEntry {
  id: string
  tool_name: string
  action_tier: number | null
  verb: string
  resource_field?: string
  command_field?: string
}

/** models.Approval. input_digest is hex; see that type's MarshalJSON. */
export interface Approval {
  id: string
  agent_id: string
  delegation_id: string
  root_delegation_id: string
  subject: string
  root_principal: string
  tool_name: string
  action: string
  derived_tier: number
  input_digest: string
  status: string
  requested_at: string
  expires_at: string
  approved_by?: string
  approved_at?: string
}

/** models.Delegation */
export interface Delegation {
  id: string
  user_id: string
  agent_id: string
  approved_tools: string[]
  max_action_tier: number
  escalate_at?: number
  purpose: string
  expires_at: string
  created_at: string
  revoked: boolean
  revoked_at?: string
  root_delegation_id: string
  depth: number
}

/** An HTTP error carrying the status so a screen can say WHY it failed —
 *  403 in particular, which is the server enforcing a role this UI has no
 *  business second-guessing. */
export class APIError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'APIError'
    this.status = status
  }
}

/** An error's own words, with the HTTP status when there is one. Lives here,
 *  beside APIError, so a screen never has to know how to unwrap one — and so
 *  screens.tsx exports components and nothing else. */
export function describeError(err: unknown): string {
  if (err instanceof APIError) return `${err.status}: ${err.message}`
  return err instanceof Error ? err.message : String(err)
}

async function request<T>(method: string, path: string): Promise<T> {
  const header = authHeader()
  if (!header) throw new APIError(401, 'not signed in')

  const res = await fetch(path, { method, headers: { ...header, Accept: 'application/json' } })
  if (res.status === 401) {
    // The token is dead. Drop it rather than retry with it.
    onUnauthorized()
    throw new APIError(401, 'your session has expired — sign in again')
  }
  if (!res.ok) {
    const body = (await res.text()).trim()
    throw new APIError(res.status, body || `${method} ${path} failed with ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** The PAP's public, unauthenticated configuration endpoint. Fetched before
 *  sign-in — it must be, since it names the IdP to sign in against — and it
 *  carries no secret: an OIDC public client's id is public by construction. */
export async function fetchUIConfig(): Promise<UIConfig> {
  const res = await fetch('/ui-config', { headers: { Accept: 'application/json' } })
  if (!res.ok) throw new Error(`the admin plane returned ${res.status} for its own configuration`)
  return (await res.json()) as UIConfig
}

export const api = {
  policies: () => request<Policy[]>('GET', '/v1/policies'),
  agents: () => request<Agent[]>('GET', '/v1/agents'),
  tierOverrides: () => request<TierOverride[]>('GET', '/v1/tier-overrides'),
  toolCatalog: () => request<ToolCatalogEntry[]>('GET', '/v1/tool-catalog'),
  approvals: () => request<Approval[]>('GET', '/v1/approvals'),
  delegations: () => request<Delegation[]>('GET', '/v1/delegations'),

  // The one write this application performs. Offered to every signed-in
  // operator: the server refuses it below RoleAdmin, and hiding the button
  // would be this UI claiming an authorization decision it does not make
  // (N14). A refusal comes back as APIError(403) and is shown as such.
  revokeDelegation: (id: string) =>
    request<Delegation>('POST', `/v1/delegations/${encodeURIComponent(id)}/revoke`),
}
