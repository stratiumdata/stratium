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

/** models.ResourceLabelRule.
 *
 *  `prefix` may legitimately be the EMPTY STRING: "" is a prefix of every
 *  resource id, which makes such a row the tenant's catch-all (R7) and the
 *  answer to "a cap was enabled and now everything denies". Nothing in this
 *  client may treat it as a missing required field — migrations/000019
 *  deliberately omits the length(prefix) > 0 CHECK. */
export interface ResourceLabelRule {
  id: string
  tenant_id: string
  prefix: string
  hierarchy: string
  level: string
}

/** The classification-caps sub-resource: hierarchy -> level.
 *
 *  An EMPTY map is the off switch — CheckCap returns allow for len(caps) == 0.
 *  Any entry at all makes an unlabelled resource DENY (R2). The two states are
 *  not "unset" and "set to nothing"; they are "off" and "on". */
export type ClassificationCaps = Record<string, string>

/** models.AgentCapsView, what GET/PUT .../classification-caps return. */
export interface AgentCapsView {
  agent_id: string
  classification_caps: ClassificationCaps
  /** Per hierarchy, the level the tenant's catch-all label rule assigns, or
   *  null where no catch-all exists for it. Read-only context: it is what an
   *  unlabelled resource resolves to, which is what makes a cap bite. */
  catch_all: Record<string, string | null>
}

/** One leg of POST /v1/policies/test's answer. */
export interface PolicyTestVerdict {
  effect: string
  reason: string
  source?: string
  policy_id?: string
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

/** The PAP client's single request path. `body` is omitted, not null, on a
 *  read: sending `Content-Type: application/json` with no body invites a 400
 *  from a strict decoder, and several routes here are POSTs that genuinely
 *  carry nothing (approve, deny, revoke). */
async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const header = authHeader()
  if (!header) throw new APIError(401, 'not signed in')

  const headers: Record<string, string> = { ...header, Accept: 'application/json' }
  const init: RequestInit = { method, headers }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(body)
  }

  const res = await fetch(path, init)
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

  policyLanguages: () =>
    request<{ languages: string[] }>('GET', '/v1/policy-languages').then((r) => r.languages),

  policy: (id: string) => request<Policy>('GET', `/v1/policies/${encodeURIComponent(id)}`),
  createPolicy: (p: Policy) => request<Policy>('POST', '/v1/policies', p),
  updatePolicy: (id: string, p: Policy) =>
    request<Policy>('PUT', `/v1/policies/${encodeURIComponent(id)}`, p),
  deletePolicy: (id: string) => request<void>('DELETE', `/v1/policies/${encodeURIComponent(id)}`),

  // validate answers 200 {valid:true} or a 400 carrying the engine's own
  // message. The 400 is the useful case, and APIError already carries its
  // body, so this returns void and lets the rejection speak.
  validatePolicy: (language: string, policyContent: string) =>
    request<void>('POST', '/v1/policies/validate', { language, policy_content: policyContent }),
  testPolicy: (req: unknown) => request<PolicyTestVerdict>('POST', '/v1/policies/test', req),

  agent: (id: string) => request<Agent>('GET', `/v1/agents/${encodeURIComponent(id)}`),
  createAgent: (a: Agent) => request<Agent>('POST', '/v1/agents', a),
  updateAgent: (id: string, a: Agent) =>
    request<Agent>('PUT', `/v1/agents/${encodeURIComponent(id)}`, a),
  deleteAgent: (id: string) => request<void>('DELETE', `/v1/agents/${encodeURIComponent(id)}`),

  // The caps sub-resource is a separate route at a separate role floor
  // (RoleAdmin, where the agent body is RoleEditor). store.UpdateAgent ignores
  // classification_caps on input, so this is the ONLY way to write one.
  agentCaps: (id: string) =>
    request<AgentCapsView>('GET', `/v1/agents/${encodeURIComponent(id)}/classification-caps`),
  putAgentCaps: (id: string, caps: ClassificationCaps) =>
    request<AgentCapsView>('PUT', `/v1/agents/${encodeURIComponent(id)}/classification-caps`,
      { classification_caps: caps }),
  deleteAgentCaps: (id: string) =>
    request<void>('DELETE', `/v1/agents/${encodeURIComponent(id)}/classification-caps`),

  tierOverride: (id: string) =>
    request<TierOverride>('GET', `/v1/tier-overrides/${encodeURIComponent(id)}`),
  createTierOverride: (t: TierOverride) => request<TierOverride>('POST', '/v1/tier-overrides', t),
  updateTierOverride: (id: string, t: TierOverride) =>
    request<TierOverride>('PUT', `/v1/tier-overrides/${encodeURIComponent(id)}`, t),
  deleteTierOverride: (id: string) =>
    request<void>('DELETE', `/v1/tier-overrides/${encodeURIComponent(id)}`),

  toolCatalogEntry: (id: string) =>
    request<ToolCatalogEntry>('GET', `/v1/tool-catalog/${encodeURIComponent(id)}`),
  createToolCatalogEntry: (e: ToolCatalogEntry) =>
    request<ToolCatalogEntry>('POST', '/v1/tool-catalog', e),
  updateToolCatalogEntry: (id: string, e: ToolCatalogEntry) =>
    request<ToolCatalogEntry>('PUT', `/v1/tool-catalog/${encodeURIComponent(id)}`, e),
  // No delete: the PAP exposes no DELETE /v1/tool-catalog/{id}.

  resourceLabelRules: () => request<ResourceLabelRule[]>('GET', '/v1/resource-label-rules'),
  resourceLabelRule: (id: string) =>
    request<ResourceLabelRule>('GET', `/v1/resource-label-rules/${encodeURIComponent(id)}`),
  createResourceLabelRule: (r: ResourceLabelRule) =>
    request<ResourceLabelRule>('POST', '/v1/resource-label-rules', r),
  updateResourceLabelRule: (id: string, r: ResourceLabelRule) =>
    request<ResourceLabelRule>('PUT', `/v1/resource-label-rules/${encodeURIComponent(id)}`, r),
  deleteResourceLabelRule: (id: string) =>
    request<void>('DELETE', `/v1/resource-label-rules/${encodeURIComponent(id)}`),

  approveApproval: (id: string) =>
    request<Approval>('POST', `/v1/approvals/${encodeURIComponent(id)}/approve`),
  denyApproval: (id: string) =>
    request<Approval>('POST', `/v1/approvals/${encodeURIComponent(id)}/deny`),
}
