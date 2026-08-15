// screens.tsx holds all six admin screens. One file rather than six: each is
// the same shape — fetch a list, render a table — and the shared `useList`
// hook plus the shared table primitives are most of the code. Splitting them
// would trade six imports for six near-identical twelve-line files.
//
// N14 — none of these screens decides anything. They render what the API
// returned, and the one action offered (revoke) is offered unconditionally,
// because whether this operator may perform it is the server's answer to
// give, not this file's guess. A viewer sees the button and gets a 403 with
// the server's own words.

import { useCallback, useEffect, useState } from 'react'

import {
  api,
  describeError,
  type Agent,
  type Approval,
  type Delegation,
  type Policy,
  type TierOverride,
  type ToolCatalogEntry,
} from './api'
import { actionTier, policyEffect, shortDigest, timestamp, toolList, trustTier } from './display'
import { Badge, Button, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from './ui'

interface ListState<T> {
  rows: T[] | null
  error: string | null
}

/** Loads a list on mount, and again whenever reload() is called. `rows ===
 *  null` means "not loaded yet" — distinct from `[]`, which means the tenant
 *  genuinely has none. The API guarantees that distinction: every list
 *  endpoint returns [] and never null.
 *
 *  reload bumps a counter rather than re-running the effect body directly, so
 *  no setState happens synchronously inside the effect — the cascading-render
 *  pattern react-hooks/set-state-in-effect exists to catch. A reload leaves
 *  the previous rows on screen until the new ones arrive, which is what an
 *  operator who just clicked Revoke wants to see. */
function useList<T>(load: () => Promise<T[]>): ListState<T> & { reload: () => void } {
  const [state, setState] = useState<ListState<T>>({ rows: null, error: null })
  const [generation, setGeneration] = useState(0)

  useEffect(() => {
    let live = true
    load().then(
      (rows) => {
        if (live) setState({ rows, error: null })
      },
      (err: unknown) => {
        if (live) setState({ rows: [], error: describeError(err) })
      },
    )
    return () => {
      live = false
    }
  }, [load, generation])

  const reload = useCallback(() => setGeneration((g) => g + 1), [])
  return { ...state, reload }
}

function Loading() {
  return <p className="text-sm text-muted-foreground">Loading…</p>
}

// --- Policies -----------------------------------------------------------

export function PoliciesScreen() {
  const { rows, error } = useList<Policy>(api.policies)
  return (
    <section>
      <ScreenHeader title="Policies">
        A policy's effect is shown only for the two languages where the stored value is
        checked against the policy text at write time. A Rego or XACML policy can define
        rules of both effects, resolved only when a request is evaluated, so no effect is
        claimed for one.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Language', 'Effect', 'Version', 'Enabled', 'Updated']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No policies.</EmptyRow> : null}
            {rows.map((p) => {
              const effect = policyEffect(p.language, p.effect)
              return (
                <TRow key={p.id}>
                  <TCell>
                    <div className="font-medium">{p.name}</div>
                    {p.description ? (
                      <div className="text-xs text-muted-foreground">{p.description}</div>
                    ) : null}
                  </TCell>
                  <TCell>{p.language}</TCell>
                  <TCell>
                    {effect.kind === 'declared' ? (
                      <Badge tone={effect.effect === 'allow' ? 'good' : 'warn'}>{effect.effect}</Badge>
                    ) : (
                      <span title={effect.reason} className="text-muted-foreground">
                        determined at evaluation
                      </span>
                    )}
                  </TCell>
                  <TCell>{p.version}</TCell>
                  <TCell>{p.enabled ? 'yes' : 'no'}</TCell>
                  <TCell>{timestamp(p.updated_at)}</TCell>
                </TRow>
              )
            })}
          </tbody>
        </Table>
      )}
    </section>
  )
}

// --- Agents -------------------------------------------------------------

export function AgentsScreen() {
  const { rows, error } = useList<Agent>(api.agents)
  return (
    <section>
      <ScreenHeader title="Agents">
        An empty allowed-tools list is unrestricted, not empty — the delegation is the real
        constraint.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Name', 'Provider', 'Model', 'Trust tier', 'State', 'Allowed tools']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={6}>No agents.</EmptyRow> : null}
            {rows.map((a) => (
              <TRow key={a.id}>
                <TCell className="font-medium">{a.name}</TCell>
                <TCell>{a.provider}</TCell>
                <TCell>{a.model_id}</TCell>
                <TCell>{trustTier(a.trust_tier)}</TCell>
                <TCell>
                  {a.suspended ? (
                    <Badge tone="warn">suspended</Badge>
                  ) : a.enabled ? (
                    <Badge tone="good">enabled</Badge>
                  ) : (
                    <Badge>disabled</Badge>
                  )}
                </TCell>
                <TCell>{toolList(a.allowed_tools)}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}

// --- Tier overrides -----------------------------------------------------

export function TierOverridesScreen() {
  const { rows, error } = useList<TierOverride>(api.tierOverrides)
  return (
    <section>
      <ScreenHeader title="Tier overrides">
        An override may only raise a tool's built-in tier, never lower it. The built-in
        column is derived by the server and is what the override was validated against.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool or verb', 'Override tier', 'Built-in tier', 'Created', 'By']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={5}>No tier overrides.</EmptyRow> : null}
            {rows.map((o) => (
              <TRow key={o.id}>
                <TCell className="font-medium">{o.tool_or_verb}</TCell>
                <TCell>{actionTier(o.action_tier)}</TCell>
                <TCell className="text-muted-foreground">{actionTier(o.builtin_tier)}</TCell>
                <TCell>{timestamp(o.created_at)}</TCell>
                <TCell>{o.created_by}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}

// --- Tool catalog -------------------------------------------------------

export function ToolCatalogScreen() {
  const { rows, error } = useList<ToolCatalogEntry>(api.toolCatalog)
  return (
    <section>
      <ScreenHeader title="Tool catalog">
        A tool with no action tier is classified per invocation from its command field —
        the shell-shaped case, where one tool name covers both a harmless read and a
        destructive command.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead columns={['Tool', 'Verb', 'Action tier', 'Resource field', 'Command field']} />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={5}>No catalog entries.</EmptyRow> : null}
            {rows.map((e) => (
              <TRow key={e.id}>
                <TCell className="font-medium">{e.tool_name}</TCell>
                <TCell>{e.verb}</TCell>
                <TCell>
                  {e.action_tier === null ? (
                    <span className="text-muted-foreground">per invocation</span>
                  ) : (
                    actionTier(e.action_tier)
                  )}
                </TCell>
                <TCell>{e.resource_field ?? '—'}</TCell>
                <TCell>{e.command_field ?? '—'}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}

// --- Approvals ----------------------------------------------------------

export function ApprovalsScreen() {
  const { rows, error } = useList<Approval>(api.approvals)
  const [showAll, setShowAll] = useState(false)
  const visible = rows === null ? null : showAll ? rows : rows.filter((a) => a.status === 'pending')
  return (
    <section>
      <ScreenHeader title="Pending approvals">
        Deciding an escalation requires more than a role: the operator's own identity must
        equal the approval's root principal, and the admin plane enforces that itself. This
        screen shows pending requests by default; the endpoint returns every status, so the
        decided ones are one toggle away.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      <div className="mb-3">
        <Button variant="outline" size="sm" onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Show pending only' : 'Show all statuses'}
        </Button>
      </div>
      {visible === null ? (
        <Loading />
      ) : (
        <Table>
          <THead
            columns={['Status', 'Tool', 'Action', 'Tier', 'Root principal', 'Input digest', 'Requested', 'Expires']}
          />
          <tbody>
            {visible.length === 0 ? (
              <EmptyRow colSpan={8}>{showAll ? 'No approvals.' : 'No pending approvals.'}</EmptyRow>
            ) : null}
            {visible.map((a) => (
              <TRow key={a.id}>
                <TCell>
                  <Badge tone={a.status === 'approved' ? 'good' : a.status === 'denied' ? 'warn' : 'neutral'}>
                    {a.status}
                  </Badge>
                </TCell>
                <TCell className="font-medium">{a.tool_name}</TCell>
                <TCell>{a.action}</TCell>
                <TCell>{actionTier(a.derived_tier)}</TCell>
                <TCell>{a.root_principal}</TCell>
                <TCell title={a.input_digest} className="font-mono text-xs">
                  {shortDigest(a.input_digest)}
                </TCell>
                <TCell>{timestamp(a.requested_at)}</TCell>
                <TCell>{timestamp(a.expires_at)}</TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}

// --- Delegations --------------------------------------------------------

export function DelegationsScreen() {
  const { rows, error, reload } = useList<Delegation>(api.delegations)
  const [actionError, setActionError] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)

  const revoke = async (id: string) => {
    setActionError(null)
    setRevoking(id)
    try {
      await api.revokeDelegation(id)
      reload()
    } catch (err) {
      // The server's own refusal, shown as-is. This is the whole of N14 on
      // this screen: the button was never hidden, the request was really
      // made, and the admin plane said no.
      setActionError(describeError(err))
    } finally {
      setRevoking(null)
    }
  }

  return (
    <section>
      <ScreenHeader title="Delegations">
        Revoking a delegation denies every delegation beneath it on its next decision — the
        chain is re-checked each time, so there is nothing to cascade by hand. Revoked
        delegations stay listed so a revocation can be confirmed.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
      {rows === null ? (
        <Loading />
      ) : (
        <Table>
          <THead
            columns={['Principal', 'Agent', 'Max tier', 'Depth', 'Tools', 'Expires', 'State', '']}
          />
          <tbody>
            {rows.length === 0 ? <EmptyRow colSpan={8}>No delegations.</EmptyRow> : null}
            {rows.map((d) => (
              <TRow key={d.id}>
                <TCell className="font-medium">{d.user_id}</TCell>
                <TCell className="font-mono text-xs">{d.agent_id}</TCell>
                <TCell>{actionTier(d.max_action_tier)}</TCell>
                <TCell>{d.depth}</TCell>
                <TCell>{toolList(d.approved_tools)}</TCell>
                <TCell>{timestamp(d.expires_at)}</TCell>
                <TCell>
                  {d.revoked ? (
                    <Badge tone="warn" title={timestamp(d.revoked_at)}>
                      revoked
                    </Badge>
                  ) : (
                    <Badge tone="good">active</Badge>
                  )}
                </TCell>
                <TCell>
                  {d.revoked ? null : (
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={revoking === d.id}
                      onClick={() => void revoke(d.id)}
                    >
                      {revoking === d.id ? 'Revoking…' : 'Revoke'}
                    </Button>
                  )}
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
