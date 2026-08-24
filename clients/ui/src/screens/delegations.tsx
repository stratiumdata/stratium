import { useMemo, useState } from 'react'

import { api, describeError, type Agent, type Delegation } from '../api'
import { actionTier, timestamp, toolList } from '../display'
import {
  Badge, Button, DetailRow, EmptyRow, ErrorBanner, Modal, ScreenHeader,
  TCell, THead, TRow, Table,
} from '../ui'
import { Loading, useList } from '../crud'

// --- Delegations --------------------------------------------------------

/** Agent id -> name, for the Agent column and the chain in the detail modal.
 *
 *  A missing id renders as the id. That happens for an agent deleted since the
 *  delegation was issued, and for every row if the agents request failed —
 *  neither is a reason to show an empty cell or invent "unknown", and the raw
 *  id is still the thing an operator can search the API for. */
function agentName(names: Map<string, string>, id: string): string {
  return names.get(id) ?? id
}

/** The chain as names, root first. ChainAgentIDs is built root-first with the
 *  delegation's own agent appended last (pdpgrpc/delegation.go), so rendering
 *  it in reverse would invert who delegated to whom. */
function chainPath(names: Map<string, string>, chain: string[] | undefined): string {
  return (chain ?? []).map((id) => agentName(names, id)).join('  →  ')
}

/** A delegation has no name, so one is composed: its agent, plus its purpose
 *  when it has one (purpose is free text and some rows leave it empty).
 *
 *  Returns null when the id names a delegation not in the list. Every parent
 *  and root resolves today -- GET /v1/delegations neither filters nor
 *  paginates -- but inventing a label for a delegation we cannot see would be
 *  worse than showing the caller only the id it already has. */
function delegationLabel(
  byId: Map<string, Delegation>,
  names: Map<string, string>,
  id: string,
): string | null {
  const d = byId.get(id)
  if (!d) return null
  const agent = agentName(names, d.agent_id)
  return d.purpose ? `${agent} · “${d.purpose}”` : agent
}

/** A delegation reference: its composed label, with the id kept beneath.
 *
 *  The id stays visible rather than moving to a tooltip because this modal is
 *  the only place it is shown, and it is what an operator pastes into a revoke
 *  call or greps an audit log for. A hover-only id cannot be read from a
 *  screenshot or on a touch device. */
function DelegationRef({ id, label }: { id: string; label: string | null }) {
  return (
    <>
      {label ? <div>{label}</div> : null}
      <div className="font-mono text-xs text-muted-foreground">{id}</div>
    </>
  )
}

function DelegationDetail({ d, byId, names, onClose }: {
  d: Delegation | null
  byId: Map<string, Delegation>
  names: Map<string, string>
  onClose: () => void
}) {
  return (
    <Modal open={d !== null} title="Delegation" onClose={onClose}>
      {d === null ? null : (
        <>
          <DetailRow label="Chain">
            <span className="font-mono text-xs">{chainPath(names, d.chain_agent_ids) || '—'}</span>
            <span className="ml-2 text-muted-foreground">(depth {d.depth})</span>
          </DetailRow>
          <DetailRow label="Delegation id">
            <DelegationRef id={d.id} label={delegationLabel(byId, names, d.id)} />
          </DetailRow>
          <DetailRow label="Parent">
            {d.parent_delegation_id ? (
              <DelegationRef
                id={d.parent_delegation_id}
                label={delegationLabel(byId, names, d.parent_delegation_id)}
              />
            ) : (
              <span className="text-muted-foreground">none — this is a root delegation</span>
            )}
          </DetailRow>
          <DetailRow label="Root">
            <DelegationRef
              id={d.root_delegation_id}
              label={delegationLabel(byId, names, d.root_delegation_id)}
            />
          </DetailRow>

          <DetailRow label="Principal">{d.user_id}</DetailRow>
          <DetailRow label="Agent">{agentName(names, d.agent_id)}</DetailRow>
          <DetailRow label="Purpose">{d.purpose || '—'}</DetailRow>

          <DetailRow label="Approved tools">{toolList(d.approved_tools)}</DetailRow>
          <DetailRow label="Max action tier">{actionTier(d.max_action_tier)}</DetailRow>
          <DetailRow label="Escalates at">
            {d.escalate_at === undefined || d.escalate_at === null
              ? <span className="text-muted-foreground">never — nothing escalates</span>
              : actionTier(d.escalate_at)}
          </DetailRow>

          <DetailRow label="Classification caps">
            {Object.keys(d.classification_caps ?? {}).length === 0 ? (
              <span className="text-muted-foreground">none — no classification ceiling</span>
            ) : (
              <span className="font-mono text-xs">
                {Object.entries(d.classification_caps).map(([h, l]) => `${h}: ${l}`).join(', ')}
              </span>
            )}
          </DetailRow>
          <DetailRow label="Resource constraints">
            {Object.keys(d.resource_constraints ?? {}).length === 0 ? (
              <span className="text-muted-foreground">none</span>
            ) : (
              <span className="font-mono text-xs">
                {Object.entries(d.resource_constraints).map(([k, v]) => `${k}: ${v}`).join(', ')}
              </span>
            )}
          </DetailRow>

          <DetailRow label="Created">{timestamp(d.created_at)}</DetailRow>
          <DetailRow label="Expires">{timestamp(d.expires_at)}</DetailRow>
          <DetailRow label="State">
            {d.revoked
              ? <Badge tone="warn">revoked {timestamp(d.revoked_at)}</Badge>
              : <Badge tone="good">active</Badge>}
          </DetailRow>

          <p className="mt-3 text-xs text-muted-foreground">
            Read-only. Caps and constraints were copied onto this delegation when it was
            issued — changing the agent&apos;s caps now does not change these.
          </p>
        </>
      )}
    </Modal>
  )
}

export function DelegationsScreen() {
  const { rows, error, reload } = useList<Delegation>(api.delegations)
  // Loaded for the Agent column and the chain. A failure here must not take
  // the screen down with it: agentName falls back to the id.
  const { rows: agents } = useList<Agent>(api.agents)
  const [actionError, setActionError] = useState<string | null>(null)
  const [revoking, setRevoking] = useState<string | null>(null)
  const [detail, setDetail] = useState<Delegation | null>(null)

  const names = useMemo(
    () => new Map((agents ?? []).map((a) => [a.id, a.name])),
    [agents],
  )
  // Parent and root are references to other delegations in this same list --
  // GET /v1/delegations neither filters nor paginates, so they resolve.
  const byId = useMemo(
    () => new Map((rows ?? []).map((d) => [d.id, d])),
    [rows],
  )

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
        delegations stay listed so a revocation can be confirmed. Select a row for its
        chain and the rest of what it grants.
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
              <TRow
                key={d.id}
                // Focusable and Enter/Space activated: a row that only opens
                // on click puts the whole detail view out of reach without a
                // mouse, and this is the only place the chain is shown.
                tabIndex={0}
                role="button"
                aria-label={`Delegation for ${agentName(names, d.agent_id)}`}
                className="cursor-pointer hover:bg-accent"
                onClick={() => setDetail(d)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault()
                    setDetail(d)
                  }
                }}
              >
                <TCell className="font-medium">{d.user_id}</TCell>
                <TCell>{agentName(names, d.agent_id)}</TCell>
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
                      // The row opens the detail modal; revoking is a
                      // different intent and must not also open it.
                      onClick={(e) => {
                        e.stopPropagation()
                        void revoke(d.id)
                      }}
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

      <DelegationDetail d={detail} byId={byId} names={names} onClose={() => setDetail(null)} />
    </section>
  )
}
