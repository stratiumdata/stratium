import { useState } from 'react'

import { api, describeError, type Delegation } from '../api'
import { actionTier, timestamp, toolList } from '../display'
import { Badge, Button, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

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
