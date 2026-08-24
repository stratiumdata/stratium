import { useState } from 'react'

import { api, type Approval } from '../api'
import { actionTier, shortDigest, timestamp } from '../display'
import { Badge, Button, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

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
