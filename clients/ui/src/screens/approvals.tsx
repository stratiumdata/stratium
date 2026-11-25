import { useCallback, useState } from 'react'

import { api, describeError, type Approval } from '../api'
import { actionTier, shortDigest, timestamp } from '../display'
import { Badge, Button, EmptyRow, ErrorBanner, ScreenHeader, TCell, THead, TRow, Table } from '../ui'
import { Loading, useList } from '../crud'

// --- Approvals ----------------------------------------------------------

// An approval is decidable only while it is pending AND unexpired. Expiry is
// not a status: the schema's CHECK holds only pending/approved/denied, so an
// expired request still reads 'pending'. models.Approval.Verify refuses it at
// consumption ("approval %s expired at %s"), which means DecideApproval would
// return 200 on one while the agent's call stays refused -- the operator
// believing they unblocked something that never moved.
function decidable(a: Approval): boolean {
  return a.status === 'pending' && new Date(a.expires_at).getTime() > Date.now()
}

export function ApprovalsScreen() {
  const { rows, error, reload } = useList<Approval>(api.approvals)
  const [showAll, setShowAll] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  // { id, how } of the decision in flight, mirroring delegations.tsx's
  // `revoking`: disables the row's buttons and relabels the one clicked for
  // the round trip, so a double-click cannot fire the decision twice.
  const [deciding, setDeciding] = useState<{ id: string; how: 'approve' | 'deny' } | null>(null)
  const visible = rows === null ? null : showAll ? rows : rows.filter((a) => a.status === 'pending')

  const decide = useCallback((id: string, how: 'approve' | 'deny') => {
    setDeciding({ id, how })
    const call = how === 'approve' ? api.approveApproval : api.denyApproval
    call(id).then(
      () => { setActionError(null); setDeciding(null); reload() },
      (err: unknown) => { setActionError(describeError(err)); setDeciding(null) },
    )
  }, [reload])

  return (
    <section>
      <ScreenHeader title="Pending approvals">
        Deciding an escalation requires more than a role: the operator's own identity must
        equal the approval's root principal, and the admin plane enforces that itself. This
        screen shows pending requests by default; the endpoint returns every status, so the
        decided ones are one toggle away.
      </ScreenHeader>
      {error ? <ErrorBanner>{error}</ErrorBanner> : null}
      {actionError ? <ErrorBanner>{actionError}</ErrorBanner> : null}
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
            columns={[
              'Status', 'Tool', 'Action', 'Tier', 'Root principal', 'Input digest', 'Requested', 'Expires', '',
            ]}
          />
          <tbody>
            {visible.length === 0 ? (
              <EmptyRow colSpan={9}>{showAll ? 'No approvals.' : 'No pending approvals.'}</EmptyRow>
            ) : null}
            {visible.map((a) => (
              <TRow key={a.id}>
                <TCell>
                  {a.status === 'pending' && !decidable(a) ? (
                    <Badge tone="warn">expired</Badge>
                  ) : a.used_at ? (
                    // An approval allows one call. Once that call is made it can
                    // do nothing more, which "approved" alone would not say.
                    <Badge tone="neutral" title={`used ${timestamp(a.used_at)}`}>used</Badge>
                  ) : (
                    <Badge tone={a.status === 'approved' ? 'good' : a.status === 'denied' ? 'warn' : 'neutral'}>
                      {a.status}
                    </Badge>
                  )}
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
                <TCell className="text-right">
                  {decidable(a) ? (
                    <>
                      <Button
                        variant="ghost" size="sm"
                        disabled={deciding?.id === a.id}
                        onClick={() => decide(a.id, 'approve')}
                      >
                        {deciding?.id === a.id && deciding.how === 'approve' ? 'Approving…' : 'Approve'}
                      </Button>
                      <Button
                        variant="ghost" size="sm"
                        disabled={deciding?.id === a.id}
                        onClick={() => decide(a.id, 'deny')}
                      >
                        {deciding?.id === a.id && deciding.how === 'deny' ? 'Denying…' : 'Deny'}
                      </Button>
                    </>
                  ) : null}
                </TCell>
              </TRow>
            ))}
          </tbody>
        </Table>
      )}
    </section>
  )
}
