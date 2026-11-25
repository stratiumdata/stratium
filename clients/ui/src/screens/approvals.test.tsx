import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { APIError, api, type Approval } from '../api'
import { ApprovalsScreen } from './approvals'

// decidable() compares expires_at against Date.now(), so the fixtures'
// timestamps only mean what they say relative to a pinned clock -- otherwise
// this suite rots the moment the real calendar catches up to 2026-08-23.
beforeEach(() => { vi.setSystemTime(new Date('2026-08-23T10:01:00Z')) })
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

function approval(over: Partial<Approval> = {}): Approval {
  return {
    id: '44444444-4444-4444-4444-444444444444',
    agent_id: '55555555-5555-5555-5555-555555555555',
    delegation_id: '66666666-6666-6666-6666-666666666666',
    root_delegation_id: '66666666-6666-6666-6666-666666666666',
    subject: 'agent@example.com',
    root_principal: 'operator@example.com',
    tool_name: 'Bash',
    action: 'rm -rf /tmp/x',
    derived_tier: 4,
    input_digest: 'a'.repeat(64),
    status: 'pending',
    requested_at: '2026-08-23T10:00:00Z',
    expires_at: '2026-08-23T10:02:00Z',
    ...over,
  }
}

describe('ApprovalsScreen', () => {
  it('offers approve and deny on a pending approval', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval()])
    const approve = vi.spyOn(api, 'approveApproval').mockResolvedValue(approval({ status: 'approved' }))

    render(<ApprovalsScreen />)
    ;(await screen.findByRole('button', { name: 'Approve' })).click()

    await waitFor(() => expect(approve).toHaveBeenCalledWith('44444444-4444-4444-4444-444444444444'))
  })

  // An expired approval keeps status 'pending' -- the schema's CHECK has only
  // pending/approved/denied -- but models.Approval.Verify refuses it at
  // CONSUMPTION ("approval %s expired at %s"). So DecideApproval would happily
  // return 200 while the agent's call stays refused: the operator believes
  // they unblocked something and nothing happened.
  it('offers neither on an approval that has expired, and says why', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([
      approval({ status: 'pending', expires_at: '2020-01-01T00:00:00Z' }),
    ])
    render(<ApprovalsScreen />)

    expect(await screen.findByText(/expired/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  it('offers neither on an approval that is already decided', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval({ status: 'approved', approved_by: 'op@example.com' })])
    render(<ApprovalsScreen />)

    // The screen defaults to pending-only (see its own header text); a
    // decided approval only comes into view after asking for every status.
    fireEvent.click(await screen.findByRole('button', { name: 'Show all statuses' }))

    await screen.findByText('approved')
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Deny' })).not.toBeInTheDocument()
  })

  it('marks an approved approval whose one call has been made as used', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([
      approval({ status: 'approved', approved_by: 'op@example.com', used_at: '2026-08-23T10:00:30Z' }),
    ])
    render(<ApprovalsScreen />)
    fireEvent.click(await screen.findByRole('button', { name: 'Show all statuses' }))

    await screen.findByText('used')
    expect(screen.queryByText('approved')).not.toBeInTheDocument()
  })

  // N7: the approver is fixed to the chain's ROOT PRINCIPAL, and a role is
  // necessary but never sufficient. respond.go's message carries only the
  // approval id -- deliberately not the operator identity or the root
  // principal -- so this screen shows what it was given and invents nothing.
  it('shows the N7 refusal verbatim without reconstructing who was expected', async () => {
    vi.spyOn(api, 'approvals').mockResolvedValue([approval()])
    vi.spyOn(api, 'approveApproval').mockRejectedValue(
      new APIError(403, 'approver is not the root principal of approval 44444444-4444-4444-4444-444444444444'),
    )

    render(<ApprovalsScreen />)
    ;(await screen.findByRole('button', { name: 'Approve' })).click()

    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('approver is not the root principal')
    // The server withholds both identities on purpose; the screen must not
    // fill the gap from the row it happens to be rendering.
    expect(alert).not.toHaveTextContent('operator@example.com')
  })
})
