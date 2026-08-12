package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Approval is one row of the approvals table (migrations/000012_approvals):
// the record of a single escalated decision, from the moment
// store.CreateApproval creates it pending through whatever disposition the
// control plane later writes directly against the row (E7 — see that
// migration's own comment on the grants that enforce it).
//
// Defined here, in pkg/models, rather than in internal/store where Task 2
// first put it (that package's own approval.go doc comment flagged this
// choice for Task 3 to make explicitly): internal/pdpgrpc now needs to both
// construct a value of this type (on a fresh escalation, before any row
// exists) and read nearly every field of one back (to verify a retry), the
// same two-sided, full-fidelity use every other store-persisted domain type
// in this package already gets — internal/store.LoadChain already returns
// *models.Delegation rather than a store-local type for exactly this
// reason. The alternative internal/authz.AgentInfo takes — a reduced,
// consumer-shaped view distinct from the full pkg/models.Agent row — does
// not fit here: verification needs essentially the whole row (status,
// expiry, approver, and all six of the request-matching fields), so there
// is no meaningful subset left to reduce to.
type Approval struct {
	ID       uuid.UUID
	TenantID string

	AgentID          uuid.UUID
	DelegationID     uuid.UUID
	RootDelegationID uuid.UUID

	// Subject is the requesting principal on the escalated call itself
	// (authz.Principal.Subject / DecideRequest.subject) — who asked, not
	// who may approve. RootPrincipal, below, is the only identity C21
	// permits to satisfy that.
	Subject string

	// RootPrincipal is the chain's root delegation's UserID — the only
	// identity permitted to approve (spec C21). At chain depth > 0 the
	// immediate delegator is an agent, and routing approval to an agent
	// would let the chain approve itself.
	RootPrincipal string

	ToolName    string
	Action      string
	DerivedTier ActionTier

	// InputDigest binds this approval to one specific request. Reused
	// unchanged from the audit chain's own notion of request identity
	// (a SHA-256 digest of the raw tool input) rather than inventing a
	// second one — see migrations/000012's own comment.
	InputDigest [32]byte

	// Status is a closed vocabulary ('pending', 'approved', 'denied')
	// enforced by a CHECK constraint in the migration, deliberately not
	// re-validated here: internal/store never writes anything but 'pending'
	// (store.CreateApproval), and never writes this column at all on any
	// other value, so there is no Go-side path that needs to reject a bad
	// one. Left as a plain string, matching this codebase's existing
	// pattern for other CHECK-constrained columns (audit_chain.decision,
	// audit_chain.denied_leg) rather than a typed enum.
	Status string

	RequestedAt time.Time
	ExpiresAt   time.Time

	ApprovedBy *string
	ApprovedAt *time.Time
}

// approvalStatusApproved is the one value of Status's closed vocabulary
// ('pending' | 'approved' | 'denied') that Verify accepts.
const approvalStatusApproved = "approved"

// Verify checks a loaded approval against every condition phase 5's
// escalation retry requires except tenant membership — RLS's job, already
// enforced by whatever loaded a into a store.LoadApproval, not by anything
// pure Go code could add here (store.go's own package doc: a second,
// divergent tenant check is worse than none). It returns "" once every
// remaining condition passes, or a description of the first one that does
// not — the same "empty means valid" convention ScopeNarrows uses for a
// delegation pair, extended to an approval-versus-request pair.
//
// now is a parameter, never read from the ambient clock: the same
// determinism Delegation.IsActive already requires of every function in
// this package.
//
// This is the load-bearing check of the whole escalation subsystem. Without
// the six comparisons in the switch below, an approval granted for
// Read /tmp/notes.txt would authorize Bash rm -rf / — same agent,
// delegation, and root principal, different tool, action, tier, and input
// entirely. Each is therefore its own comparison, in its own switch case,
// rather than one aggregate equality check: a single combined comparison
// can be satisfied by coincidence during a refactor in a way six named
// cases cannot, and each is proven independently, by mutation, in
// approval_test.go.
func (a *Approval) Verify(
	rootPrincipal string,
	agentID, delegationID uuid.UUID,
	tool, action string,
	derivedTier ActionTier,
	inputDigest [32]byte,
	now time.Time,
) string {
	if a.Status != approvalStatusApproved {
		return fmt.Sprintf("approval %s status is %q, want %q", a.ID, a.Status, approvalStatusApproved)
	}
	// Strictly before, not before-or-equal: expires_at is the instant the
	// approval stops being usable, not the last instant it still is. There
	// is deliberately no stored 'expired' status (migrations/000012's own
	// comment) — this comparison against the injected now is the only
	// source of truth, never a cached column that could drift out of step
	// with it.
	if !now.Before(a.ExpiresAt) {
		return fmt.Sprintf("approval %s expired at %s", a.ID, a.ExpiresAt.Format(time.RFC3339))
	}
	// approved_by is nullable in the schema even though a genuinely
	// 'approved' row should always carry it (the control plane writes both
	// together) — nothing here should trust that it always did. A nil
	// value fails this check rather than panicking on the dereference
	// below, the same fail-closed discipline every branch in this method
	// follows.
	if a.ApprovedBy == nil || *a.ApprovedBy != rootPrincipal {
		return fmt.Sprintf("approval %s was not approved by the delegation chain's root principal", a.ID)
	}
	switch {
	case a.AgentID != agentID:
		return fmt.Sprintf("approval %s was granted to a different agent", a.ID)
	case a.DelegationID != delegationID:
		return fmt.Sprintf("approval %s was granted for a different delegation", a.ID)
	case a.ToolName != tool:
		return fmt.Sprintf("approval %s was granted for a different tool", a.ID)
	case a.Action != action:
		return fmt.Sprintf("approval %s was granted for a different action", a.ID)
	case a.DerivedTier != derivedTier:
		return fmt.Sprintf("approval %s was granted for a different derived tier", a.ID)
	case a.InputDigest != inputDigest:
		return fmt.Sprintf("approval %s was granted for different input", a.ID)
	default:
		return ""
	}
}
