package models

import (
	"encoding/hex"
	"encoding/json"
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
// The json/db tags match Delegation's own snake_case convention (see that
// type). They arrived later than the type itself because until Task 6 added
// GET /v1/approvals, nothing ever marshalled an Approval: the PDP's two
// paths are protobuf (internal/pdpgrpc) and SQL (internal/store), and the
// PAP's approve/deny responses were the only JSON, produced with Go field
// names nobody had yet had to read.
type Approval struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	AgentID          uuid.UUID `json:"agent_id"           db:"agent_id"`
	DelegationID     uuid.UUID `json:"delegation_id"      db:"delegation_id"`
	RootDelegationID uuid.UUID `json:"root_delegation_id" db:"root_delegation_id"`

	// Subject is the requesting principal on the escalated call itself
	// (authz.Principal.Subject / DecideRequest.subject) — who asked, not
	// who may approve. RootPrincipal, below, is the only identity C21
	// permits to satisfy that.
	Subject string `json:"subject" db:"subject"`

	// RootPrincipal is the chain's root delegation's UserID — the only
	// identity permitted to approve (spec C21). At chain depth > 0 the
	// immediate delegator is an agent, and routing approval to an agent
	// would let the chain approve itself.
	RootPrincipal string `json:"root_principal" db:"root_principal"`

	ToolName    string     `json:"tool_name"    db:"tool_name"`
	Action      string     `json:"action"       db:"action"`
	DerivedTier ActionTier `json:"derived_tier" db:"derived_tier"`

	// InputDigest binds this approval to one specific request. Reused
	// unchanged from the audit chain's own notion of request identity
	// (a SHA-256 digest of the raw tool input) rather than inventing a
	// second one — see migrations/000012's own comment.
	//
	// json:"-" is not "do not serialise this": MarshalJSON/UnmarshalJSON
	// below carry it as a lowercase hex string under "input_digest"
	// instead. A bare [32]byte marshals as a JSON array of 32 numbers,
	// which no admin UI can display and no operator can compare against a
	// digest printed anywhere else in this system. Excluding it here, and
	// re-adding it in the wrapper, is what keeps those two methods free of
	// any encoding/json field-shadowing subtlety to reason about.
	//
	// The digest is one-way and stays that way: it is a SHA-256 of raw tool
	// input, so there is nothing for a UI to recover from it. It is useful
	// only for what a digest is for — telling two requests apart, and
	// matching this approval to the audit entry carrying the same value.
	InputDigest [32]byte `json:"-" db:"input_digest"`

	// Status is a closed vocabulary ('pending', 'approved', 'denied')
	// enforced by a CHECK constraint in the migration, deliberately not
	// re-validated here: internal/store never writes anything but 'pending'
	// (store.CreateApproval), and never writes this column at all on any
	// other value, so there is no Go-side path that needs to reject a bad
	// one. Left as a plain string, matching this codebase's existing
	// pattern for other CHECK-constrained columns (audit_chain.decision,
	// audit_chain.denied_leg) rather than a typed enum.
	Status string `json:"status" db:"status"`

	RequestedAt time.Time `json:"requested_at" db:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"   db:"expires_at"`

	ApprovedBy *string    `json:"approved_by,omitempty" db:"approved_by"`
	ApprovedAt *time.Time `json:"approved_at,omitempty" db:"approved_at"`
}

// approvalFields exists only to shed Approval's own JSON methods. A defined
// type with Approval's underlying struct type inherits its fields and tags
// but none of its methods, which is what keeps the two methods below from
// recursing into themselves.
type approvalFields Approval

// approvalWire is the encoding both JSON methods below share: every tagged
// field exactly as declared above, plus input_digest as hex. Declared once
// so Marshal and Unmarshal cannot drift into disagreeing about the wire
// format — the failure mode two hand-written mirror structs would invite.
type approvalWire struct {
	approvalFields
	InputDigest string `json:"input_digest"`
}

// MarshalJSON renders InputDigest as lowercase hex; every other field
// follows its own tag above.
func (a Approval) MarshalJSON() ([]byte, error) {
	return json.Marshal(approvalWire{
		approvalFields: approvalFields(a),
		InputDigest:    hex.EncodeToString(a.InputDigest[:]),
	})
}

// UnmarshalJSON is MarshalJSON's exact inverse. It exists because
// MarshalJSON alone would make an Approval lossy to round-trip — decoding
// what this type had just encoded would silently yield a zero InputDigest,
// and a zero digest is not "unknown," it is a digest that matches nothing
// and would fail Verify's own input comparison for a reason no one could
// trace back to a JSON hop. A [32]byte with no MarshalJSON at all round-trips
// correctly (as an array of numbers); adding one direction only would take
// that away.
//
// A digest that is present but not 32 bytes of hex is an error, never a
// partially-copied array: the same fail-loudly rule store.scanApproval
// applies to a short input_digest column. An absent or empty field leaves the
// digest zero without erroring — it is the caller's job to decide whether a
// zero digest is usable, exactly as it is for a row read any other way.
func (a *Approval) UnmarshalJSON(b []byte) error {
	var wire approvalWire
	if err := json.Unmarshal(b, &wire); err != nil {
		return err
	}
	*a = Approval(wire.approvalFields)
	if wire.InputDigest == "" {
		return nil
	}
	raw, err := hex.DecodeString(wire.InputDigest)
	if err != nil {
		return fmt.Errorf("approval input_digest: %w", err)
	}
	if len(raw) != len(a.InputDigest) {
		return fmt.Errorf("approval input_digest decodes to %d bytes, want %d", len(raw), len(a.InputDigest))
	}
	copy(a.InputDigest[:], raw)
	return nil
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
