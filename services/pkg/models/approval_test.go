package models

import (
	"crypto/sha256"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Fixed request identity every Approval.Verify test in this file checks
// against. Values are deliberately distinct in shape and content from one
// another — two unrelated UUIDs, two unrelated English verbs, a mid-range
// tier, a digest of a string naming this fixture — so a scan or argument-
// order mixup inside Verify shows up as a specific, wrong-field failure
// rather than passing by coincidence. This project's own house style calls
// out that a fixture whose fields are hard to tell apart has masked exactly
// this kind of mixup before; the tests below go one step further where it
// matters most (TestApproval_Verify_RejectsMismatchedRequest's own doc
// comment explains why).
var (
	approvalAgentID       = uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	approvalDelegationID  = uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000002")
	approvalRootPrincipal = "root-principal@example.com"
	approvalTool          = "Bash"
	approvalAction        = "execute"
	approvalTier          = ActionTierExternalComms
)

func approvalInputDigest() [32]byte {
	return sha256.Sum256([]byte("verify-approval fixture: rm -rf /tmp/x"))
}

var approvalTestNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

// validApproval returns an approved, unexpired row that matches every field
// verify (below) checks it against — the baseline every test in this file
// starts from and mutates exactly one field away from.
func validApproval() Approval {
	approvedBy := approvalRootPrincipal
	return Approval{
		ID:           uuid.New(),
		AgentID:      approvalAgentID,
		DelegationID: approvalDelegationID,
		ToolName:     approvalTool,
		Action:       approvalAction,
		DerivedTier:  approvalTier,
		InputDigest:  approvalInputDigest(),
		Status:       approvalStatusApproved,
		ExpiresAt:    approvalTestNow.Add(time.Hour),
		ApprovedBy:   &approvedBy,
	}
}

// verify calls a.Verify with the fixed request identity above, at
// approvalTestNow — the one call site every test in this file shares, so a
// mistake in wiring the parameters would show up everywhere at once rather
// than being able to hide in one test's own bespoke call.
func verify(a *Approval) string {
	return a.Verify(approvalRootPrincipal, approvalAgentID, approvalDelegationID,
		approvalTool, approvalAction, approvalTier, approvalInputDigest(), approvalTestNow)
}

// The baseline itself must pass. Every mutation test below trusts that a
// fixture identical to this one denies for the single reason it changed —
// that trust only holds if the unmodified fixture is proven clean first.
func TestApproval_Verify_AllConditionsSatisfiedPasses(t *testing.T) {
	a := validApproval()
	if reason := verify(&a); reason != "" {
		t.Fatalf("Verify() = %q, want \"\" for a fully matching, approved, unexpired approval", reason)
	}
}

func TestApproval_Verify_PendingStatusDenies(t *testing.T) {
	a := validApproval()
	a.Status = "pending"
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: a pending approval has not been actioned yet")
	}
}

// A distinct mutation from the pending case above (Status is a three-value
// vocabulary, and accepting either wrong value independently is a distinct
// way to fail closed) — kept as its own test rather than folded into the
// pending case so each is independently reported.
func TestApproval_Verify_DeniedStatusDenies(t *testing.T) {
	a := validApproval()
	a.Status = "denied"
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: a denied approval must never be accepted")
	}
}

func TestApproval_Verify_ExpiredApprovalDenies(t *testing.T) {
	a := validApproval()
	a.ExpiresAt = approvalTestNow.Add(-time.Second)
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: an expired approval must never be accepted")
	}
}

// expires_at is the instant the approval STOPS being usable, not the last
// instant it still is — Verify's comparison is strictly before. A boundary
// mutation (>= instead of >) would pass every other expiry test here (both
// clearly in the future and clearly in the past) and only be caught right
// at this line.
func TestApproval_Verify_ExpiresAtEqualToNowDenies(t *testing.T) {
	a := validApproval()
	a.ExpiresAt = approvalTestNow
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: expires_at equal to now is not strictly before it")
	}
}

// approved_by is nullable in the schema even though a genuinely 'approved'
// row should always carry it — Verify must fail closed rather than treat a
// nil pointer as a match (or panic on it).
func TestApproval_Verify_NilApprovedByDenies(t *testing.T) {
	a := validApproval()
	a.ApprovedBy = nil
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: a nil approved_by must fail closed, not be treated as a match")
	}
}

// C21's own property: an approval "approved" by anyone other than the
// chain's root principal must deny — including a plausible-looking
// identity, not just an obviously wrong string. The chain-shaped version of
// this same property, proving Decide itself passes the root's UserID and
// not an intermediate delegate's into Verify, is end to end in
// internal/pdpgrpc/escalation_test.go
// (TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate);
// this is Verify's own narrower half — given whatever string it is handed
// as the root, a different approved_by must not pass.
func TestApproval_Verify_ApprovedByNotRootPrincipalDenies(t *testing.T) {
	a := validApproval()
	notRoot := "intermediate-delegate-identity@example.com"
	a.ApprovedBy = &notRoot
	if reason := verify(&a); reason == "" {
		t.Fatal("Verify() = \"\", want a denial: approved_by must equal the chain's root principal exactly")
	}
}

// This is the load-bearing property of the whole escalation subsystem: an
// approval must bind to THIS exact request — same agent, delegation, tool,
// action, derived tier, and input_digest — or an approval granted for
// Read /tmp/notes.txt would authorize Bash rm -rf / (the plan's own worked
// example). Each field gets its own subtest, mutated alone against an
// otherwise-matching approval, so a check silently dropped for any one of
// the six is caught by exactly one failing subtest rather than being
// masked by "some field differs" passing for the wrong reason.
//
// The agent/delegation pair and the tool/action pair are deliberately
// mutated to EACH OTHER's known-good value, not to a fresh, unrelated one:
// both pairs are two same-typed fields (two uuid.UUIDs; two strings) Verify
// compares against two different parameters, and a mutation that compared
// against the wrong parameter (delegationID where agentID belongs, or vice
// versa) would still be caught by an unrelated random value purely by
// chance — almost any random UUID differs from delegationID too. Using the
// OTHER fixture's own value closes that gap: it only denies if Verify is
// really comparing AgentID against agentID and not against delegationID.
// derived_tier and input_digest have no same-typed neighbor in this
// parameter list for that swap to apply to, so those two use a plain
// different value instead — an adjacent tier for derived_tier (an
// off-by-one boundary is the stronger test), and the digest of a
// completely different, unapproved command for input_digest.
func TestApproval_Verify_RejectsMismatchedRequest(t *testing.T) {
	cases := map[string]func(*Approval){
		"agent":      func(a *Approval) { a.AgentID = approvalDelegationID },
		"delegation": func(a *Approval) { a.DelegationID = approvalAgentID },
		"tool":       func(a *Approval) { a.ToolName = approvalAction },
		"action":     func(a *Approval) { a.Action = approvalTool },
		"derived_tier": func(a *Approval) {
			a.DerivedTier = ActionTierInternalModify // adjacent to approvalTier (ActionTierExternalComms)
		},
		"input_digest": func(a *Approval) {
			a.InputDigest = sha256.Sum256([]byte("Bash rm -rf / — not the command this approval covers"))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := validApproval()
			mutate(&a)
			if reason := verify(&a); reason == "" {
				t.Fatalf("Verify() = \"\", want a denial: the approval's %s no longer matches this request", name)
			}
		})
	}
}
