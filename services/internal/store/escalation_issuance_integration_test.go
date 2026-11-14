//go:build integration

// The escalation proofs in escalation_integration_test.go seed their
// delegations with a direct INSERT (escalatingRootDelegation), because they
// are about what happens AFTER a delegation escalates. These two prove the
// path in front of that, which no supported interface had before
// migration 000022: an operator sets a threshold on the agent, issuance
// copies it onto the root, and the approval flow then runs on a delegation
// nobody wrote by hand. Same in-process server, dedicated tenant, and
// blanket-permit policy as that file, for the reasons its banner gives.
package store_test

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
)

// issueRoot issues a root delegation through the real CreateDelegation RPC,
// asking for DESTRUCTIVE and Bash, and nothing about escalation: whatever
// threshold the result carries came from the agent.
func issueRoot(t *testing.T, srv *pdpgrpc.Server, agentID uuid.UUID, subject string) *pdpgrpc.CreateDelegationResponse {
	t.Helper()
	resp, err := srv.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
		Subject: subject,
		AgentId: agentID.String(),
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: int32(models.ActionTierDestructive),
			Tools:         []string{"Bash"},
		},
		Purpose:    "escalation issuance proof",
		TtlSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}
	return resp
}

func TestIntegration_EscalationIssuance_AgentThresholdDrivesApproval(t *testing.T) {
	const tenant = "tenant-escalation-issuance-integration"
	const principal = "issuance-root@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-issuance-agent", models.TrustTierPlatformTrusted)
	if _, err := store.New(testDB, tenant).SetAgentEscalation(t.Context(), agentID,
		models.ActionTierDestructive, "operator@example.com"); err != nil {
		t.Fatalf("SetAgentEscalation() error = %v", err)
	}

	issued := issueRoot(t, srv, agentID, principal)
	if issued.GetGrantedScope().EscalateAt == nil || issued.GetGrantedScope().GetEscalateAt() != 4 {
		t.Fatalf("granted escalate_at = %v, want the agent's 4", issued.GetGrantedScope().EscalateAt)
	}
	delegationID := uuid.MustParse(issued.GetDelegationId())

	// Below the band: a read proceeds without anyone being asked.
	read := escalationDecideRequest(t, signer, delegationID, agentID, principal, nil)
	read.RawInput = "ls /tmp"
	if resp, err := srv.Decide(t.Context(), read); err != nil || resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("READ_ONLY call: effect = %v, err = %v, want ALLOW without escalation (reason: %s)",
			resp.GetEffect(), err, resp.GetReason())
	}

	// In the band: DESTRUCTIVE escalates and creates an approval.
	resp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegationID, agentID, principal, nil))
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE || resp.GetApprovalId() == "" {
		t.Fatalf("DESTRUCTIVE call: effect = %v, approval = %q, want ESCALATE with an approval (reason: %s)",
			resp.GetEffect(), resp.GetApprovalId(), resp.GetReason())
	}

	// The root principal approves; the retry naming the approval is allowed.
	approvalID := resp.GetApprovalId()
	approveApproval(t, tenant, uuid.MustParse(approvalID), principal)
	retry, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegationID, agentID, principal, &approvalID))
	if err != nil {
		t.Fatalf("retry Decide() error = %v", err)
	}
	if retry.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("approved retry: effect = %v, want ALLOW (reason: %s)", retry.GetEffect(), retry.GetReason())
	}
}

// Clearing the threshold is the widening the containment verdict exists to
// surface: the next root is issued with none, DESTRUCTIVE is allowed
// unattended, and the audit chain says who removed the human from the loop.
func TestIntegration_EscalationIssuance_ClearingIsUnattendedAndAudited(t *testing.T) {
	const tenant = "tenant-escalation-cleared-integration"
	const principal = "cleared-root@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-cleared-agent", models.TrustTierPlatformTrusted)
	repo := store.New(testDB, tenant)
	if _, err := repo.SetAgentEscalation(t.Context(), agentID, models.ActionTierDestructive, "operator@example.com"); err != nil {
		t.Fatalf("SetAgentEscalation() error = %v", err)
	}
	if err := repo.ClearAgentEscalation(t.Context(), agentID, "operator-2@example.com"); err != nil {
		t.Fatalf("ClearAgentEscalation() error = %v", err)
	}

	issued := issueRoot(t, srv, agentID, principal)
	if issued.GetGrantedScope().EscalateAt != nil {
		t.Fatalf("granted escalate_at = %d, want none after the threshold was cleared", issued.GetGrantedScope().GetEscalateAt())
	}
	resp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer,
		uuid.MustParse(issued.GetDelegationId()), agentID, principal, nil))
	if err != nil || resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("DESTRUCTIVE call: effect = %v, err = %v, want ALLOW unattended (reason: %s)",
			resp.GetEffect(), err, resp.GetReason())
	}

	var widening []string
	for _, e := range fetchAuditChain(t, tenant) {
		if e.EventType == "containment" && strings.Contains(e.Reason, "escalate_at") {
			widening = append(widening, e.Actor+": "+e.Reason)
		}
	}
	if len(widening) != 1 || !strings.HasPrefix(widening[0], "operator-2@example.com: agent grant widened") {
		t.Fatalf("containment entries naming escalate_at = %v, want exactly one, by operator-2, for the clear "+
			"(setting the first threshold narrows and must record none)", widening)
	}
}
