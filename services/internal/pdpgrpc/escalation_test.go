package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
)

// escalationFixture returns a fake store and request whose compound
// decision reaches EFFECT_ESCALATE: a single-hop root delegation whose
// ceiling (DESTRUCTIVE) sits above its own escalate_at (EXTERNAL_COMMS),
// and a Bash "rm -rf ..." command, which internal/authz's destructive-
// pattern match derives to DESTRUCTIVE outright (BuiltinTier/DeriveTier's
// raise-only evidence rule — tier.go) regardless of what the catalog would
// otherwise say for "Bash" — landing squarely inside the closed band
// [EXTERNAL_COMMS, DESTRUCTIVE] DelegationLeg checks (internal/authz/
// delegation.go). The agent is trusted enough for DESTRUCTIVE
// (PLATFORM_TRUSTED, DefaultTrustTable's own requirement) and escalationPolicy
// allows Bash outright, so neither of the other two legs has anything to
// deny on a fresh call — the escalate signal is the delegation leg's alone.
// Tests that need a DIFFERENT leg to deny on the retry (the "valid approval
// short-circuits nothing" properties) start here and perturb exactly one of
// agent/policy/delegation afterward, so a failure can only be attributed to
// the leg that test is actually about.
func escalationFixture() (*fakeStore, *DecideRequest, *models.Delegation) {
	agentID := uuid.New()
	delegationID := uuid.New()

	agent := authz.AgentInfo{
		ID: agentID, TrustTier: models.TrustTierPlatformTrusted, Enabled: true,
	}

	escalateAt := models.ActionTierExternalComms
	root := &models.Delegation{
		ID: delegationID, TenantID: testTenant, UserID: "root-principal@example.com",
		AgentID: agentID, RootDelegationID: delegationID, Depth: 0,
		MaxActionTier: models.ActionTierDestructive,
		EscalateAt:    &escalateAt,
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	fs := &fakeStore{agent: agent, chain: []*models.Delegation{root}}
	req := &DecideRequest{
		// Token: the fixture's own delegation id, spelled out — see
		// fakeSigner's Verify (server_test.go) for why that is a valid
		// "token" only for this fake.
		Token:    delegationID.String(),
		AgentId:  agentID.String(),
		Subject:  "root-principal@example.com", // root.UserID: the only subject Decide accepts for this chain
		Tool:     "Bash",
		RawInput: "rm -rf /tmp/scratch",
	}
	return fs, req, root
}

// escalationPolicy grants Bash outright — used by every escalationFixture
// test that does not itself need to make the principal leg deny.
func escalationPolicy() policy.Multi {
	return singleFakeLanguagePolicy(fakePolicyEngine{
		set: &grantSet{allowedTools: map[string]bool{"Bash": true}, maxTier: models.ActionTierDestructive},
	})
}

// approveCreatedApproval returns a copy of the single approval fs.CreateApproval
// captured, given the disposition a control-plane UPDATE would give it
// (E7): approved, by rootPrincipal. A copy, not the stored pointer itself —
// coding-style immutability, and so a test that further perturbs the copy
// (an expired ExpiresAt, say) cannot also corrupt fs.createdApprovals'
// own record of what was actually persisted.
func approveCreatedApproval(fs *fakeStore, rootPrincipal string) *models.Approval {
	a := *fs.createdApprovals[len(fs.createdApprovals)-1]
	a.Status = "approved"
	a.ApprovedBy = &rootPrincipal
	return &a
}

// escalate runs req through srv and fails the test unless it comes back
// EFFECT_ESCALATE — the shared "first call" step every two-call test in
// this file starts from, so a setup failure is reported once, clearly,
// rather than as a confusing downstream assertion on the retry.
func escalate(t *testing.T, srv *Server, req *DecideRequest) *DecideResponse {
	t.Helper()
	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a response", err)
	}
	if resp.GetEffect() != Effect_EFFECT_ESCALATE {
		t.Fatalf("Effect = %v, want EFFECT_ESCALATE (reason: %s)", resp.GetEffect(), resp.GetReason())
	}
	return resp
}

// A fresh escalation creates exactly one pending approval row, and every
// field on it traces back to this specific request — including the
// approver, fixed to the chain's ROOT principal (C21): at chain depth > 0
// the immediate delegator is an agent, not a person, and this fixture's
// single-hop chain makes the root the ONLY principal in the picture, so a
// bug that routed approval to "the last hop" instead of "the root" would
// not be visible here — see
// TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate,
// below, for the depth-2 chain that can tell the two apart.
func TestDecide_Escalation_CreatesApprovalWithRootPrincipalAsApprover(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	resp := escalate(t, srv, req)

	if resp.GetApprovalId() == "" {
		t.Fatal("ApprovalId is empty, want a newly created approval's id")
	}
	if _, err := uuid.Parse(resp.GetApprovalId()); err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", resp.GetApprovalId(), err)
	}

	if len(fs.createdApprovals) != 1 {
		t.Fatalf("approvals created = %d, want 1", len(fs.createdApprovals))
	}
	a := fs.createdApprovals[0]
	if a.ID.String() != resp.GetApprovalId() {
		t.Errorf("created approval id = %s, want %s (the response's approval_id)", a.ID, resp.GetApprovalId())
	}
	if a.AgentID.String() != req.GetAgentId() {
		t.Errorf("approval AgentID = %s, want %s", a.AgentID, req.GetAgentId())
	}
	if a.DelegationID.String() != req.GetToken() {
		t.Errorf("approval DelegationID = %s, want %s", a.DelegationID, req.GetToken())
	}
	if a.RootDelegationID != root.ID {
		t.Errorf("approval RootDelegationID = %s, want %s", a.RootDelegationID, root.ID)
	}
	if a.RootPrincipal != root.UserID {
		t.Errorf("approval RootPrincipal = %q, want %q (the chain root's UserID, C21)", a.RootPrincipal, root.UserID)
	}
	if a.Subject != req.GetSubject() {
		t.Errorf("approval Subject = %q, want %q", a.Subject, req.GetSubject())
	}
	if a.ToolName != req.GetTool() {
		t.Errorf("approval ToolName = %q, want %q", a.ToolName, req.GetTool())
	}
	// Action traces back to the tenant's tool_catalog, not the request:
	// DecideRequest carries no verb field at all after Task 3, and this
	// fixture's "Bash" has no catalog row, so action.Verb — and therefore
	// the approval's Action — is "" here, the same uncataloged-tool zero
	// value TestApplyExtraction_UncatalogedToolLeavesActionAndResourceUnchanged
	// (internal/authz/extract_test.go) and TestDecide_CatalogedVerbReachesAudit
	// (server_test.go) already pin for the audit trail's own copy of it.
	if a.Action != "" {
		t.Errorf("approval Action = %q, want \"\" (Bash is not cataloged in this fixture)", a.Action)
	}
	if a.DerivedTier != models.ActionTierDestructive {
		t.Errorf("approval DerivedTier = %v, want %v", a.DerivedTier, models.ActionTierDestructive)
	}
	if want := sha256.Sum256([]byte(req.GetRawInput())); a.InputDigest != want {
		t.Errorf("approval InputDigest = %x, want %x", a.InputDigest, want)
	}
	if !a.ExpiresAt.After(time.Now()) {
		t.Errorf("approval ExpiresAt = %v, want a future time", a.ExpiresAt)
	}

	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1", len(fs.appended))
	}
	if fs.appended[0].Decision != "ESCALATE" {
		t.Errorf("audit Decision = %q, want %q", fs.appended[0].Decision, "ESCALATE")
	}
}

// C21, where a single-hop chain cannot prove it: at depth 2, the approver
// must be the chain's ROOT (depth 0), never the depth-1 intermediate — an
// agent, not the person who could legitimately approve anything. Routing to
// the intermediate would let a chain approve itself.
func TestDecide_Escalation_RootPrincipalRoutesAroundIntermediateDelegate(t *testing.T) {
	agentID := uuid.New()
	rootID, intermediateID, actingID := uuid.New(), uuid.New(), uuid.New()
	escalateAt := models.ActionTierExternalComms

	root := &models.Delegation{
		ID: rootID, TenantID: testTenant, UserID: "root-human@example.com",
		RootDelegationID: rootID, Depth: 0,
		MaxActionTier: models.ActionTierDestructive, EscalateAt: &escalateAt,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	intermediate := &models.Delegation{
		ID: intermediateID, TenantID: testTenant, UserID: "intermediate-delegate-agent-identity",
		ParentDelegationID: &rootID, RootDelegationID: rootID, Depth: 1,
		MaxActionTier: models.ActionTierDestructive,
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	acting := &models.Delegation{
		ID: actingID, TenantID: testTenant, UserID: "acting-hop-identity", AgentID: agentID,
		ParentDelegationID: &intermediateID, RootDelegationID: rootID, Depth: 2,
		MaxActionTier: models.ActionTierDestructive,
		ExpiresAt:     time.Now().Add(time.Hour),
	}

	fs := &fakeStore{
		agent: authz.AgentInfo{ID: agentID, TrustTier: models.TrustTierPlatformTrusted, Enabled: true},
		chain: []*models.Delegation{root, intermediate, acting},
	}
	req := &DecideRequest{
		// Token is the acting delegation id, spelled out — see fakeSigner's
		// Verify (server_test.go).
		Token: actingID.String(), AgentId: agentID.String(),
		Subject: "root-human@example.com", Tool: "Bash", // root.UserID, not either later hop's
		RawInput: "rm -rf /tmp/scratch",
	}
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	escalate(t, srv, req)

	if len(fs.createdApprovals) != 1 {
		t.Fatalf("approvals created = %d, want 1", len(fs.createdApprovals))
	}
	if got := fs.createdApprovals[0].RootPrincipal; got != root.UserID {
		t.Fatalf("approval RootPrincipal = %q, want %q (the chain ROOT's UserID) — "+
			"C21: routing to depth 1's %q would let the chain approve itself",
			got, root.UserID, intermediate.UserID)
	}
}

// Deny overrides escalate (the binding constraint, restated as a test): an
// action above max_action_tier must deny even though it is also at or above
// escalate_at, and — the property that actually matters operationally — no
// approval row is created for a decision that was never escalatable. An
// approval an operator would have to explain away is noise this must not
// produce.
func TestDecide_Escalation_DenyOverridesEscalate_NoApprovalCreated(t *testing.T) {
	fs, req, root := escalationFixture()
	root.MaxActionTier = models.ActionTierInternalModify // now below the derived DESTRUCTIVE tier
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a response", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY: an action above max_action_tier must deny "+
			"even though it is also at or above escalate_at", resp.GetEffect())
	}
	if resp.GetApprovalId() != "" {
		t.Errorf("ApprovalId = %q, want empty for a DENY", resp.GetApprovalId())
	}
	if len(fs.createdApprovals) != 0 {
		t.Fatalf("approvals created = %d, want 0: a decision that was never escalatable "+
			"must not create an approval row", len(fs.createdApprovals))
	}
}

// The end-to-end happy path, and the audit requirement in the same test
// (two views of one two-call scenario, exercised together since splitting
// them would mean building this exact fixture twice): a matching, approved,
// unexpired approval turns the retry into ALLOW, mints no second approval
// row, and both the original escalation and the approved retry each get
// their own audit_chain entry — a phase that made escalations invisible to
// the audit chain would be worse than one that denied them.
func TestDecide_Escalation_ValidApprovalAllowsAndBothDecisionsAudited(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("second Effect = %v, want EFFECT_ALLOW (reason: %s)", second.GetEffect(), second.GetReason())
	}
	if second.GetApprovalId() != "" {
		t.Errorf("second ApprovalId = %q, want empty: no new approval is created on an approved retry",
			second.GetApprovalId())
	}
	if len(fs.createdApprovals) != 1 {
		t.Errorf("approvals created = %d, want 1: the retry must consume the existing row, not mint a second one",
			len(fs.createdApprovals))
	}

	if len(fs.appended) != 2 {
		t.Fatalf("audit entries appended = %d, want 2 (the escalation and the approved retry)", len(fs.appended))
	}
	if fs.appended[0].Decision != "ESCALATE" {
		t.Errorf("first audit Decision = %q, want %q", fs.appended[0].Decision, "ESCALATE")
	}
	if fs.appended[1].Decision != "ALLOW" {
		t.Errorf("second audit Decision = %q, want %q", fs.appended[1].Decision, "ALLOW")
	}
}

// An approval is good for one call. The same request, offering the same
// approval a second time, is denied and says why.
func TestDecide_Escalation_AnApprovalAllowsOnce(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)
	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID

	if resp, err := srv.Decide(context.Background(), req); err != nil || resp.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("first use: Effect = %v, err = %v; want EFFECT_ALLOW", resp.GetEffect(), err)
	}
	again, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second use: Decide() error = %v", err)
	}
	if again.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(again.GetReason(), "already been used") {
		t.Fatalf("second use: Effect = %v, Reason = %q; want EFFECT_DENY saying it has been used",
			again.GetEffect(), again.GetReason())
	}
}

// A call the approval does not cover is denied without spending it, so the
// call it was granted for can still use it.
func TestDecide_Escalation_ARefusedAttemptDoesNotSpendTheApproval(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)
	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	approved := req.RawInput

	req.RawInput = "rm -rf / --no-preserve-root"
	if resp, err := srv.Decide(context.Background(), req); err != nil || resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("different input: Effect = %v, err = %v; want EFFECT_DENY", resp.GetEffect(), err)
	}
	req.RawInput = approved
	if resp, err := srv.Decide(context.Background(), req); err != nil || resp.GetEffect() != Effect_EFFECT_ALLOW {
		t.Fatalf("the approved call: Effect = %v, err = %v, reason %q; want EFFECT_ALLOW",
			resp.GetEffect(), err, resp.GetReason())
	}
}

// An approval that cannot be recorded as spent allows nothing.
func TestDecide_Escalation_FailureToSpendTheApprovalIsNotAnAllow(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)
	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	fs.useApprovalErr = errors.New("database is down")

	if resp, err := srv.Decide(context.Background(), req); err == nil {
		t.Fatalf("Decide() = %v, want an error and no decision", resp.GetEffect())
	}
}

// The wire-level form of point 5's own worked example: an approval minted
// for one command must not authorize a different one. Same tool, same
// delegation, same everything except raw_input — so input_digest is the
// only thing that can catch this.
func TestDecide_Escalation_RetryWithDifferentInputDenies(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)

	req.RawInput = "rm -rf / --no-preserve-root" // still destructive, still Bash — different input entirely
	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID

	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: an approval must not authorize different input",
			second.GetEffect())
	}
}

func TestDecide_Escalation_ExpiredApprovalRetryDenies(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	approved := approveCreatedApproval(fs, root.UserID)
	approved.ExpiresAt = time.Now().Add(-time.Minute)
	fs.loadApproval = approved

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY", second.GetEffect())
	}
	if second.GetReason() == "" {
		t.Error("Reason is empty, want a reason naming the expired approval")
	}
	// "delegation" here names a structural denial that is not any of the
	// three legs' own re-evaluation (denyForApproval's own doc comment,
	// escalation.go) — audit_chain's CHECK constraint on denied_leg accepts
	// only '', 'principal', 'agent', or 'delegation', so this is also the
	// only choice that does not turn a clean DENY into an Internal error on
	// the audit write.
	if second.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", second.GetDeniedLeg(), "delegation")
	}

	if len(fs.appended) != 2 {
		t.Fatalf("audit entries appended = %d, want 2", len(fs.appended))
	}
	if fs.appended[1].Decision != "DENY" {
		t.Errorf("second audit Decision = %q, want %q", fs.appended[1].Decision, "DENY")
	}
	if fs.appended[1].DeniedLeg != "delegation" {
		t.Errorf("second audit DeniedLeg = %q, want %q", fs.appended[1].DeniedLeg, "delegation")
	}
}

// A missing approval — an unknown id, or one belonging to another tenant,
// indistinguishable by RLS design (store.go's own package doc) — denies. It
// must not fail the call: the phase plan's fail-closed rule ("a missing
// approval denies") is explicit that this is a DENY decision, not an RPC
// error a retrying PEP might mistake for transient.
func TestDecide_Escalation_UnknownApprovalIDDenies(t *testing.T) {
	fs, req, _ := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	escalate(t, srv, req)
	unknown := uuid.New()
	fs.loadApprovalErr = fmt.Errorf("%w: approval %s", store.ErrNotFound, unknown)

	id := unknown.String()
	req.ApprovalId = &id
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v, want a DENY response, not an RPC error", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY", second.GetEffect())
	}
}

// A generic store failure while loading the approval (a corrupt row, a
// connection blip) — not ErrNotFound — must ALSO deny rather than fail the
// call: the phase plan's fail-closed rule covers "cannot be loaded"
// generally ("an approval that cannot be loaded, parsed, matched, or
// verified denies"), not just the not-found case.
func TestDecide_Escalation_ApprovalLoadErrorDenies(t *testing.T) {
	fs, req, _ := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApprovalErr = errors.New("connection reset")

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v, want a DENY response: an approval that "+
			"cannot be loaded must deny, not fail the call", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY", second.GetEffect())
	}
}

// Unlike a verification failure, a pending approval that fails to PERSIST
// is treated like a failed audit write (D3's sibling rule): the call fails
// outright, with no response — a bare ESCALATE with no row behind it would
// give a PEP an approval id GetApproval could never resolve.
func TestDecide_Escalation_CreateApprovalFailure_Internal(t *testing.T) {
	fs, req, _ := escalationFixture()
	fs.createApprovalErr = errors.New("disk full")
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.appended) != 0 {
		t.Errorf("audit entries appended = %d, want 0: nothing to audit if the decision could not be recorded",
			len(fs.appended))
	}
}

// --- "a valid approval satisfies the escalation condition and nothing
// else" — one test per leg, each perturbing exactly that leg between the
// escalation and the retry so a failure can only be attributed to it. ---

// The plan's own named example: an approved escalation whose delegation has
// since been revoked must deny, not allow.
func TestDecide_Escalation_ValidApproval_RevokedDelegationStillDenies(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)

	root.Revoked = true // the delegation itself is mutated; fs.chain holds this same pointer

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: a revoked delegation must survive a valid approval",
			second.GetEffect())
	}
	if second.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", second.GetDeniedLeg(), "delegation")
	}
	if len(fs.createdApprovals) != 1 {
		t.Errorf("approvals created = %d, want 1 (only the original escalation)", len(fs.createdApprovals))
	}
}

// A valid approval must not resurrect an agent that was suspended between
// the escalation and the retry.
func TestDecide_Escalation_ValidApproval_SuspendedAgentStillDenies(t *testing.T) {
	fs, req, root := escalationFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)

	fs.agent.Suspended = true

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: a suspended agent must survive a valid approval",
			second.GetEffect())
	}
	if second.GetDeniedLeg() != "agent" {
		t.Errorf("DeniedLeg = %q, want %q", second.GetDeniedLeg(), "agent")
	}
}

// A valid approval must not stand in for a principal policy that started
// refusing between the escalation and the retry — the approval satisfies
// the escalation band, never the principal leg itself.
func TestDecide_Escalation_ValidApproval_PolicyDenyStillDenies(t *testing.T) {
	fs, req, root := escalationFixture()
	set := &grantSet{allowedTools: map[string]bool{"Bash": true}, maxTier: models.ActionTierDestructive}
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: set}), testConfig(), &fakeSigner{})

	first := escalate(t, srv, req)
	fs.loadApproval = approveCreatedApproval(fs, root.UserID)

	set.allowedTools = map[string]bool{} // Bash is no longer granted

	approvalID := first.GetApprovalId()
	req.ApprovalId = &approvalID
	second, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	if second.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: a principal-leg denial must survive a valid approval",
			second.GetEffect())
	}
	if second.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q, want %q: the approval must not mask which leg actually denied",
			second.GetDeniedLeg(), "principal")
	}
}

// A second ask for a call that already has an approval waiting gets that
// approval's id back, and creates nothing.
func TestDecide_Escalation_SameCallAlreadyPending_ReturnsTheWaitingApproval(t *testing.T) {
	fs, req, _ := escalationFixture()
	fs.pendingApproval = uuid.New()
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	resp := escalate(t, srv, req)

	if resp.GetApprovalId() != fs.pendingApproval.String() {
		t.Errorf("ApprovalId = %q, want the waiting approval %s", resp.GetApprovalId(), fs.pendingApproval)
	}
	if len(fs.createdApprovals) != 0 {
		t.Errorf("approvals created = %d, want 0", len(fs.createdApprovals))
	}
	if fs.lastMaxPending != testConfig().MaxPendingApprovals {
		t.Errorf("maximum passed to the store = %d, want the configured %d", fs.lastMaxPending, testConfig().MaxPendingApprovals)
	}
}

// A session at its maximum is denied, and the denial is audited like any
// other: it is a decision, not a failure.
func TestDecide_Escalation_TooManyPending_IsAnAuditedDeny(t *testing.T) {
	fs, req, _ := escalationFixture()
	fs.createApprovalErr = fmt.Errorf("%w: 20", store.ErrTooManyPendingApprovals)
	srv := NewServer(fs, escalationPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), "approvals waiting") {
		t.Fatalf("Effect = %v, Reason = %q; want a DENY saying approvals are waiting", resp.GetEffect(), resp.GetReason())
	}
	if resp.GetApprovalId() != "" {
		t.Errorf("ApprovalId = %q, want none", resp.GetApprovalId())
	}
	if len(fs.appended) != 1 || fs.appended[0].Decision != "DENY" {
		t.Errorf("want one audit row recording DENY, got %d rows", len(fs.appended))
	}
}
