//go:build integration

// Phase 5 Task 5 (docs/superpowers/sdd/2026-08-12-phase-5-escalation/
// task-5-brief.md): the six escalation proofs against a live stack, plus one
// more the phase's own binding constraint requires ("an approval is a
// fourth condition, never a bypass ... if your proofs do not exercise that,
// add one that does").
//
// A separate file from store_integration_test.go, alphabetically ordered
// before it — "escalation_integration_test.go" sorts before
// "store_integration_test.go", so these tests register, and run, before
// TestEndToEnd's own proof6 permanently revokes INSERT on audit_chain from
// stratium_app/stratium_audit_owner. That revocation would not actually
// break these tests either way — they build their Server on testDB
// (stratium_migrate), which OWNS every table these migrations create
// (deploy/docker/init-db.sql) and so holds full privileges independent of
// any GRANT/REVOKE aimed at a different role — but there is no reason to
// rely on that ownership technicality when file ordering settles the
// question for free, the same way this whole package's TestMain, and every
// package-level var and helper below (testDB, seedAgent, seedDelegation,
// withTenantTx, fetchAuditChain, wantCode, ...), are already shared across
// every *_test.go file in this one package without an import.
//
// Every proof below builds a real pdpgrpc.Server in-process against
// store.New(testDB, tenant) rather than going through pdpClient — the same
// choice, for the same reason, store_integration_test.go's own "Phase 4
// Task 6" banner already makes at length: pdpClient is permanently scoped to
// configuredTenant (main.go fixes cfg.TenantID once at startup), and
// configuredTenant accumulates cedar/rego/json/xacml policies scoped to
// specific named principals as TestEndToEnd runs — a fresh escalation
// principal there would fall through every one of them to default-deny at
// the principal leg, masking the delegation-leg signal these proofs are
// actually about (the same lesson TestIntegration_LoadAllPolicies_
// RoundTripsPriority's own doc comment states for policy seeding
// specifically). A dedicated tenant per proof is what the task's own brief
// points at directly: "seed into dedicated tenants, as the existing
// TestIntegration_* tests do."
//
// This is still genuinely "against a live stack," the same claim that
// banner makes for policy.Multi: real Postgres, the real migrated schema
// and RLS (FORCE ROW LEVEL SECURITY on approvals applies even to testDB's
// stratium_migrate connection, which owns the tables but is not a
// superuser or BYPASSRLS — deploy/docker/init-db.sql), the real production
// pdpgrpc.Server.Decide/GetApproval, resolveEscalation, models.Approval.
// Verify, and store.CreateApproval/LoadApproval — only the transport (an
// in-process call vs. a second dialled docker-compose PDP, which cannot
// exist for an arbitrary tenant since STRATIUM_TENANT_ID is fixed per
// container) differs. Also consistent with this codebase's own established
// vocabulary for "wire-level": internal/pdpgrpc/escalation_test.go's
// TestDecide_Escalation_RetryWithDifferentInputDenies already calls itself
// "the wire-level form" of the exact property proof 4 below re-proves, while
// using a FAKE store — "wire" there names the DecideRequest/DecideResponse
// proto types and the Server.Decide method boundary, not a literal TCP
// socket. Every proof below promotes that same property from a fake store
// to real Postgres, which is the axis that actually matters.
//
// One shared registry (cedar only, one blanket permit policy) and one
// shared delegation shape (single root hop, escalate_at EXTERNAL_COMMS
// through a caller-chosen max_action_tier, a Bash "rm -rf" raw_input that
// destructiveEvidence — internal/authz/tier.go — derives DESTRUCTIVE
// outright) are reused throughout: the same fixture shape
// escalationFixture (internal/pdpgrpc/escalation_test.go) already proved
// correct at the unit level, so every proof's outcome below is attributable
// to exactly the mechanism under test — the delegation leg's escalate band
// and resolveEscalation — never a policy surprise or an unrelated leg
// denial.
package store_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/policy/cedar"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/internal/token"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

// escalationBlanketPermit is the simplest possible Cedar policy — the same
// one-liner TestIntegration_LoadAllPolicies_RoundTripsPriority already uses
// — so the principal leg always allows and every proof's DENY/ESCALATE below
// is unambiguously attributable to the delegation leg or resolveEscalation
// alone, never to policy.
const escalationBlanketPermit = `permit(principal, action, resource);`

// escalationRegistry is a single-engine (cedar) registry: these proofs are
// about escalation mechanics, not multi-language policy plumbing, so a
// second/third/fourth engine would only be fixture noise.
func escalationRegistry() policy.Registry {
	return policy.Registry{"cedar": cedar.New()}
}

// escalationServer builds a real pdpgrpc.Server for tenant against real
// Postgres (testDB), with escalationBlanketPermit seeded so the principal
// leg always allows. See this file's own banner for why an in-process
// server against a dedicated tenant is the right tool here, not pdpClient.
//
// Also returns the *token.Signer it was built with: every proof in this
// file calls Decide, which as of Phase 9 Task 3 authenticates a token on
// EVERY call (spec K4) — unlike before that task, a nil signer here would
// now panic on the first Decide call rather than sit safely unused (that
// was true when this comment, and this function's signature, last changed:
// Decide's own doc comment covers why there is no signer-optional path left
// at all). Callers use the returned signer to mint the tokens
// escalationDecideRequest needs.
func escalationServer(t *testing.T, tenant string) (*pdpgrpc.Server, *token.Signer) {
	t.Helper()
	seedPolicy(t, tenant, "escalation-blanket-permit", escalationBlanketPermit, "allow")
	repo := store.New(testDB, tenant)
	cfg := config.Config{TenantID: tenant, MaxDepth: 5, ApprovalTTL: time.Hour, PrincipalAuthInsecure: true}
	// The SAME signer instance both signs (below, via NewServer) and is
	// handed back to the caller to mint tokens with: two independently
	// generated keys would mean every token escalationToken mints fails
	// this exact server's own Verify, defeating the whole point of handing
	// the signer back at all.
	signer := escalationSigner(t)
	return pdpgrpc.NewServer(repo, policy.NewMulti(repo, escalationRegistry()), cfg, signer), signer
}

// escalationSigner returns a real *token.Signer backed by a freshly
// generated, current-only EC key. Fresh per call, never a package-level
// shared key or fixture committed to the repo — the same discipline
// internal/pdpgrpc/token_test.go's freshECKeyPEM documents for itself, and
// for the same reason: a genuinely distinct key per test is what this
// package's own no-committed-test-keys rule (Task 1's finding) requires,
// and t.TempDir() gives each caller its own auto-cleaned key file with no
// risk of one test's key leaking into another's.
//
// Duplicated here rather than imported from internal/pdpgrpc's own
// equivalent (token_test.go's freshECKeyPEM): that helper is unexported,
// belongs to a different package, and this file has no reason to depend on
// pdpgrpc's own test internals just to generate a throwaway key.
func escalationSigner(t *testing.T) *token.Signer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	signer, err := token.Load(path, "")
	if err != nil {
		t.Fatalf("token.Load() = %v, want success", err)
	}
	return signer
}

// escalationToken mints a token naming delegationID via signer: the minimal
// claim set authenticateToken (internal/pdpgrpc/authenticate.go) actually
// reads -- "sub", the delegation id -- plus "exp", which
// internal/token.Verify requires present via jwt.WithExpirationRequired().
// Built directly as jwt.MapClaims rather than through pdpgrpc's own
// tokenClaims: that function is unexported, belongs to a different package,
// and bakes in claims (tenant_id, iat, jti) this file's own proofs have no
// need to assert on -- they are about escalation mechanics (resolveEscalation,
// DelegationLeg, Approval.Verify), not about K3's exact claim shape, which
// internal/pdpgrpc/token_test.go already pins on its own.
func escalationToken(t *testing.T, signer *token.Signer, delegationID uuid.UUID) string {
	t.Helper()
	tok, err := signer.Sign(jwt.MapClaims{
		"sub": delegationID.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("Sign() error = %v, want success", err)
	}
	return tok
}

// escalationRawInput is a Bash command internal/authz's destructive-pattern
// match (destructiveEvidence, tier.go) derives DESTRUCTIVE outright,
// regardless of any catalog entry — the same raw_input escalationFixture
// (internal/pdpgrpc/escalation_test.go) uses, reused here because it is
// already proven to land in the closed [EXTERNAL_COMMS, DESTRUCTIVE] band
// escalatingRootDelegation checks against.
const escalationRawInput = "rm -rf /tmp/scratch"

// escalatingRootDelegation seeds a single-hop root delegation banded
// [EXTERNAL_COMMS, maxTier]. maxTier is the caller's choice so proof 2 below
// can lower it beneath the derived DESTRUCTIVE tier and prove
// deny-overrides-escalate without a second fixture shape. rootPrincipal
// becomes both delegations.user_id and, once an escalation occurs,
// approvals.root_principal — the identity C21 permits to approve.
func escalatingRootDelegation(t *testing.T, tenant string, agentID uuid.UUID, rootPrincipal string, maxTier models.ActionTier, purpose string) *models.Delegation {
	t.Helper()
	escalateAt := models.ActionTierExternalComms
	id := uuid.New()
	return seedDelegation(t, &models.Delegation{
		ID: id, TenantID: tenant, UserID: rootPrincipal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: maxTier, EscalateAt: &escalateAt,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
}

// escalationDecideRequest builds the Bash "rm -rf" DecideRequest every proof
// below sends, varying only what each proof needs to vary: approvalID is
// nil on a fresh escalation, set (a pointer to the id string) on a retry.
// Token is a genuine, freshly signed token naming delegationID
// (escalationToken) — not delegationID's own string form — matching Phase 9
// Task 3's removal of the bare delegation_id field this request type used
// to carry (spec K4).
func escalationDecideRequest(t *testing.T, signer *token.Signer, delegationID, agentID uuid.UUID, subject string, approvalID *string) *pdpgrpc.DecideRequest {
	t.Helper()
	return &pdpgrpc.DecideRequest{
		Token:      escalationToken(t, signer, delegationID),
		AgentId:    agentID.String(),
		Subject:    subject,
		Tool:       "Bash",
		RawInput:   escalationRawInput,
		ApprovalId: approvalID,
	}
}

// approveApproval performs the control-plane UPDATE directly against
// Postgres, through testDB — E7 requires this ("the PDP never grants an
// approval, it only reads one"; migrations/000012_approvals grants
// stratium_app SELECT, INSERT, deliberately never UPDATE). testDB, never
// servingDB: this is the control plane's own write path, a different role
// entirely, not a probe of what the PDP's serving role can or cannot do —
// TestIntegration_Approvals_ServingRoleCannotUpdate already proves that
// absence; this helper writes the approval the way the control plane
// actually would. approvedBy must equal the chain's root principal exactly
// for Approval.Verify to accept it later.
func approveApproval(t *testing.T, tenant string, approvalID uuid.UUID, approvedBy string) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(),
			`UPDATE approvals SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE id = $2`,
			approvedBy, approvalID.String())
		if err != nil {
			t.Fatalf("control-plane UPDATE approvals: %v", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			t.Fatalf("RowsAffected: %v", err)
		}
		if n != 1 {
			t.Fatalf("control-plane UPDATE approvals affected %d rows, want 1", n)
		}
	})
}

// countApprovals returns how many approvals rows exist for tenant — the
// DB-level truth proof 2 checks directly, rather than trusting the
// response's own approval_id being empty.
func countApprovals(t *testing.T, tenant string) int {
	t.Helper()
	var n int
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM approvals`).Scan(&n); err != nil {
			t.Fatalf("count approvals: %v", err)
		}
	})
	return n
}

// TestIntegration_Escalation_InBandEscalatesWithApprovalAndRootPrincipalApprover
// is proof 1: a delegation with a threshold below its ceiling, an action in
// the band, returns ESCALATE with an approval id, and the pending row exists
// with the root principal as approver. Also reports the escalated
// decision's latency (brief item 3): CreateApproval is a second INSERT this
// call performs beyond the audit_chain append every decision already makes
// — the first decision path in this codebase where the store does more than
// the two loads (LoadAgent, LoadChain) plus the one audit write. See the
// task report for the number, compared against Phase 1c's ~2.5ms baseline
// and Phase 4's four-engine figure (~4.30ms mean, task-6-report.md).
func TestIntegration_Escalation_InBandEscalatesWithApprovalAndRootPrincipalApprover(t *testing.T) {
	const tenant = "tenant-escalation-inband-integration"
	const rootPrincipal = "root-inband@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-inband-agent", models.TrustTierPlatformTrusted)
	delegation := escalatingRootDelegation(t, tenant, agentID, rootPrincipal, models.ActionTierDestructive, "in-band escalation proof")

	callStart := time.Now()
	resp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	escalatedLatency := time.Since(callStart)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a response", err)
	}
	t.Logf("escalated decision latency: %s (Phase 1c baseline ~2.5ms; Phase 4's four-engine mean ~4.30ms, "+
		"task-6-report.md; this call also performs CreateApproval, a second INSERT beyond the audit append "+
		"every decision already makes)", escalatedLatency)

	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("Effect = %v, want EFFECT_ESCALATE (reason: %s)", resp.GetEffect(), resp.GetReason())
	}
	if resp.GetApprovalId() == "" {
		t.Fatal("ApprovalId is empty, want a newly created approval's id")
	}
	approvalID, err := uuid.Parse(resp.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", resp.GetApprovalId(), err)
	}
	// Documented empty unless effect is EFFECT_DENY (proto/pdp/v1/pdp.proto)
	// — this is an escalation, not a denial.
	if resp.GetDeniedLeg() != "" {
		t.Errorf("DeniedLeg = %q, want empty", resp.GetDeniedLeg())
	}

	approval, err := store.New(testDB, tenant).LoadApproval(t.Context(), approvalID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	t.Logf("pending approval: %+v", approval)
	if approval.Status != "pending" {
		t.Errorf("Status = %q, want %q", approval.Status, "pending")
	}
	if approval.RootPrincipal != rootPrincipal {
		t.Errorf("RootPrincipal = %q, want %q", approval.RootPrincipal, rootPrincipal)
	}
	if approval.AgentID != agentID {
		t.Errorf("AgentID = %s, want %s", approval.AgentID, agentID)
	}
	if approval.DelegationID != delegation.ID {
		t.Errorf("DelegationID = %s, want %s", approval.DelegationID, delegation.ID)
	}
	if approval.DerivedTier != models.ActionTierDestructive {
		t.Errorf("DerivedTier = %v, want %v", approval.DerivedTier, models.ActionTierDestructive)
	}
	if approval.ApprovedBy != nil {
		t.Errorf("ApprovedBy = %v, want nil (still pending)", approval.ApprovedBy)
	}
	if n := countApprovals(t, tenant); n != 1 {
		t.Errorf("approvals rows for tenant = %d, want 1", n)
	}
}

// TestIntegration_Escalation_AboveCeilingDeniesNoApprovalCreated is proof 2:
// an action above the delegation's ceiling denies, and creates no approval
// row, even though it is also at or above escalate_at — deny overrides
// escalate, and an escalation record for a decision that was never
// escalatable is noise an operator would have to explain. Checked at the DB
// level (countApprovals), not just against the response's own empty
// approval_id.
func TestIntegration_Escalation_AboveCeilingDeniesNoApprovalCreated(t *testing.T) {
	const tenant = "tenant-escalation-above-ceiling-integration"
	const rootPrincipal = "root-above-ceiling@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-above-ceiling-agent", models.TrustTierPlatformTrusted)
	// max_action_tier INTERNAL_MODIFY, below the derived DESTRUCTIVE tier.
	// escalate_at (EXTERNAL_COMMS, fixed by escalatingRootDelegation) is
	// still <= derived, so this WOULD have escalated if the ceiling did not
	// deny first — DelegationLeg checks the ceiling before the band (see
	// that function's own doc comment, internal/authz/delegation.go).
	delegation := escalatingRootDelegation(t, tenant, agentID, rootPrincipal, models.ActionTierInternalModify, "above-ceiling denial proof")

	resp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("Decide() error = %v, want a response", err)
	}
	t.Logf("Decide() above the ceiling -> effect=%s denied_leg=%q reason=%q",
		resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason())

	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY: an action above max_action_tier must deny even though it "+
			"is also at or above escalate_at", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
	}
	if resp.GetApprovalId() != "" {
		t.Errorf("ApprovalId = %q, want empty for a DENY", resp.GetApprovalId())
	}
	if n := countApprovals(t, tenant); n != 0 {
		t.Errorf("approvals rows for tenant = %d, want 0: a decision that was never escalatable must not "+
			"create an approval row", n)
	}
}

// TestIntegration_Escalation_ApprovedRetryAllowsAndAuditChainVerifies is
// proof 3: a control-plane UPDATE to 'approved' — written directly against
// the database, as E7 requires, since the PDP has no UPDATE grant
// (TestIntegration_Approvals_ServingRoleCannotUpdate already proves that
// grant's absence; approveApproval writes the approval the way the control
// plane actually would, through testDB, a different role entirely, never
// through the PDP) — then a retry with the approval id allows, and the
// audit chain contains both the escalation and the approved retry, and
// audit.Verify passes over the pair. Also reports the approved retry's
// latency (brief item 3).
func TestIntegration_Escalation_ApprovedRetryAllowsAndAuditChainVerifies(t *testing.T) {
	const tenant = "tenant-escalation-approved-retry-integration"
	const rootPrincipal = "root-approved-retry@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-approved-retry-agent", models.TrustTierPlatformTrusted)
	delegation := escalatingRootDelegation(t, tenant, agentID, rootPrincipal, models.ActionTierDestructive, "approved retry proof")

	first, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("first Decide() error = %v", err)
	}
	if first.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("first Effect = %v, want EFFECT_ESCALATE", first.GetEffect())
	}
	approvalID, err := uuid.Parse(first.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", first.GetApprovalId(), err)
	}

	approveApproval(t, tenant, approvalID, rootPrincipal)

	approvalIDStr := first.GetApprovalId()
	callStart := time.Now()
	second, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, &approvalIDStr))
	approvedRetryLatency := time.Since(callStart)
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	t.Logf("approved-retry decision latency: %s (Phase 1c baseline ~2.5ms; Phase 4's four-engine mean "+
		"~4.30ms, task-6-report.md; this call performs one extra SELECT — LoadApproval — versus an "+
		"ordinary decision, but no extra INSERT)", approvedRetryLatency)

	if second.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("second Effect = %v, want EFFECT_ALLOW (reason: %s)", second.GetEffect(), second.GetReason())
	}
	if second.GetApprovalId() != "" {
		t.Errorf("second ApprovalId = %q, want empty: no new approval is created on an approved retry", second.GetApprovalId())
	}
	// All three legs still evaluate on the approved retry — an approval is a
	// fourth condition, never a bypass (the phase's own binding constraint).
	// Per-leg fields are never rewritten by approval resolution (Task 3's
	// design choice): DelegationEffect stays ESCALATE here, the leg's own
	// honest, fresh verdict, not evidence the leg was skipped — only the
	// overall Effect becomes ALLOW, because resolveEscalation independently
	// verified a matching approval on top of it.
	if second.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Errorf("second PrincipalEffect = %v, want EFFECT_ALLOW (the blanket permit policy)", second.GetPrincipalEffect())
	}
	if second.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Errorf("second AgentEffect = %v, want EFFECT_ALLOW", second.GetAgentEffect())
	}
	if second.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Errorf("second DelegationEffect = %v, want EFFECT_ESCALATE (the leg's own fresh verdict, unmasked "+
			"by the approval that separately satisfied it)", second.GetDelegationEffect())
	}
	if n := countApprovals(t, tenant); n != 1 {
		t.Errorf("approvals rows for tenant = %d, want 1: the retry must consume the existing row, not mint a second one", n)
	}

	entries := fetchAuditChain(t, tenant)
	if len(entries) != 2 {
		t.Fatalf("audit_chain entries for tenant = %d, want 2 (the escalation and the approved retry)", len(entries))
	}
	if entries[0].Decision != "ESCALATE" {
		t.Errorf("entries[0].Decision = %q, want %q", entries[0].Decision, "ESCALATE")
	}
	if entries[1].Decision != "ALLOW" {
		t.Errorf("entries[1].Decision = %q, want %q", entries[1].Decision, "ALLOW")
	}
	if err := audit.Verify(entries); err != nil {
		t.Fatalf("audit.Verify() over the escalation+approved-retry pair error = %v, want nil", err)
	}
	t.Logf("audit.Verify() passed over the escalation and approved-retry pair")

	// The approval is spent: the same call, offering it again, is denied.
	// Against the real database this is also what shows the serving role may
	// set used_at (migrations/000023) and that the statement finds the row
	// under row-level security.
	third, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, &approvalIDStr))
	if err != nil {
		t.Fatalf("third Decide() error = %v", err)
	}
	if third.GetEffect() != pdpgrpc.Effect_EFFECT_DENY || !strings.Contains(third.GetReason(), "already been used") {
		t.Errorf("third Effect = %v, Reason = %q; want EFFECT_DENY saying the approval has been used",
			third.GetEffect(), third.GetReason())
	}
}

// TestIntegration_Escalation_ApprovedRetryStillEnforcesDelegationLeg is the
// live proof the phase's own binding constraint asks for directly: "an
// approval is a fourth condition, never a bypass ... all three legs still
// evaluate on the approved retry. If your proofs do not exercise that, add
// one that does." Proof 3 above shows the happy path leaves every leg's own
// verdict intact; this test shows the consequence when a leg's fresh
// evaluation genuinely changes between the escalation and the retry: the
// SAME valid, approved approval — status='approved', correct approver,
// correct six-field request match, unexpired — must NOT resurrect a
// delegation revoked in between. Mirrors internal/pdpgrpc/escalation_test.go's
// TestDecide_Escalation_ValidApproval_RevokedDelegationStillDenies, live
// against real Postgres rather than a fake store.
func TestIntegration_Escalation_ApprovedRetryStillEnforcesDelegationLeg(t *testing.T) {
	const tenant = "tenant-escalation-not-a-bypass-integration"
	const rootPrincipal = "root-not-a-bypass@example.com"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-not-a-bypass-agent", models.TrustTierPlatformTrusted)
	delegation := escalatingRootDelegation(t, tenant, agentID, rootPrincipal, models.ActionTierDestructive, "approval is not a bypass proof")

	first, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("first Decide() error = %v", err)
	}
	if first.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("first Effect = %v, want EFFECT_ESCALATE", first.GetEffect())
	}
	approvalID, err := uuid.Parse(first.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", first.GetApprovalId(), err)
	}
	approveApproval(t, tenant, approvalID, rootPrincipal)

	// The delegation itself is revoked directly against Postgres — the same
	// structural fact that would occur if a principal pulled the grant
	// between requesting escalation and a human approving it.
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), `UPDATE delegations SET revoked = true WHERE id = $1`, delegation.ID.String()); err != nil {
			t.Fatalf("revoke delegation: %v", err)
		}
	})

	approvalIDStr := first.GetApprovalId()
	second, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, &approvalIDStr))
	if err != nil {
		t.Fatalf("second Decide() error = %v", err)
	}
	t.Logf("Decide() with a valid, approved approval against a now-revoked delegation -> effect=%s reason=%q",
		second.GetEffect(), second.GetReason())
	if second.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("second Effect = %v, want EFFECT_DENY: a valid approval must not resurrect a delegation "+
			"revoked since the escalation — an approval is a fourth condition, never a bypass", second.GetEffect())
	}
	if second.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", second.GetDeniedLeg(), "delegation")
	}
}

// TestIntegration_Escalation_ApprovalDoesNotAuthorizeDifferentInput is proof
// 4, the one the brief names as mattering most: an approval for one action
// does not authorize a different one — the input_digest binding, live
// against real Postgres rather than the fake-store unit test
// (internal/pdpgrpc/escalation_test.go's TestDecide_Escalation_
// RetryWithDifferentInputDenies already proves this against a fake; this is
// that same property promoted to a real approvals row, a real
// Approval.Verify call, and a real database round trip). Proven in both
// directions: the ORIGINAL input, replayed with the approval id, allows
// first — the control case, without which a DENY on different input would
// not distinguish "the binding works" from "something else about this
// retry is broken" — and only then a DIFFERENT input, same approval id,
// same everything else, denies.
func TestIntegration_Escalation_ApprovalDoesNotAuthorizeDifferentInput(t *testing.T) {
	const tenant = "tenant-escalation-input-digest-integration"
	const rootPrincipal = "root-input-digest@example.com"
	const differentInput = "rm -rf / --no-preserve-root"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-input-digest-agent", models.TrustTierPlatformTrusted)
	delegation := escalatingRootDelegation(t, tenant, agentID, rootPrincipal, models.ActionTierDestructive, "input_digest binding proof")

	first, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("first Decide() error = %v", err)
	}
	if first.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("first Effect = %v, want EFFECT_ESCALATE", first.GetEffect())
	}
	approvalID, err := uuid.Parse(first.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", first.GetApprovalId(), err)
	}
	approveApproval(t, tenant, approvalID, rootPrincipal)

	// Confirm the persisted digest is genuinely keyed off the original
	// input, not a coincidence of both commands hashing the same way.
	stored, err := store.New(testDB, tenant).LoadApproval(t.Context(), approvalID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	wantDigest := sha256.Sum256([]byte(escalationRawInput))
	if stored.InputDigest != wantDigest {
		t.Fatalf("stored input_digest = %x, want %x (sha256 of the original raw_input)", stored.InputDigest, wantDigest)
	}

	approvalIDStr := first.GetApprovalId()

	// Control: the ORIGINAL input, same approval id, must allow.
	allowResp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, &approvalIDStr))
	if err != nil {
		t.Fatalf("same-input retry Decide() error = %v", err)
	}
	if allowResp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("same-input retry Effect = %v, want EFFECT_ALLOW (reason: %s) — the control case must "+
			"pass before a denial on different input proves anything", allowResp.GetEffect(), allowResp.GetReason())
	}

	// The actual proof: a DIFFERENT input, same approval id, same
	// delegation/agent/subject/tool/verb — must deny.
	differentInputReq := escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, &approvalIDStr)
	differentInputReq.RawInput = differentInput
	denyResp, err := srv.Decide(t.Context(), differentInputReq)
	if err != nil {
		t.Fatalf("different-input retry Decide() error = %v", err)
	}
	t.Logf("Decide() with a valid approval but different input -> effect=%s reason=%q",
		denyResp.GetEffect(), denyResp.GetReason())
	if denyResp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("different-input retry Effect = %v, want EFFECT_DENY: an approval for one action must not "+
			"authorize a different one", denyResp.GetEffect())
	}
	if denyResp.GetDeniedLeg() != "delegation" {
		t.Errorf("DeniedLeg = %q, want %q", denyResp.GetDeniedLeg(), "delegation")
	}
	if denyResp.GetApprovalId() != "" {
		t.Errorf("ApprovalId = %q, want empty: a denied verification never mints a new approval", denyResp.GetApprovalId())
	}
	if n := countApprovals(t, tenant); n != 1 {
		t.Errorf("approvals rows for tenant = %d, want 1", n)
	}
}

// TestIntegration_Escalation_DepthTwoChainRoutesApprovalToRoot is proof 5:
// a depth-2 chain routes approval to the root principal, not the depth-1
// agent — C21, end to end rather than in a unit test. Mirrors
// internal/pdpgrpc/escalation_test.go's TestDecide_Escalation_
// RootPrincipalRoutesAroundIntermediateDelegate: a depth-0 (single-hop)
// chain's root IS its only hop, so it cannot distinguish "the root" from
// "the last hop" the way this depth-2 fixture can.
func TestIntegration_Escalation_DepthTwoChainRoutesApprovalToRoot(t *testing.T) {
	const tenant = "tenant-escalation-depth2-root-integration"
	const rootPrincipal = "root-human-depth2@example.com"
	const intermediatePrincipal = "intermediate-delegate-agent-identity"
	srv, signer := escalationServer(t, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "escalation-depth2-agent", models.TrustTierPlatformTrusted)

	escalateAt := models.ActionTierExternalComms
	now := time.Now().UTC().Truncate(time.Second)
	rootID, intermediateID, actingID := uuid.New(), uuid.New(), uuid.New()

	seedDelegation(t, &models.Delegation{
		ID: rootID, TenantID: tenant, UserID: rootPrincipal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive, EscalateAt: &escalateAt,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "depth-2 C21 proof: root", ExpiresAt: now.Add(time.Hour),
		RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
	seedDelegation(t, &models.Delegation{
		ID: intermediateID, TenantID: tenant, UserID: intermediatePrincipal, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "depth-2 C21 proof: intermediate", ExpiresAt: now.Add(time.Hour),
		ParentDelegationID: &rootID, RootDelegationID: rootID, Depth: 1, ChainAgentIDs: []uuid.UUID{agentID, agentID},
	})
	acting := seedDelegation(t, &models.Delegation{
		ID: actingID, TenantID: tenant, UserID: "acting-hop-identity", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "depth-2 C21 proof: acting", ExpiresAt: now.Add(time.Hour),
		ParentDelegationID: &intermediateID, RootDelegationID: rootID, Depth: 2, ChainAgentIDs: []uuid.UUID{agentID, agentID, agentID},
	})

	resp, err := srv.Decide(t.Context(), escalationDecideRequest(t, signer, acting.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("Decide() error = %v, want a response", err)
	}
	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("Effect = %v, want EFFECT_ESCALATE (reason: %s)", resp.GetEffect(), resp.GetReason())
	}
	approvalID, err := uuid.Parse(resp.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", resp.GetApprovalId(), err)
	}

	approval, err := store.New(testDB, tenant).LoadApproval(t.Context(), approvalID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	t.Logf("depth-2 escalation approval: root_principal=%q (want root %q, not intermediate %q)",
		approval.RootPrincipal, rootPrincipal, intermediatePrincipal)
	if approval.RootPrincipal != rootPrincipal {
		t.Fatalf("RootPrincipal = %q, want %q (the chain ROOT's UserID) — C21: routing to depth 1's %q "+
			"would let the chain approve itself", approval.RootPrincipal, rootPrincipal, intermediatePrincipal)
	}
}

// TestIntegration_Escalation_CrossTenantCannotReadOrApprove is proof 6: a
// second tenant can neither read nor approve the first tenant's approval —
// NotFound via RLS. Two independent checks, both against real Postgres:
// GetApproval (the actual read-only RPC a PEP would poll) through a Server
// scoped to tenant B returns NotFound for tenant A's approval id; a
// control-plane-shaped UPDATE issued with app.tenant_id set to tenant B
// affects zero rows for the same id, through testDB — the role that DOES
// hold UPDATE privilege (it owns the table), so what stops it here is RLS
// alone, never a grant (the grant's absence is
// TestIntegration_Approvals_ServingRoleCannotUpdate's separate proof, for
// the serving role). Binding constraint: "No WHERE tenant_id in any Go
// query; RLS is the only tenant boundary" — this is that boundary, proven
// at the one table Phase 5 adds.
func TestIntegration_Escalation_CrossTenantCannotReadOrApprove(t *testing.T) {
	const tenantA = "tenant-escalation-cross-a-integration"
	const tenantB = "tenant-escalation-cross-b-integration"
	const rootPrincipal = "root-cross-tenant@example.com"

	srvA, signer := escalationServer(t, tenantA)

	agentID := uuid.New()
	seedAgent(t, tenantA, agentID, "escalation-cross-tenant-agent", models.TrustTierPlatformTrusted)
	delegation := escalatingRootDelegation(t, tenantA, agentID, rootPrincipal, models.ActionTierDestructive, "cross-tenant proof")

	first, err := srvA.Decide(t.Context(), escalationDecideRequest(t, signer, delegation.ID, agentID, rootPrincipal, nil))
	if err != nil {
		t.Fatalf("first Decide() error = %v", err)
	}
	if first.GetEffect() != pdpgrpc.Effect_EFFECT_ESCALATE {
		t.Fatalf("first Effect = %v, want EFFECT_ESCALATE", first.GetEffect())
	}
	approvalID, err := uuid.Parse(first.GetApprovalId())
	if err != nil {
		t.Fatalf("ApprovalId = %q is not a valid UUID: %v", first.GetApprovalId(), err)
	}

	// Read: tenant B's own Server (its own store, scoped to tenantB, no
	// policy needed since GetApproval never evaluates one) asked for tenant
	// A's approval id.
	repoB := store.New(testDB, tenantB)
	// Tenant B's server trusts the same signing key and is handed the very
	// token the approval's own delegation holds, so the only thing left
	// between it and tenant A's row is the tenant boundary.
	srvB := pdpgrpc.NewServer(repoB, policy.NewMulti(repoB, escalationRegistry()),
		config.Config{TenantID: tenantB, MaxDepth: 5, ApprovalTTL: time.Hour, PrincipalAuthInsecure: true}, signer)
	_, err = srvB.GetApproval(t.Context(), &pdpgrpc.GetApprovalRequest{
		ApprovalId: approvalID.String(), Token: escalationToken(t, signer, delegation.ID)})
	if err == nil {
		t.Fatal("GetApproval() from tenant B for tenant A's approval id succeeded, want NotFound")
	}
	wantCode(t, err, codes.NotFound)
	t.Logf("GetApproval() from tenant B for tenant A's approval -> %v", err)

	// Approve: a control-plane-shaped UPDATE, issued with app.tenant_id set
	// to tenant B, targeting tenant A's approval id.
	withTenantTx(t, tenantB, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(),
			`UPDATE approvals SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE id = $2`,
			rootPrincipal, approvalID.String())
		if err != nil {
			t.Fatalf("cross-tenant UPDATE attempt: %v", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			t.Fatalf("RowsAffected: %v", err)
		}
		if n != 0 {
			t.Fatalf("cross-tenant UPDATE affected %d rows, want 0 (RLS must make tenant A's row invisible "+
				"to a connection scoped to tenant B)", n)
		}
	})
	t.Logf("UPDATE from tenant B against tenant A's approval id affected 0 rows")

	// Confirm the row is genuinely unchanged, read back through tenant A's
	// own store.
	stillPending, err := store.New(testDB, tenantA).LoadApproval(t.Context(), approvalID)
	if err != nil {
		t.Fatalf("LoadApproval(tenantA) after the cross-tenant attempts error = %v", err)
	}
	if stillPending.Status != "pending" || stillPending.ApprovedBy != nil {
		t.Errorf("approval after tenant B's attempts = %+v, want unchanged (status=pending, approved_by=nil)", stillPending)
	}
}
