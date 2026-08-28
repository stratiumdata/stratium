//go:build integration

// Task 4's real-Postgres proof for E7 (approvals) and V4 (delegation
// revocation) -- migrations/000013_tool_catalog's own T1 proof lives in
// catalog_integration_test.go instead, alongside Task 1's existing coverage
// of that same table, rather than a third file for a table already proven
// live elsewhere. A separate file from pap_role_integration_test.go (Task
// 2's own grant proofs) and pap_crud_integration_test.go (Task 3's CRUD
// round trips), the same reasoning escalation_integration_test.go's own
// doc comment gives at length for why this codebase prefers many small
// integration-test files over one growing monolith: every package-level
// var and helper this file uses (testDB, servingDB, papDB, seedAgent,
// singleHopDelegation, twoHopChain, readTenantEpoch, assertEpochBumped,
// fetchAuditChain, withTenantTx, ...) is already shared across every
// *_test.go file in this one package without an import.
package store_test

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/internal/store"
	"stratium/pkg/models"
)

// seedPendingApproval creates one pending approvals row through the real
// production write path (store.CreateApproval, via papDB -- the same
// connection every write in this file exercises), naming rootPrincipal as
// the only identity N7 will ever accept for it. Returns the approval so
// callers can read its own id back without a separate query.
func seedPendingApproval(t *testing.T, tenant string, agentID uuid.UUID, delegation *models.Delegation, rootPrincipal, seed string) *models.Approval {
	t.Helper()
	a := &models.Approval{
		ID: uuid.New(), AgentID: agentID, DelegationID: delegation.ID, RootDelegationID: delegation.ID,
		Subject: "requesting-subject", RootPrincipal: rootPrincipal,
		ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierExternalComms,
		InputDigest: sha256.Sum256([]byte(seed)),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := store.New(papDB, tenant).CreateApproval(t.Context(), a); err != nil {
		t.Fatalf("CreateApproval() error = %v", err)
	}
	return a
}

// TestIntegration_DecideApproval_RoundTrip is E7's own positive proof, live:
// an operator whose identity equals root_principal approves through the
// real stratium_pap connection, and the row round-trips exactly what N7
// requires (status, approved_by == root_principal, approved_at set).
func TestIntegration_DecideApproval_RoundTrip(t *testing.T) {
	const tenant = "tenant-pap-task4-decide-approval-roundtrip-integration"
	const rootPrincipal = "root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "decide-approval-roundtrip-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "decide approval round trip")
	approval := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "decide approval round trip")

	got, err := repo.DecideApproval(t.Context(), approval.ID, true, rootPrincipal, "integration-operator", time.Now())
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if got.Status != "approved" {
		t.Fatalf("Status = %q, want %q", got.Status, "approved")
	}
	if got.ApprovedBy == nil || *got.ApprovedBy != rootPrincipal {
		t.Fatalf("ApprovedBy = %v, want %q", got.ApprovedBy, rootPrincipal)
	}

	reloaded, err := store.New(testDB, tenant).LoadApproval(t.Context(), approval.ID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	if reloaded.Status != "approved" {
		t.Fatalf("reloaded Status = %q, want %q", reloaded.Status, "approved")
	}

	// The row this produced would actually satisfy the PDP's own
	// consumption-time check (models.Approval.Verify) -- proven in-process
	// here (pure Go, no PDP container needed) rather than assumed, since
	// this is the write path Verify's own comparisons depend on being
	// correct. Full end-to-end proof through a live PDP retry is Task 7's
	// stated scope ("approving an escalation through the PAP lets the
	// agent's retry succeed -- E7 end to end"), not this task's.
	if reason := reloaded.Verify(rootPrincipal, agentID, delegation.ID, "Bash", "execute",
		models.ActionTierExternalComms, approval.InputDigest, time.Now()); reason != "" {
		t.Errorf("Verify() = %q, want \"\" (the PDP's own consumption-time check must accept this decision)", reason)
	}

	assertAuditTrailMatches(t, tenant, "integration-operator", "approval_approved")
}

// TestIntegration_DecideApproval_WrongApproverRefused_Live is N7's own
// required, live test (task brief: "one whose identity does not [match] is
// refused... that is N7 and it needs its own test") -- proven here against
// the real stratium_pap role and a real transaction, not only sqlmock's
// simulated one. The row is confirmed UNCHANGED afterward: a refused
// decision must persist nothing, matching this task's own "fail closed"
// binding constraint.
func TestIntegration_DecideApproval_WrongApproverRefused_Live(t *testing.T) {
	const tenant = "tenant-pap-task4-decide-approval-wrong-approver-integration"
	const rootPrincipal = "the-real-root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "wrong-approver-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "wrong approver proof")
	approval := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "wrong approver proof")

	_, err := repo.DecideApproval(t.Context(), approval.ID, true, "an-impostor@example.com", "integration-operator", time.Now())
	if !errors.Is(err, store.ErrApproverNotRootPrincipal) {
		t.Fatalf("DecideApproval() error = %v, want errors.Is(_, store.ErrApproverNotRootPrincipal)", err)
	}

	reloaded, err := store.New(testDB, tenant).LoadApproval(t.Context(), approval.ID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v", err)
	}
	if reloaded.Status != "pending" || reloaded.ApprovedBy != nil {
		t.Fatalf("approval after a refused decision = %+v, want unchanged (status=pending, approved_by=nil)", reloaded)
	}

	entries := fetchAuditChain(t, tenant)
	if len(entries) != 0 {
		t.Fatalf("audit_chain has %d entries after a refused decision, want 0 -- nothing was decided", len(entries))
	}
}

// TestIntegration_DecideApproval_ExplicitDeny_Live is the task brief's own
// required test, live: "an explicit deny records denied."
func TestIntegration_DecideApproval_ExplicitDeny_Live(t *testing.T) {
	const tenant = "tenant-pap-task4-decide-approval-deny-integration"
	const rootPrincipal = "root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "deny-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "explicit deny proof")
	approval := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "explicit deny proof")

	got, err := repo.DecideApproval(t.Context(), approval.ID, false, rootPrincipal, "integration-operator", time.Now())
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if got.Status != "denied" {
		t.Fatalf("Status = %q, want %q", got.Status, "denied")
	}

	// A denied approval must NOT satisfy the PDP's own consumption-time
	// check -- the direct negative counterpart of RoundTrip's own Verify
	// assertion above.
	if reason := got.Verify(rootPrincipal, agentID, delegation.ID, "Bash", "execute",
		models.ActionTierExternalComms, approval.InputDigest, time.Now()); reason == "" {
		t.Error("Verify() = \"\", want a refusal reason -- a denied approval must never verify as usable")
	}

	assertAuditTrailMatches(t, tenant, "integration-operator", "approval_denied")
}

// TestIntegration_RevokeDelegation_RoundTrip is V4's own write proof, live:
// revoked/revoked_at are set through the real stratium_pap connection, the
// write bumps tenant_epoch (unlike an approval decision -- see the
// consolidated comparison below), and the write is audited.
func TestIntegration_RevokeDelegation_RoundTrip(t *testing.T) {
	const tenant = "tenant-pap-task4-revoke-roundtrip-integration"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "revoke-roundtrip-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "revoke round trip proof")

	// Captured after seeding: seedAgent's own INSERT already bumped (agents
	// is a governed table) and singleHopDelegation's own INSERT does not
	// (V2 -- a brand new delegation invalidates no existing decision), so
	// this "before" reading isolates RevokeDelegation's own effect, or lack
	// of one.
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	got, err := repo.RevokeDelegation(t.Context(), delegation.ID, "integration-operator", time.Now())
	if err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}
	if !got.Revoked || got.RevokedAt == nil {
		t.Fatalf("RevokeDelegation() = %+v, want Revoked=true with RevokedAt set", got)
	}
	assertEpochBumped(t, tenant, before)

	reloaded, err := store.New(testDB, tenant).LoadDelegation(t.Context(), delegation.ID)
	if err != nil {
		t.Fatalf("LoadDelegation() error = %v", err)
	}
	if !reloaded.Revoked {
		t.Fatal("reloaded delegation is not revoked")
	}

	assertAuditTrailMatches(t, tenant, "integration-operator", "delegation_revoked")
}

// TestIntegration_RevokeDelegation_CascadeHoldsWithoutNewCode is the task
// brief's own required proof: "confirm cascade holds rather than
// implementing it -- revoking a root denies every descendant on the next
// action." Every step below except the revoke itself is EXISTING
// production code -- twoHopChain seeds real rows, LoadChain performs a
// real, unmodified read, and authz.DelegationLeg is internal/authz's own
// pure decision function, called here exactly as pdpgrpc.Server.Decide
// already calls it, completely untouched by this task ("internal/authz
// stays pure and is not touched" -- this task's own binding constraint).
// If cascade denial required any new code, this test would need to write
// some; it does not.
func TestIntegration_RevokeDelegation_CascadeHoldsWithoutNewCode(t *testing.T) {
	const tenant = "tenant-pap-task4-cascade-integration"
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "cascade-agent", models.TrustTierUnverified)
	root, child := twoHopChain(t, tenant, agentID)

	// Before revocation: the live chain allows (both hops are active,
	// well-formed, and within scope -- twoHopChain's own doc comment). This
	// is the negative control: without it, a DENY after revocation could be
	// explained by something else entirely (wrong tool, expired delegation)
	// rather than by REVOCATION specifically.
	before, err := store.New(testDB, tenant).LoadChain(t.Context(), child.ID)
	if err != nil {
		t.Fatalf("LoadChain() before revocation error = %v", err)
	}
	action := authz.Action{Tool: "Bash", Verb: "execute"}
	const maxDepth = 10
	preLeg, preDeniedDepth := authz.DelegationLeg(before, action, models.ActionTierInternalModify, nil, nil, time.Now(), maxDepth)
	if preLeg.Effect != authz.EffectAllow {
		t.Fatalf("test setup: DelegationLeg() before revocation = %v (%q), want EffectAllow -- "+
			"the chain must be unambiguously healthy before this test can attribute a later DENY to revocation specifically",
			preLeg.Effect, preLeg.Reason)
	}
	if preDeniedDepth != -1 {
		t.Fatalf("test setup: DelegationLeg() before revocation denied at depth %d, want -1 (no denial)", preDeniedDepth)
	}

	// The one write this task adds: revoke the ROOT, through the real
	// stratium_pap connection.
	if _, err := store.New(papDB, tenant).RevokeDelegation(t.Context(), root.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}

	// The next action: reload the chain fresh (exactly as a real Decide
	// call would -- store.LoadChain is not cached anywhere in this system)
	// and re-run the identical pure decision function.
	after, err := store.New(testDB, tenant).LoadChain(t.Context(), child.ID)
	if err != nil {
		t.Fatalf("LoadChain() after revocation error = %v", err)
	}
	if !after[0].Revoked {
		t.Fatalf("reloaded root delegation Revoked = false, want true -- the write above did not persist")
	}

	postLeg, postDeniedDepth := authz.DelegationLeg(after, action, models.ActionTierInternalModify, nil, nil, time.Now(), maxDepth)
	if postLeg.Effect != authz.EffectDeny {
		t.Fatalf("DelegationLeg() after revoking the root = %v (%q), want EffectDeny -- "+
			"the CHILD's own next action must be denied by the root's revocation, cascading through the chain "+
			"with no new authz code", postLeg.Effect, postLeg.Reason)
	}
	if postDeniedDepth != root.Depth {
		t.Errorf("DelegationLeg() denied at depth %d, want %d (the root's own depth -- the revoked hop, not some other one)",
			postDeniedDepth, root.Depth)
	}
	if !strings.Contains(postLeg.Reason, "revoked") {
		t.Errorf("DelegationLeg() reason = %q, want it to name the revocation specifically", postLeg.Reason)
	}
}

// TestIntegration_ApproveDecision_DoesNotBumpEpoch_WhileCatalogAndRevocationDo
// puts the task brief's own three-way comparison side by side in one test,
// on the SAME tenant, so the three deltas are directly comparable rather
// than three separate tests each trusting a different "before" reading:
// approving must NOT bump tenant_epoch (migrations/000015_tenant_epoch_
// trigger does not name approvals -- spec §4.10.1's own reasoning: "an
// approval does not change what an existing decision would evaluate to"),
// while a tool_catalog write and a delegation revocation both must.
func TestIntegration_ApproveDecision_DoesNotBumpEpoch_WhileCatalogAndRevocationDo(t *testing.T) {
	const tenant = "tenant-pap-task4-epoch-comparison-integration"
	const rootPrincipal = "root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "epoch-comparison-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "epoch comparison proof")
	approval := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "epoch comparison proof")

	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding", tenant)
	}

	if _, err := repo.DecideApproval(t.Context(), approval.ID, true, rootPrincipal, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	afterApprove, existsAfterApprove := readTenantEpoch(t, tenant)
	if !existsAfterApprove || afterApprove != before {
		t.Fatalf("epoch = %d (exists=%v) after DecideApproval, want unchanged at %d -- "+
			"approvals has no tenant_epoch trigger (migrations/000015 does not name it)", afterApprove, existsAfterApprove, before)
	}

	if _, err := repo.CreateToolCatalogEntry(t.Context(),
		models.ToolCatalogEntry{ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), Verb: "read"},
		"integration-operator", time.Now()); err != nil {
		t.Fatalf("CreateToolCatalogEntry() error = %v", err)
	}
	afterCatalog := assertEpochBumped(t, tenant, afterApprove)

	if _, err := repo.RevokeDelegation(t.Context(), delegation.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}
	assertEpochBumped(t, tenant, afterCatalog)
}

// TestIntegration_PAPTask4_AuditColumnsMatchEstablishedSentinelsLiterally is
// this task's own instance of the "structurally blind" pattern
// pap_crud_integration_test.go's TestIntegration_PAPCRUD_
// DeniedAtDepthMatchesTheEstablishedSentinel already found for Task 3:
// every assertion below reads the raw column back from Postgres against a
// HARDCODED literal, never against this package's own noDenial/eventType*/
// decision-string symbols, so a future drift in any of THOSE constants
// cannot silently carry a matching test expectation along with it the way
// comparing against the identical symbol on both sides would.
func TestIntegration_PAPTask4_AuditColumnsMatchEstablishedSentinelsLiterally(t *testing.T) {
	const tenant = "tenant-pap-task4-sentinel-integration"
	const rootPrincipal = "root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "sentinel-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "sentinel proof")
	approval := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "sentinel proof")

	if _, err := repo.DecideApproval(t.Context(), approval.ID, false, rootPrincipal, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if _, err := repo.RevokeDelegation(t.Context(), delegation.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}

	var denyDecision, revokeDecision string
	var denyDeniedAtDepth, revokeDeniedAtDepth int16
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT decision, denied_at_depth FROM audit_chain WHERE event_type = 'approval_denied' ORDER BY seq DESC LIMIT 1`,
		).Scan(&denyDecision, &denyDeniedAtDepth); err != nil {
			t.Fatalf("read back audit_chain row for the denied approval: %v", err)
		}
		if err := tx.QueryRowContext(t.Context(),
			`SELECT decision, denied_at_depth FROM audit_chain WHERE event_type = 'delegation_revoked' ORDER BY seq DESC LIMIT 1`,
		).Scan(&revokeDecision, &revokeDeniedAtDepth); err != nil {
			t.Fatalf("read back audit_chain row for the revoked delegation: %v", err)
		}
	})

	if denyDecision != "DENY" {
		t.Errorf("denied approval's audit_chain.decision = %q, want %q", denyDecision, "DENY")
	}
	if denyDeniedAtDepth != -1 {
		t.Errorf("denied approval's audit_chain.denied_at_depth = %d, want %d (hardcoded literal, not this package's own noDenial symbol)",
			denyDeniedAtDepth, -1)
	}
	if revokeDecision != "ALLOW" {
		t.Errorf("revoked delegation's audit_chain.decision = %q, want %q (the WRITE succeeded; this column is not describing "+
			"the delegation's own now-denied future decisions)", revokeDecision, "ALLOW")
	}
	if revokeDeniedAtDepth != -1 {
		t.Errorf("revoked delegation's audit_chain.denied_at_depth = %d, want %d", revokeDeniedAtDepth, -1)
	}
}
