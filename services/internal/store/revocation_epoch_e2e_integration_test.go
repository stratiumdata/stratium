//go:build integration

// Task 3's real-stack proof
// (.superpowers/sdd/2026-08-14-phase-12-revocation-epoch/task-3-brief.md):
// six properties Task 1 (migrations/000015_tenant_epoch_trigger,
// tenant_epoch_integration_test.go) and Task 2 (LoadTenantEpoch, Decide/
// CreateDelegation/IssueToken reading and returning it, server.go) built in
// isolation, now proven TOGETHER against a live PDP — a real gRPC Decide/
// CreateDelegation call observing what a raw SQL write and a raw SQL read
// already proved separately.
//
// Kept in its own file rather than folded into tenant_epoch_integration_
// test.go: that file's own proofs are deliberately store-layer-only (raw SQL
// writes, readTenantEpoch, no gRPC client) — see its header comment. Proofs
// 1-4 here dial epochPdpClient, the real PDP server package pdpgrpc
// implements, which is a different concern reusing the same table and the
// same shared fixtures (testDB, seedAgent, seedPolicy, seedDelegation,
// singleHopDelegation, mintToken, withTenantTx, readTenantEpoch,
// assertEpochBumped, tierPtr, seedToolCatalogEntry, insertPolicyQuery,
// seedPolicyPriority, ...) already shared, without an import, across every
// *_test.go file in this one package (store_test) — store_integration_
// test.go's own header comment explains why this file must be an external
// test package for the same reason: it dials epochPdpClient, which imports
// internal/pdpgrpc, and pdpgrpc imports internal/store.
//
// epochPdpClient/epochTenant (store_integration_test.go's own package-level
// vars) are a SEVENTH, dedicated PDP instance (deploy/docker/docker-
// compose.yml's pdp-epoch service), touched by nothing else in this
// package — not configuredTenant/pdpClient, store_integration_test.go's own
// TestEndToEnd tenant. Found live, not reasoned in advance, and it took TWO
// fixes together, not one: this file first used configuredTenant/pdpClient
// directly, and running it broke in both directions depending only on
// file-ordering — sorted before store_integration_test.go, its policy/
// audit-row seeds left configuredTenant no longer pristine by the time
// TestEndToEnd's own proof2_decide_denies_at_principal_leg and proof3_
// audit_row_written_and_chain_verifies ran (both assume zero policies and
// zero audit rows at that point); sorted after, TestEndToEnd's own LAST
// subtest (proof6_failed_audit_append_blocks_the_decision) had by then
// already, deliberately and irreversibly for the rest of the process,
// revoked stratium_app's INSERT on audit_chain.
//
// Switching to a dedicated tenant (this file's first fix) closed the FIRST
// failure mode but not the second: the audit_chain revoke is a ROLE-level
// grant, not tenant-scoped (pdp-resource's own compose comment states this
// explicitly), so it disables every PDP instance sharing that role —
// pdp-epoch included — the moment TestEndToEnd's last subtest has run, no
// matter which tenant a later call names. Confirmed live a second time:
// this file, already on epochTenant/epochPdpClient, still failed every
// live-RPC proof with "permission denied for table audit_chain" once its
// name sorted AFTER store_integration_test.go. The dedicated tenant and
// this file's own name — chosen to sort BEFORE store_integration_test.go,
// so every proof below runs to completion before TestEndToEnd's own last
// subtest ever executes — are both required, together; neither alone is
// sufficient. This is not a special case: catalog_integration_test.go,
// escalation_integration_test.go, extauthz_integration_test.go, and
// proxy_integration_test.go all already sort before store_integration_
// test.go too, for the identical, previously-implicit reason.
//
// Proof 5 (tenant isolation) and proof 6 (concurrency) need no live PDP at
// all — both are store-layer/trigger properties, like every proof in
// tenant_epoch_integration_test.go — so both use their own freshly
// dedicated tenant constants and testDB directly, following that file's own
// dedicated-tenant discipline, entirely independent of epochTenant too.
package store_test

import (
	"database/sql"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/pdpgrpc"
	"stratium/pkg/models"
)

// epochE2EChain builds a delegation chain hops+1 deep (depths 0..hops), one
// row per depth, each narrowing the previous by one level — twoHopChain's
// own two-row shape (store_integration_test.go), generalized because proof
// 4 below needs "denies every descendant, proven at depth" to mean
// genuinely deeper than the two-hop case C9's unit test and twoHopChain's
// own fixture already cover elsewhere in this suite. twoHopChain itself is
// left untouched — many existing subtests depend on its fixed two-row
// shape, and this package's convention is many small, single-purpose
// helpers, not one generalized enough to serve every caller retroactively.
func epochE2EChain(t *testing.T, tenant string, agentID uuid.UUID, hops int) []*models.Delegation {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootID := uuid.New()
	chain := make([]*models.Delegation, 0, hops+1)
	var parentID *uuid.UUID
	for depth := 0; depth <= hops; depth++ {
		id := rootID
		if depth > 0 {
			id = uuid.New()
		}
		chainAgentIDs := make([]uuid.UUID, depth+1)
		for i := range chainAgentIDs {
			chainAgentIDs[i] = agentID
		}
		d := seedDelegation(t, &models.Delegation{
			ID: id, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose:            fmt.Sprintf("integration test: epoch e2e chain, depth %d", depth),
			ExpiresAt:          now.Add(time.Hour),
			ParentDelegationID: parentID, RootDelegationID: rootID, Depth: depth,
			ChainAgentIDs: chainAgentIDs,
		})
		chain = append(chain, d)
		parentID = &id
	}
	return chain
}

// TestIntegration_RevocationEpoch_E2E_RevocationBumpsAndNextDecideDeniesAtDelegationLeg
// is proof 1: a control-plane UPDATE revoking a delegation bumps
// epochTenant's epoch, and the very next Decide call — same token, same
// request — both reports the new epoch and denies at the delegation leg.
// This is spec §4.8's cascade property (V4: DelegationLeg already checks
// Revoked; the epoch is what makes that fact observable to a future cache
// rather than only to the live path), the first time it is proven through
// the real Decide RPC rather than a raw SQL read.
//
// The revocation is a raw SQL UPDATE, not a PDP call: the PDP holds no
// UPDATE grant on delegations (spec E7/V4 — see this task's own brief), so
// this is the only way a real revocation happens in this system today,
// exactly as tenant_epoch_integration_test.go's own delegations subtest
// revokes.
func TestIntegration_RevocationEpoch_E2E_RevocationBumpsAndNextDecideDeniesAtDelegationLeg(t *testing.T) {
	const subject = "epoch-e2e-proof1@example.com"
	agentID := uuid.New()
	seedAgent(t, epochTenant, agentID, "integration-agent-epoch-proof1", models.TrustTierUnverified)
	seedPolicy(t, epochTenant, "epoch-proof1-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	delegation := singleHopDelegation(t, epochTenant, agentID, models.ActionTierInternalModify,
		"integration test: epoch e2e proof 1 (revocation cascade)")
	token := mintToken(t, epochPdpClient, delegation.ID)

	decideReq := &pdpgrpc.DecideRequest{Token: token, AgentId: agentID.String(), Subject: subject, Tool: "Read"}

	baseline, err := epochPdpClient.Decide(t.Context(), decideReq)
	if err != nil {
		t.Fatalf("Decide() (baseline) error = %v", err)
	}
	if baseline.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide() (baseline) effect = %v, want EFFECT_ALLOW — the fixture must be clean before "+
			"the revocation below is what denies", baseline.GetEffect())
	}
	before := baseline.GetEpoch()

	withTenantTx(t, epochTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, delegation.ID.String()); err != nil {
			t.Fatalf("UPDATE delegations (revoke): %v", err)
		}
	})

	next, err := epochPdpClient.Decide(t.Context(), decideReq)
	if err != nil {
		t.Fatalf("Decide() (after revocation) error = %v", err)
	}

	if got := next.GetEpoch(); got <= before {
		t.Fatalf("Decide() epoch after revocation = %d, want > %d — the very next Decide must report the bump", got, before)
	}
	if next.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Decide() effect after revocation = %v, want EFFECT_DENY", next.GetEffect())
	}
	if next.GetDeniedLeg() != "delegation" {
		t.Errorf("Decide() denied_leg after revocation = %q, want %q", next.GetDeniedLeg(), "delegation")
	}
	if next.GetDeniedAtDepth() != 0 {
		t.Errorf("Decide() denied_at_depth after revocation = %d, want 0 (the revoked delegation is the root of a single-hop chain)",
			next.GetDeniedAtDepth())
	}

	// Cross-checked against an independent raw read, not just the response's
	// own field: a response that echoed some plausible-looking number
	// unrelated to tenant_epoch itself would otherwise pass the checks
	// above undetected. See proof 3's own doc comment for the fuller
	// argument against trusting a wire value alone.
	if raw, exists := readTenantEpoch(t, epochTenant); !exists || raw != next.GetEpoch() {
		t.Errorf("raw tenant_epoch read = %d (exists=%v), want %d to match Decide()'s own reported epoch",
			raw, exists, next.GetEpoch())
	}
}

// TestIntegration_RevocationEpoch_E2E_GovernedWritesObservedAcrossLiveDecideCalls
// is proof 2: suspending an agent, changing a policy, and adding a
// tool_catalog row each bump epochTenant's epoch, observed the same way
// proof 1 observes a revocation — through the epoch a live Decide call
// actually reports, not a raw SQL read of tenant_epoch. Task 1's own
// BumpsOnGovernedTableWrites already proves each of these three writes
// bumps the counter at the store/trigger layer; this proof's job is
// narrower and specific to Task 3: prove the SAME three writes are visible
// through the wire response a future cache would actually consult.
//
// One agent/delegation/token fixture, reused across all three steps rather
// than three separate ones: nothing after the first step (suspending the
// agent) needs Decide's Effect to still be ALLOW — only Epoch is under
// test here — so there is no reason to pay for three independent setups.
func TestIntegration_RevocationEpoch_E2E_GovernedWritesObservedAcrossLiveDecideCalls(t *testing.T) {
	const subject = "epoch-e2e-proof2@example.com"
	agentID := uuid.New()
	seedAgent(t, epochTenant, agentID, "integration-agent-epoch-proof2", models.TrustTierUnverified)
	policyID := seedPolicy(t, epochTenant, "epoch-proof2-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	delegation := singleHopDelegation(t, epochTenant, agentID, models.ActionTierInternalModify,
		"integration test: epoch e2e proof 2 (governed writes)")
	token := mintToken(t, epochPdpClient, delegation.ID)
	decideReq := &pdpgrpc.DecideRequest{Token: token, AgentId: agentID.String(), Subject: subject, Tool: "Read"}

	decide := func(step string) int64 {
		t.Helper()
		resp, err := epochPdpClient.Decide(t.Context(), decideReq)
		if err != nil {
			t.Fatalf("Decide() (%s) error = %v", step, err)
		}
		return resp.GetEpoch()
	}

	epoch := decide("baseline")

	t.Run("suspending_the_agent_bumps_it", func(t *testing.T) {
		withTenantTx(t, epochTenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE agents SET suspended = true WHERE id = $1`, agentID.String()); err != nil {
				t.Fatalf("UPDATE agents (suspend): %v", err)
			}
		})
		next := decide("after agent suspend")
		if next <= epoch {
			t.Fatalf("epoch = %d, want > %d after suspending the agent", next, epoch)
		}
		epoch = next
	})

	t.Run("changing_a_policy_bumps_it", func(t *testing.T) {
		withTenantTx(t, epochTenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), `UPDATE policies SET description = $1 WHERE id = $2`,
				"epoch-e2e-proof2-changed", policyID); err != nil {
				t.Fatalf("UPDATE policies: %v", err)
			}
		})
		next := decide("after policy change")
		if next <= epoch {
			t.Fatalf("epoch = %d, want > %d after changing a policy", next, epoch)
		}
		epoch = next
	})

	t.Run("adding_a_catalog_row_bumps_it", func(t *testing.T) {
		resourceField := "epoch_e2e_proof2_field"
		seedToolCatalogEntry(t, epochTenant, "EpochE2EProof2Tool", tierPtr(models.ActionTierReadOnly),
			"read", &resourceField, nil)
		next := decide("after catalog insert")
		if next <= epoch {
			t.Fatalf("epoch = %d, want > %d after adding a tool_catalog row", next, epoch)
		}
		epoch = next
	})

	// Close the loop against an independent raw read once, at the end,
	// rather than after each step: the point is to confirm the wire values
	// above were never disconnected from the real counter, not to re-derive
	// three separate deltas a raw read would only duplicate.
	if raw, exists := readTenantEpoch(t, epochTenant); !exists || raw != epoch {
		t.Errorf("raw tenant_epoch read = %d (exists=%v), want %d to match the last Decide()'s own reported epoch",
			raw, exists, epoch)
	}
}

// TestIntegration_RevocationEpoch_E2E_CreateDelegationDoesNotBump is proof
// 3: creating a delegation through the real CreateDelegation RPC — the
// production write path, not tenant_epoch_integration_test.go's raw SQL
// INSERT (TestIntegration_TenantEpoch_DelegationInsertDoesNotBump, which
// already covers that path) — must not bump the epoch. This is Task 1's
// deliberate narrowing (delegations bumps on UPDATE/DELETE only, never
// INSERT) observed through the one path a real PEP actually uses.
//
// Two sequential CreateDelegation calls bracket the write under test:
// CreateDelegation reads the epoch FIRST (spec V3, before its own INSERT),
// so the first call's own response epoch cannot yet reflect anything its
// own insert does. The second call's response epoch, read at the START of
// the second call — after the first call's insert has already committed —
// is what actually tells us whether that insert bumped anything in
// between. Equal means it did not.
//
// Cross-checked against an independent raw read of tenant_epoch around each
// call, not just the two responses' own Epoch fields: if CreateDelegation
// ever returned some fixed or otherwise-disconnected number, comparing it
// only to itself would pass by construction regardless of what the trigger
// actually did — the same tautology risk a unit test comparing a constant
// against itself has (Task 2's own bonus mutation 2 found exactly this
// shape of gap at the sqlmock layer; this proof does not get to lean on a
// real Postgres elsewhere the way that fix did, since Postgres IS what this
// proof is against — so the independent check has to live here instead).
func TestIntegration_RevocationEpoch_E2E_CreateDelegationDoesNotBump(t *testing.T) {
	const subject = "epoch-e2e-proof3@example.com"
	agentID := uuid.New()
	seedAgent(t, epochTenant, agentID, "integration-agent-epoch-proof3", models.TrustTierUnverified)
	seedPolicy(t, epochTenant, "epoch-proof3-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")

	newReq := func(purpose string) *pdpgrpc.CreateDelegationRequest {
		return &pdpgrpc.CreateDelegationRequest{
			Subject: subject,
			AgentId: agentID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierReadOnly),
				Tools:         []string{"Read"},
			},
			Purpose:    purpose,
			TtlSeconds: 3600,
		}
	}

	first, err := epochPdpClient.CreateDelegation(t.Context(), newReq("integration test: epoch e2e proof 3, first create"))
	if err != nil {
		t.Fatalf("CreateDelegation() (first) error = %v, want a response — a blanket permit for this subject must clamp to nothing", err)
	}
	before := first.GetEpoch()
	rawBefore, existsBefore := readTenantEpoch(t, epochTenant)
	if !existsBefore || rawBefore != before {
		t.Fatalf("raw tenant_epoch read = %d (exists=%v) right after the first CreateDelegation, want %d to match its own reported epoch",
			rawBefore, existsBefore, before)
	}

	second, err := epochPdpClient.CreateDelegation(t.Context(), newReq("integration test: epoch e2e proof 3, second create"))
	if err != nil {
		t.Fatalf("CreateDelegation() (second) error = %v", err)
	}
	after := second.GetEpoch()
	rawAfter, existsAfter := readTenantEpoch(t, epochTenant)
	if !existsAfter {
		t.Fatalf("tenant_epoch row for %s vanished between the two CreateDelegation calls", epochTenant)
	}

	if after != before {
		t.Fatalf("epoch = %d after a real CreateDelegation call, want unchanged at %d — "+
			"creating a delegation must never bump (Task 1's deliberate narrowing)", after, before)
	}
	if rawAfter != rawBefore {
		t.Fatalf("raw tenant_epoch read = %d after the second call's own start (which followed the first call's "+
			"insert), want unchanged at %d — independent of what either response claims", rawAfter, rawBefore)
	}
}

// TestIntegration_RevocationEpoch_E2E_RevokedRootBumpsOnceAndDeniesEveryDescendantAtDepth
// is proof 4: revoking a root delegation in a chain deeper than the two-hop
// fixtures used elsewhere in this suite (twoHopChain, C9's own unit test)
// bumps the epoch exactly once, and every descendant — not merely the
// deepest one — is denied by the very next Decide call, each attributed to
// depth 0 (the root), never to the depth of the descendant presenting the
// token.
//
// DelegationLeg (internal/authz/delegation.go) already checks Revoked at
// every hop, root-first, and returns on the FIRST hop that fails — so a
// revoked root denies the whole chain regardless of how deep it runs. That
// is existing behaviour (spec V4), true on the live path before this phase
// touched anything; this proof does not exercise new denial logic. What IS
// new, and what this proof actually adds beyond C9's own unit-level check
// of a one-child chain, is: the same revoking UPDATE now also bumps the
// epoch once (Task 1), and every one of those denials — at three different
// presenting depths — reports that identical, single bump (Task 2),
// together making the cascade observable to a future cache rather than
// only to whichever descendant happens to be tested.
func TestIntegration_RevocationEpoch_E2E_RevokedRootBumpsOnceAndDeniesEveryDescendantAtDepth(t *testing.T) {
	const hops = 3
	const subject = "epoch-e2e-proof4@example.com"
	agentID := uuid.New()
	seedAgent(t, epochTenant, agentID, "integration-agent-epoch-proof4", models.TrustTierUnverified)
	seedPolicy(t, epochTenant, "epoch-proof4-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")

	chain := epochE2EChain(t, epochTenant, agentID, hops)
	root := chain[0]

	// Minted before revoking, not after: IssueToken re-issuance checks only
	// the NAMED row's own liveness (store.LoadDelegation, never the full
	// chain — see that method's own doc comment), so minting order relative
	// to the root's revocation cannot matter functionally. Minting first
	// just keeps this test's timeline the same shape a real PEP's would be:
	// sessions established, then the root revoked out from under all of
	// them at once.
	tokens := make([]string, hops+1)
	for depth := 1; depth <= hops; depth++ {
		tokens[depth] = mintToken(t, epochPdpClient, chain[depth].ID)
	}

	before, existsBefore := readTenantEpoch(t, epochTenant)
	if !existsBefore {
		t.Fatalf("tenant_epoch row for %s does not exist before proof 4's revocation", epochTenant)
	}

	withTenantTx(t, epochTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, root.ID.String()); err != nil {
			t.Fatalf("UPDATE delegations (revoke root): %v", err)
		}
	})

	// "Bumps once": one UPDATE statement touching one row must produce
	// exactly one increment — TestIntegration_TenantEpoch_
	// TwoWritesInOneTransactionBumpTwice (tenant_epoch_integration_test.go)
	// already pins the multi-write case; this is its single-write
	// counterpart, checked here because the rest of this proof depends on
	// there being exactly one bump to attribute every subsequent Decide
	// call's epoch to.
	after, existsAfter := readTenantEpoch(t, epochTenant)
	if !existsAfter {
		t.Fatalf("tenant_epoch row for %s vanished after revoking the root", epochTenant)
	}
	if want := before + 1; after != want {
		t.Fatalf("epoch after revoking the root once = %d, want exactly %d (before=%d + 1)", after, want, before)
	}

	for depth := 1; depth <= hops; depth++ {
		resp, err := epochPdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: tokens[depth], AgentId: agentID.String(), Subject: subject, Tool: "Read",
		})
		if err != nil {
			t.Fatalf("Decide() at depth %d error = %v", depth, err)
		}
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("Decide() at depth %d effect = %v, want EFFECT_DENY — a revoked root must deny every descendant",
				depth, resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("Decide() at depth %d denied_leg = %q, want %q", depth, resp.GetDeniedLeg(), "delegation")
		}
		// The depth asserted is 0 (the root), never `depth` (the presenting
		// descendant): DelegationLeg iterates root-first and returns on the
		// FIRST hop whose own Revoked is true, which is the root here no
		// matter which descendant's token presented the chain. That
		// specific fact — not merely "some deny happened somewhere in the
		// chain" — is what "proven at depth" means for this proof.
		if resp.GetDeniedAtDepth() != 0 {
			t.Errorf("Decide() at depth %d denied_at_depth = %d, want 0 (the revoked root, not the presenting hop)",
				depth, resp.GetDeniedAtDepth())
		}
		if got := resp.GetEpoch(); got != after {
			t.Errorf("Decide() at depth %d epoch = %d, want %d (the single bump from revoking the root)", depth, got, after)
		}
	}
}

// TestIntegration_RevocationEpoch_E2E_TwoTenantsMoveIndependently is proof
// 5: a write in one tenant does not move another tenant's epoch. This is
// the tenancy property, and per this task's own brief it is the single most
// plausible thing for the trigger to get wrong — a trigger that resolved
// the tenant incorrectly would invalidate every tenant's cache on any
// write, and nothing else about it would fail, since every other proof in
// this file and in tenant_epoch_integration_test.go only ever looks at one
// tenant at a time.
//
// Two freshly dedicated tenants, touched by nothing else in this package —
// tenant_epoch_integration_test.go's own dedicated-tenant discipline, not
// epochTenant/configuredTenant/secondTenantID (all shared with other
// subtests, which would make "did tenant B change" ambiguous against
// writes this test does not control).
//
// No live PDP needed: this is a trigger/store-layer property, proven the
// same way every proof in tenant_epoch_integration_test.go is, via raw SQL
// and readTenantEpoch.
func TestIntegration_RevocationEpoch_E2E_TwoTenantsMoveIndependently(t *testing.T) {
	const tenantA = "tenant-epoch-e2e-isolation-a-integration"
	const tenantB = "tenant-epoch-e2e-isolation-b-integration"

	// Establish both tenants' rows first, each via its own governed write,
	// so both starting points are known values rather than "no row yet" —
	// which would leave a subsequent bump ambiguous with create-on-demand.
	seedPolicy(t, tenantA, "epoch-e2e-isolation-seed-a", "permit(principal, action, resource);", "allow")
	seedPolicy(t, tenantB, "epoch-e2e-isolation-seed-b", "permit(principal, action, resource);", "allow")

	beforeA, existsA := readTenantEpoch(t, tenantA)
	if !existsA {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding it", tenantA)
	}
	beforeB, existsB := readTenantEpoch(t, tenantB)
	if !existsB {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding it", tenantB)
	}

	// The write under test: tenant A only.
	seedPolicy(t, tenantA, "epoch-e2e-isolation-second-write-a", "permit(principal, action, resource);", "allow")

	assertEpochBumped(t, tenantA, beforeA)

	afterB, existsB2 := readTenantEpoch(t, tenantB)
	if !existsB2 {
		t.Fatalf("tenant_epoch row for %s vanished", tenantB)
	}
	if afterB != beforeB {
		t.Fatalf("tenant %s epoch = %d after a write to tenant %s only, want unchanged at %d — "+
			"the trigger resolved the wrong tenant", tenantB, afterB, tenantA, beforeB)
	}
}

// TestIntegration_RevocationEpoch_E2E_MonotonicUnderConcurrentWrites is
// proof 6: ten concurrent writers, each in its own transaction against the
// same tenant, bump the epoch to a strictly increasing sequence with no
// value reused, skipped, or lost.
//
// Reuses the audit suite's concurrency SHAPE (AppendAudit's own doc
// comment; the interleaved-burst subtest in store_integration_test.go): N
// goroutines gated behind one shared start channel, released together,
// collected via a WaitGroup. Deliberately does NOT reuse
// pg_advisory_xact_lock itself — that lock exists to serialize
// AppendAudit's own read-then-link-then-insert sequence across DIFFERENT
// rows (the hash chain's tail), a problem this counter does not have.
// tenant_epoch's own bump is a single-row UPSERT (migrations/000015_
// tenant_epoch_trigger: `SET epoch = tenant_epoch.epoch + 1`), and Postgres
// already serializes concurrent writers to the SAME row via that row's own
// lock, re-evaluating the SET expression against the current value once a
// blocked writer's lock is granted (EvalPlanQual, per that migration's own
// comment) — a manual advisory lock here would only re-implement a
// guarantee the UPSERT already has for free. What this proof adds beyond
// Task 1's own sequential tests (TwoWritesInOneTransactionBumpTwice,
// BumpsAreMonotonicAcrossManyWrites — both one write at a time, one
// transaction fully committed before the next begins) is TRUE
// cross-transaction concurrency: ten writers actually in flight against the
// trigger at once, which Task 2's own report explicitly declined to build
// at the store layer ("Not built, and why" — a real goroutine-based
// concurrency test against the live trigger). This is that test.
//
// Each goroutine captures the epoch value ITS OWN transaction produced by
// reading tenant_epoch from inside that same transaction, immediately after
// its own governed write and before commit — safe under read committed
// specifically because the row lock the UPSERT already holds guarantees
// that read sees exactly what that transaction's own increment wrote, not a
// value some other concurrent writer's increment produced.
func TestIntegration_RevocationEpoch_E2E_MonotonicUnderConcurrentWrites(t *testing.T) {
	const tenant = "tenant-epoch-e2e-concurrent-integration"
	const n = 10

	seedPolicy(t, tenant, "epoch-e2e-concurrent-seed", "permit(principal, action, resource);", "allow")
	before, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist after seeding it", tenant)
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]int64, n)
	errs := make([]error, n)

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start

			tx, err := testDB.BeginTx(t.Context(), nil)
			if err != nil {
				errs[i] = fmt.Errorf("begin tx: %w", err)
				return
			}
			defer func() { _ = tx.Rollback() }()

			if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
				errs[i] = fmt.Errorf("set_config: %w", err)
				return
			}
			if _, err := tx.ExecContext(t.Context(), insertPolicyQuery,
				uuid.New().String(), tenant, fmt.Sprintf("epoch-e2e-concurrent-%d", i), "cedar",
				"permit(principal, action, resource);", "allow", true, seedPolicyPriority,
			); err != nil {
				errs[i] = fmt.Errorf("insert policy %d: %w", i, err)
				return
			}

			var got int64
			if err := tx.QueryRowContext(t.Context(),
				`SELECT epoch FROM tenant_epoch WHERE tenant_id = $1`, tenant).Scan(&got); err != nil {
				errs[i] = fmt.Errorf("read epoch mid-transaction: %w", err)
				return
			}
			if err := tx.Commit(); err != nil {
				errs[i] = fmt.Errorf("commit: %w", err)
				return
			}
			results[i] = got
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent writer %d: %v", i, err)
		}
	}

	after, exists := readTenantEpoch(t, tenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s vanished after the concurrent burst", tenant)
	}
	if want := before + n; after != want {
		t.Fatalf("epoch after %d concurrent writers = %d, want exactly %d (before=%d + %d) — a bump was lost", n, after, want, before, n)
	}

	sorted := append([]int64(nil), results...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	for i, got := range sorted {
		want := before + int64(i) + 1
		if got != want {
			t.Fatalf("concurrent bump #%d (sorted ascending) = %d, want %d — a value was reused, skipped, or lost under concurrency",
				i, got, want)
		}
	}
}
