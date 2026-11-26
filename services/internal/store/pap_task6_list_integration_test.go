//go:build integration

// Task 6's real-Postgres proof for the two list methods Tasks 4's write
// actions were keyed by an id nothing returned: ListApprovals and
// ListDelegations. A separate file from pap_task4_integration_test.go for the
// reason that file's own doc comment gives — this codebase prefers many small
// integration-test files over one growing monolith, and every package-level
// var and helper used here (papDB, seedAgent, singleHopDelegation,
// seedPendingApproval, ...) is already shared across every *_test.go in this
// package without an import.
//
// Two things live here that no sqlmock test can prove, and both are the
// reason this file exists rather than being folded into the unit tests:
//
//  1. stratium_pap can actually SELECT these two tables.
//     migrations/000016_stratium_pap_role grants it (`GRANT SELECT, INSERT,
//     UPDATE ON tool_catalog, approvals, delegations`), but a missing grant
//     is a runtime insufficient_privilege that every sqlmock test in this
//     package would sail straight past — sqlmock replays rows, it does not
//     ask Postgres for permission.
//  2. RLS, not a WHERE clause, is what scopes these lists to one tenant.
//     Neither query has a WHERE clause at all (asserted on the query text in
//     approval_test.go/delegation_test.go); this file is where that absence
//     is shown to be safe rather than merely intended.
package store_test

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/models"
)

// TestIntegration_ListApprovals_EveryStatusUnderThePAPRole is the live half
// of the "all statuses, not only pending" ruling (see
// internal/store.listApprovalsQuery's own doc comment): one approval is left
// pending and one is decided through the real DecideApproval write path, and
// both must come back. A pending-only filter would make the decided one
// unreachable through the admin plane forever — there is no
// GET /v1/approvals/{id} in this phase.
func TestIntegration_ListApprovals_EveryStatusUnderThePAPRole(t *testing.T) {
	const tenant = "tenant-pap-task6-list-approvals-integration"
	const rootPrincipal = "root-principal@example.com"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "list-approvals-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "list approvals")
	pending := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "list approvals pending")
	decided := seedPendingApproval(t, tenant, agentID, delegation, rootPrincipal, "list approvals decided")

	if _, err := repo.DecideApproval(t.Context(), decided.ID, true, rootPrincipal, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}

	listed, _, err := repo.ListApprovals(t.Context(), nil, 0)
	if err != nil {
		t.Fatalf("ListApprovals() error = %v", err)
	}

	byID := map[uuid.UUID]models.Approval{}
	for _, a := range listed {
		byID[a.ID] = a
	}
	if got, ok := byID[pending.ID]; !ok || got.Status != "pending" {
		t.Errorf("the pending approval is %v (present = %t), want status pending", got.Status, ok)
	}
	if got, ok := byID[decided.ID]; !ok || got.Status != "approved" {
		t.Errorf("the decided approval is %v (present = %t), want status approved: this list answers "+
			"/v1/approvals, not /v1/approvals/pending, and nothing else can reach a decided row", got.Status, ok)
	}
	// The digest survives the round trip through Postgres's bytea, which is
	// what the hex rendering on the wire is derived from.
	if got := byID[pending.ID]; got.InputDigest != pending.InputDigest {
		t.Errorf("InputDigest = %x, want %x", got.InputDigest, pending.InputDigest)
	}
}

// TestIntegration_ListDelegations_IncludesRevokedUnderThePAPRole: the list a
// revoke action is issued from must show the result of that action, or an
// operator has no way to confirm their own revocation landed.
func TestIntegration_ListDelegations_IncludesRevokedUnderThePAPRole(t *testing.T) {
	const tenant = "tenant-pap-task6-list-delegations-integration"
	repo := store.New(papDB, tenant)

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "list-delegations-agent", models.TrustTierUnverified)
	live := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "list delegations live")
	doomed := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "list delegations revoked")

	if _, err := repo.RevokeDelegation(t.Context(), doomed.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("RevokeDelegation() error = %v", err)
	}

	listed, _, err := repo.ListDelegations(t.Context(), nil, 0)
	if err != nil {
		t.Fatalf("ListDelegations() error = %v", err)
	}

	byID := map[uuid.UUID]models.Delegation{}
	for _, d := range listed {
		byID[d.ID] = d
	}
	if got, ok := byID[live.ID]; !ok || got.Revoked {
		t.Errorf("the live delegation is revoked = %t (present = %t), want present and not revoked", got.Revoked, ok)
	}
	if got, ok := byID[doomed.ID]; !ok || !got.Revoked {
		t.Errorf("the revoked delegation is revoked = %t (present = %t), want present and revoked", got.Revoked, ok)
	}
}

// TestIntegration_ListsAreScopedByRLSNotByAPredicate is the point of this
// whole file. Neither list query carries a WHERE clause of any kind, so if
// row-level security were not doing the work, every tenant's approvals and
// delegations would come back to every other tenant. Two tenants are seeded
// through the real production write paths and each Store must see exactly its
// own rows.
//
// This is also the honest answer to Task 6's own required mutation ("add a
// WHERE tenant_id predicate and confirm a test notices"): nothing notices,
// because the predicate would be redundant with the policy this test proves
// is already enforcing the boundary. Adding it changes no observable
// behaviour — it only moves the apparent source of the guarantee somewhere it
// is not, which is why the query-text assertions in approval_test.go and
// delegation_test.go exist alongside this one.
func TestIntegration_ListsAreScopedByRLSNotByAPredicate(t *testing.T) {
	const tenantA = "tenant-pap-task6-list-rls-a-integration"
	const tenantB = "tenant-pap-task6-list-rls-b-integration"
	const rootPrincipal = "root-principal@example.com"

	seed := func(tenant string) (uuid.UUID, uuid.UUID) {
		t.Helper()
		agentID := uuid.New()
		seedAgent(t, tenant, agentID, "rls-scope-agent-"+tenant, models.TrustTierUnverified)
		d := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "rls scope")
		a := seedPendingApproval(t, tenant, agentID, d, rootPrincipal, "rls scope "+tenant)
		return d.ID, a.ID
	}
	delegationA, approvalA := seed(tenantA)
	delegationB, approvalB := seed(tenantB)

	assertScoped := func(tenant string, wantDelegation, wantApproval, notDelegation, notApproval uuid.UUID) {
		t.Helper()
		repo := store.New(papDB, tenant)

		approvals, _, err := repo.ListApprovals(t.Context(), nil, 0)
		if err != nil {
			t.Fatalf("ListApprovals() as %s error = %v", tenant, err)
		}
		seen := map[uuid.UUID]bool{}
		for _, a := range approvals {
			seen[a.ID] = true
		}
		if !seen[wantApproval] {
			t.Errorf("ListApprovals() as %s is missing its own approval %s", tenant, wantApproval)
		}
		if seen[notApproval] {
			t.Errorf("ListApprovals() as %s returned ANOTHER TENANT'S approval %s: RLS is not scoping this query", tenant, notApproval)
		}

		delegations, _, err := repo.ListDelegations(t.Context(), nil, 0)
		if err != nil {
			t.Fatalf("ListDelegations() as %s error = %v", tenant, err)
		}
		seen = map[uuid.UUID]bool{}
		for _, d := range delegations {
			seen[d.ID] = true
		}
		if !seen[wantDelegation] {
			t.Errorf("ListDelegations() as %s is missing its own delegation %s", tenant, wantDelegation)
		}
		if seen[notDelegation] {
			t.Errorf("ListDelegations() as %s returned ANOTHER TENANT'S delegation %s: RLS is not scoping this query", tenant, notDelegation)
		}
	}
	assertScoped(tenantA, delegationA, approvalA, delegationB, approvalB)
	assertScoped(tenantB, delegationB, approvalB, delegationA, approvalA)
}
