package main

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/models"
)

// TestEffective_UnionsOnlyLiveRootDelegations pins the three filters that
// make the answer honest: revoked, expired, and non-root delegations do not
// contribute. A revoked delegation grants nothing, so counting it would
// overstate a principal's reach and train operators to ignore the report.
func TestEffective_UnionsOnlyLiveRootDelegations(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	child := uuidFor(t, "11111111-1111-1111-1111-111111111111")

	all := []models.Delegation{
		{UserID: "alice", MaxActionTier: models.ActionTierReadOnly,
			ApprovedTools: []string{"Read"}, ExpiresAt: now.Add(time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierExternalComms,
			ApprovedTools: []string{"Bash"}, ExpiresAt: now.Add(time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Delete"}, ExpiresAt: now.Add(time.Hour), Revoked: true},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Nuke"}, ExpiresAt: now.Add(-time.Hour)},
		{UserID: "alice", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Sub"}, ExpiresAt: now.Add(time.Hour),
			ParentDelegationID: &child},
		{UserID: "bob", MaxActionTier: models.ActionTierDestructive,
			ApprovedTools: []string{"Other"}, ExpiresAt: now.Add(time.Hour)},
	}

	got := effectiveFor(all, "alice", now)

	if got.Union.MaxTier != models.ActionTierExternalComms {
		t.Errorf("MaxTier = %s, want EXTERNAL_COMMS (revoked, expired, child and "+
			"other-principal rows must not contribute)", got.Union.MaxTier)
	}
	if got.DelegationsCounted != 2 {
		t.Errorf("DelegationsCounted = %d, want 2", got.DelegationsCounted)
	}
}

// A principal with no live delegations must return an empty grant, not an
// error and not an unrestricted one -- an empty tool list means UNRESTRICTED
// everywhere else in this system, so the count is what disambiguates.
func TestEffective_NoLiveDelegationsReturnsEmptyGrantAndZeroCount(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	got := effectiveFor(nil, "nobody", now)
	if got.DelegationsCounted != 0 {
		t.Errorf("DelegationsCounted = %d, want 0", got.DelegationsCounted)
	}
	if got.Union.MaxTier != models.ActionTierReasoning {
		t.Errorf("MaxTier = %s, want REASONING", got.Union.MaxTier)
	}
}

func TestEffective_RouteIsRegisteredAtViewer(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "GET /v1/principals/{id}/effective" {
			found = true
			if rt.MinRole != RoleViewer {
				t.Errorf("MinRole = %v, want RoleViewer", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("GET /v1/principals/{id}/effective is not in routeTable")
	}
}

func uuidFor(t *testing.T, s string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(s)
	if err != nil {
		t.Fatalf("parse uuid: %v", err)
	}
	return id
}
