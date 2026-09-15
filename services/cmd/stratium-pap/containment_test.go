package main

import (
	"testing"
	"time"

	"stratium/pkg/models"
	"stratium/pkg/permset"
)

func TestContainment_ReportsContainedAndNot(t *testing.T) {
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	baseline := permset.Set{
		Tools: []string{"Read", "Write"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}
	narrower := permset.Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly, ExpiresAt: at,
	}
	wider := permset.Set{
		Tools: []string{"Read", "Bash"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}

	if got := containmentOf(baseline, narrower); !got.Contained || got.Reason != "" {
		t.Errorf("narrower candidate must be contained, got %+v", got)
	}
	got := containmentOf(baseline, wider)
	if got.Contained {
		t.Error("a candidate adding a tool must not be contained")
	}
	if got.Reason != "child tool Bash not in parent approved_tools" {
		t.Errorf("Reason = %q, want the tool reason verbatim", got.Reason)
	}
}

func TestContainment_RouteIsRegisteredAtViewer(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "POST /v1/containment" {
			found = true
			if rt.MinRole != RoleViewer {
				t.Errorf("MinRole = %v, want RoleViewer: this endpoint reads, it does not write", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("POST /v1/containment is not in routeTable")
	}
}
