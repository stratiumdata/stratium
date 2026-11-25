package store

import (
	"testing"

	"github.com/stratiumdata/stratium/pkg/models"
)

func TestAgentLoosens(t *testing.T) {
	type state struct {
		tier               models.AgentTrustTier
		enabled, suspended bool
	}
	base := state{tier: 1, enabled: true, suspended: false}
	tests := []struct {
		name     string
		old, new state
		loosens  bool
	}{
		{"unchanged", base, base, false},
		{"trust tier lowered", base, state{0, true, false}, false},
		{"suspended", base, state{1, true, true}, false},
		{"disabled", base, state{1, false, false}, false},
		{"trust tier raised", base, state{2, true, false}, true},
		{"resumed", state{1, true, true}, base, true},
		{"re-enabled", state{1, false, false}, base, true},
		{"suspended while raising the tier", base, state{3, true, true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := agentLoosens(tt.old.tier, tt.new.tier, tt.old.enabled, tt.new.enabled, tt.old.suspended, tt.new.suspended)
			if (reason != "") != tt.loosens {
				t.Errorf("agentLoosens() = %q, want loosens = %v", reason, tt.loosens)
			}
		})
	}
}

func TestLabelRuleLoosens(t *testing.T) {
	old := models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "SECRET"}
	tests := []struct {
		name    string
		new     models.ResourceLabelRule
		loosens bool
	}{
		{"unchanged", old, false},
		{"level raised", models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "TOP-SECRET"}, false},
		{"same level, other casing", models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "NATO", Level: "secret"}, false},
		{"level lowered", models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "nato", Level: "RESTRICTED"}, true},
		{"prefix moved", models.ResourceLabelRule{Prefix: "/other/", Hierarchy: "nato", Level: "SECRET"}, true},
		{"hierarchy changed", models.ResourceLabelRule{Prefix: "/data/", Hierarchy: "commercial", Level: "HIGHLY-CONFIDENTIAL"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if reason := labelRuleLoosens(old, tt.new); (reason != "") != tt.loosens {
				t.Errorf("labelRuleLoosens() = %q, want loosens = %v", reason, tt.loosens)
			}
		})
	}
}

func TestCatalogEntryLoosens(t *testing.T) {
	tier := func(t models.ActionTier) *models.ActionTier { return &t }
	str := func(s string) *string { return &s }
	old := models.ToolCatalogEntry{ToolName: "Deploy", ActionTier: tier(2), Verb: "deploy", ResourceField: str("target")}
	with := func(change func(*models.ToolCatalogEntry)) models.ToolCatalogEntry {
		e := old
		change(&e)
		return e
	}
	commandOnly := models.ToolCatalogEntry{ToolName: "Shell", CommandField: str("command")}
	tests := []struct {
		name     string
		old, new models.ToolCatalogEntry
		loosens  bool
	}{
		{"unchanged", old, with(func(*models.ToolCatalogEntry) {}), false},
		{"same values behind new pointers", old, with(func(e *models.ToolCatalogEntry) { e.ActionTier, e.ResourceField = tier(2), str("target") }), false},
		{"tier raised", old, with(func(e *models.ToolCatalogEntry) { e.ActionTier = tier(3) }), false},
		{"tier lowered", old, with(func(e *models.ToolCatalogEntry) { e.ActionTier = tier(1) }), true},
		{"tier cleared", old, with(func(e *models.ToolCatalogEntry) { e.ActionTier, e.CommandField = nil, str("cmd") }), true},
		{"renamed", old, with(func(e *models.ToolCatalogEntry) { e.ToolName = "Other" }), true},
		{"verb changed", old, with(func(e *models.ToolCatalogEntry) { e.Verb = "read" }), true},
		{"resource field changed", old, with(func(e *models.ToolCatalogEntry) { e.ResourceField = str("note") }), true},
		{"resource field removed", old, with(func(e *models.ToolCatalogEntry) { e.ResourceField = nil }), true},
		{"command field added", old, with(func(e *models.ToolCatalogEntry) { e.CommandField = str("cmd") }), true},
		{"command-only entry unchanged", commandOnly, commandOnly, false},
		{"command-only entry given a fixed tier", commandOnly, models.ToolCatalogEntry{ToolName: "Shell", ActionTier: tier(4), CommandField: str("command")}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if reason := catalogEntryLoosens(tt.old, tt.new); (reason != "") != tt.loosens {
				t.Errorf("catalogEntryLoosens() = %q, want loosens = %v", reason, tt.loosens)
			}
		})
	}
}
