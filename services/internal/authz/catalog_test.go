package authz

import (
	"errors"
	"testing"

	"stratium/pkg/models"
)

// Every seeded tool must derive its documented tier through DeriveTier (not
// just be present in the map with the right value) — DeriveTier is what a
// real decision calls, and lookupKeys/the resolution order sit between the
// map and the answer a caller actually gets.
func TestDeriveTier_SeededToolsDeriveExpectedTier(t *testing.T) {
	cases := map[string]models.ActionTier{
		"Read":         models.ActionTierReadOnly,
		"Glob":         models.ActionTierReadOnly,
		"Grep":         models.ActionTierReadOnly,
		"NotebookRead": models.ActionTierReadOnly,
		"LS":           models.ActionTierReadOnly,
		"WebFetch":     models.ActionTierReadOnly,
		"WebSearch":    models.ActionTierReadOnly,
		"Write":        models.ActionTierInternalModify,
		"Edit":         models.ActionTierInternalModify,
		"NotebookEdit": models.ActionTierInternalModify,
		"TodoWrite":    models.ActionTierInternalModify,
	}
	table := TierTable{Catalog: DefaultCatalog()}
	for tool, want := range cases {
		t.Run(tool, func(t *testing.T) {
			got, err := DeriveTier(table, Action{Tool: tool})
			if err != nil || got != want {
				t.Fatalf("tool %q: got %v, err %v; want %v", tool, got, err, want)
			}
		})
	}
}

// This is the regression the brief names explicitly: a catalog entry for
// Bash would make every shell command derive the same tier, silently
// undoing Phase 3b. Bash must have NO catalog entry and must still reach
// the command classifier — proven here through DeriveTier with the real
// DefaultCatalog() wired in, not through BuiltinTier in isolation, so a
// mutation that adds a "Bash" key to the catalog is actually caught.
func TestDeriveTier_BashHasNoCatalogEntry(t *testing.T) {
	table := TierTable{Catalog: DefaultCatalog()}
	cases := map[string]models.ActionTier{
		"rm -rf /": models.ActionTierDestructive,
		"ls -la":   models.ActionTierReadOnly,
	}
	for cmd, want := range cases {
		t.Run(cmd, func(t *testing.T) {
			got, err := DeriveTier(table, Action{Tool: "Bash", RawInput: cmd})
			if err != nil || got != want {
				t.Fatalf("Bash %q: got %v, err %v; want %v — Bash must fall through to the command classifier", cmd, got, err, want)
			}
		})
	}
}

// A tool the catalog has never heard of must derive exactly as it did
// before the catalog existed: falling through to BuiltinTier (here, the
// verb table), unaffected by the catalog now being populated.
func TestDeriveTier_UnknownToolFallsThroughUnchanged(t *testing.T) {
	action := Action{Tool: "mcp__stripe__create_refund", Verb: "create"}

	withCatalog, err := DeriveTier(TierTable{Catalog: DefaultCatalog()}, action)
	if err != nil {
		t.Fatalf("with catalog: unexpected error %v", err)
	}
	withoutCatalog, err := DeriveTier(TierTable{}, action)
	if err != nil {
		t.Fatalf("without catalog: unexpected error %v", err)
	}
	if withCatalog != withoutCatalog {
		t.Fatalf("an unrecognized tool must derive identically with or without the catalog populated: got %v with, %v without",
			withCatalog, withoutCatalog)
	}
	if withCatalog != models.ActionTierInternalModify {
		t.Fatalf("got %v, want INTERNAL_MODIFY (verb %q via BuiltinTier's verb table)", withCatalog, action.Verb)
	}
}

// The catalog entry must beat BuiltinTier for a seeded tool, exactly as
// spec §4.4 orders resolution (override, catalog, built-in).
// TestDeriveTier_CatalogBeatsBuiltin (tier_test.go) proves this for
// DeriveTier's logic with a synthetic table; this pins it against
// DefaultCatalog()'s actual data, which is what a resolution-order
// regression (catalog moved below built-in) would actually break. "Write"
// is cataloged INTERNAL_MODIFY; tagging the call with verb "read" gives
// BuiltinTier's verb table a conflicting, definitive answer (READ_ONLY) —
// if the catalog were checked after BuiltinTier, this would come back
// READ_ONLY instead.
func TestDeriveTier_CatalogEntryBeatsBuiltinForSeededTool(t *testing.T) {
	table := TierTable{Catalog: DefaultCatalog()}
	got, err := DeriveTier(table, Action{Tool: "Write", Verb: "read"})
	if err != nil || got != models.ActionTierInternalModify {
		t.Fatalf("got %v, err %v; want INTERNAL_MODIFY — the catalog entry for Write must beat BuiltinTier's verb table", got, err)
	}
}

// A tenant override still raises above a seeded catalog entry, end to end
// through DeriveTier.
func TestDeriveTier_OverrideRaisesSeededCatalogEntry(t *testing.T) {
	table := TierTable{
		Catalog:   DefaultCatalog(),
		Overrides: map[string]models.ActionTier{"Read": models.ActionTierDestructive},
	}
	got, err := DeriveTier(table, Action{Tool: "Read"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("got %v, err %v; want DESTRUCTIVE — an override must still beat a seeded catalog entry", got, err)
	}
}

// ValidateOverride's raise-only rule (C4) must still hold when the baseline
// it is checked against is a catalog entry, not just a hand-picked
// constant: a tenant may raise a seeded tool's tier, never lower it. This is
// the write-time half of "an override raises a catalog entry but cannot
// lower it" — DeriveTier's read side is proven by
// TestDeriveTier_OverrideRaisesSeededCatalogEntry above; ValidateOverride is
// what must reject the write that DeriveTier has no way to catch (see
// TierTable.Overrides's doc comment on the decision-path gap this does not
// close).
func TestValidateOverride_CatalogEntryRaiseOnly(t *testing.T) {
	builtin := DefaultCatalog()["Read"] // READ_ONLY
	if err := ValidateOverride(builtin, models.ActionTierDestructive); err != nil {
		t.Fatalf("raising above a catalog entry must be allowed: %v", err)
	}
	if err := ValidateOverride(builtin, models.ActionTierReasoning); !errors.Is(err, ErrOverrideLowersTier) {
		t.Fatalf("lowering below a catalog entry must be rejected, got %v", err)
	}
}
