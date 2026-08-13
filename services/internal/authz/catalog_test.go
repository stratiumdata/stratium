package authz

import (
	"errors"
	"maps"
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

// TestBuildTierCatalog_EmptyEntriesEqualsDefaultCatalog is the map-level
// half of Task 2's regression guard: with zero tenant rows, the merge must
// produce a catalog indistinguishable from DefaultCatalog() itself, not an
// empty map that happens to fall through to the same place today. A merge
// that forgot to seed from defaults when entries is empty would pass every
// existing DefaultCatalog()-based test at the BuiltinTier layer (they never
// go through BuildTierCatalog) while still breaking every caller that does
// — which is exactly why TestDeriveTier_EmptyTenantCatalogFallsBackToDefaultCatalog
// below re-proves this through DeriveTier as well, the same "map inspection
// is not enough" discipline TestDeriveTier_BashHasNoCatalogEntry established
// for this file.
func TestBuildTierCatalog_EmptyEntriesEqualsDefaultCatalog(t *testing.T) {
	got := BuildTierCatalog(nil, DefaultCatalog())
	want := DefaultCatalog()
	if !maps.Equal(got, want) {
		t.Fatalf("BuildTierCatalog(nil, DefaultCatalog()) = %v, want exactly DefaultCatalog(): %v", got, want)
	}
}

// TestDeriveTier_EmptyTenantCatalogFallsBackToDefaultCatalog is the
// through-DeriveTier proof of the same property: a merge that silently drops
// to an empty (or nil) catalog when entries is empty, instead of seeding
// from defaults, would flip these two seeded tools from their documented
// tier to DeriveTier's UnknownTier floor or a DenyUnknown error — the
// mutation the phase brief names explicitly ("make an empty catalog deny
// everything").
func TestDeriveTier_EmptyTenantCatalogFallsBackToDefaultCatalog(t *testing.T) {
	table := TierTable{Catalog: BuildTierCatalog(nil, DefaultCatalog())}
	cases := map[string]models.ActionTier{
		"Read":  models.ActionTierReadOnly,
		"Write": models.ActionTierInternalModify,
	}
	for tool, want := range cases {
		t.Run(tool, func(t *testing.T) {
			got, err := DeriveTier(table, Action{Tool: tool})
			if err != nil || got != want {
				t.Fatalf("tool %q via a zero-row tenant catalog: got %v, err %v; want %v", tool, got, err, want)
			}
		})
	}
}

// TestBuildTierCatalog_TenantRowOverridesDefaultForThatToolOnly proves the
// merge is per tool, not a wholesale replacement: a tenant overriding one
// tool's tier must not disturb DefaultCatalog()'s entry for any tool it
// never mentioned. Read and Write are deliberately given DIFFERENT expected
// tiers here (DESTRUCTIVE vs INTERNAL_MODIFY, neither equal to Read's own
// default of READ_ONLY) so a merge that accidentally let one entry's value
// leak onto the other would fail a specific assertion, not pass by
// coincidence.
func TestBuildTierCatalog_TenantRowOverridesDefaultForThatToolOnly(t *testing.T) {
	entries := []models.ToolCatalogEntry{
		{ToolName: "Read", ActionTier: tierPtr(models.ActionTierDestructive)},
	}
	table := TierTable{Catalog: BuildTierCatalog(entries, DefaultCatalog())}

	got, err := DeriveTier(table, Action{Tool: "Read"})
	if err != nil || got != models.ActionTierDestructive {
		t.Fatalf("Read: got %v, err %v; want the tenant row's DESTRUCTIVE, not the default READ_ONLY", got, err)
	}
	got, err = DeriveTier(table, Action{Tool: "Write"})
	if err != nil || got != models.ActionTierInternalModify {
		t.Fatalf("Write: got %v, err %v; want DefaultCatalog()'s INTERNAL_MODIFY, unaffected by the Read row", got, err)
	}
}

// TestBuildTierCatalog_TenantCanCatalogToolAbsentFromDefaults is the
// motivating fix stated end to end: Phase 6 found a READ_ONLY delegation
// denying every third-party MCP read because read_file (or any MCP tool
// name) has no DefaultCatalog() entry and fell through to BuiltinTier's
// "unrecognized -> assume it modifies" default. A tenant's own row for that
// exact name must now resolve it correctly, through the real merge and the
// real DeriveTier, not merely through a hand-built TierTable.Catalog map as
// tier_test.go's own TestDeriveTier_CatalogBeatsBuiltin already does.
func TestBuildTierCatalog_TenantCanCatalogToolAbsentFromDefaults(t *testing.T) {
	entries := []models.ToolCatalogEntry{
		{ToolName: "read_file", ActionTier: tierPtr(models.ActionTierReadOnly)},
	}
	table := TierTable{Catalog: BuildTierCatalog(entries, DefaultCatalog())}

	got, err := DeriveTier(table, Action{Tool: "read_file", Verb: "read"})
	if err != nil || got != models.ActionTierReadOnly {
		t.Fatalf("got %v, err %v; want READ_ONLY — an MCP tool absent from DefaultCatalog() must resolve "+
			"through the tenant's own catalog row instead of BuiltinTier's unrecognized-input default", got, err)
	}
}

// TestBuildTierCatalog_NullTierEntryContributesNoFixedTier is the map-level
// half of the NULL-tier fold (paired below with
// TestDeriveTier_BashCatalogRowWithCommandFieldClassifiesReadOnly, the same
// "map inspection alone is not enough" discipline this file already applies
// throughout — see TestBuildTierCatalog_EmptyEntriesEqualsDefaultCatalog's
// own doc comment): a tenant row with ActionTier == nil must leave NO entry
// in the merged map for its tool, not a placeholder tier. Even
// ActionTierReasoning, ActionTier's own zero value, would let
// deriveTierByName (tier.go) return a fixed tier immediately and never
// reach BuiltinTier — exactly the failure a mistakenly catalogued Bash
// entry always risked (DefaultCatalog's own doc comment).
//
// The second case proves the fold actively DELETES a default entry, not
// merely skips adding one: a tenant nulling out a tool DefaultCatalog()
// already seeds (here, "Read") must still lose that default, or the
// tenant's own explicit choice to defer to the command classifier would be
// silently overruled by a seed it never asked for.
func TestBuildTierCatalog_NullTierEntryContributesNoFixedTier(t *testing.T) {
	t.Run("tool absent from defaults", func(t *testing.T) {
		entries := []models.ToolCatalogEntry{{ToolName: "Bash", CommandField: strPtr("command")}}
		got := BuildTierCatalog(entries, DefaultCatalog())
		if tier, ok := got["Bash"]; ok {
			t.Fatalf("merged catalog has an entry for Bash: %v, want none — a NULL tier must not fix one", tier)
		}
	})
	t.Run("tool present in defaults", func(t *testing.T) {
		entries := []models.ToolCatalogEntry{{ToolName: "Read", CommandField: strPtr("command")}}
		got := BuildTierCatalog(entries, DefaultCatalog())
		if tier, ok := got["Read"]; ok {
			t.Fatalf("merged catalog has an entry for Read: %v, want none — a tenant's NULL-tier row "+
				"must delete DefaultCatalog()'s own entry, not leave it in place", tier)
		}
	})
}

// TestDeriveTier_BashCatalogRowWithCommandFieldClassifiesReadOnly is Phase 8
// Task 3's own disclosed gap (task-3-report.md), closed: a Bash-shaped
// tool_catalog row — NULL ActionTier, command_field naming where the
// command lives — must still let DeriveTier reach the command classifier
// for it, exactly as TestDeriveTier_BashHasNoCatalogEntry above already
// proves for an entirely absent row. NormalizedInput is set directly here,
// as if extraction (internal/authz/extract.go) had already run against
// this same entries slice — the way pdpgrpc.Server.Decide actually chains
// them — so this test isolates BuildTierCatalog's and DeriveTier's own
// fold-through behavior from extraction's; the full pipeline, including
// extraction itself, is TestApplyExtraction_NullTierCatalogRowUsesCommandClassifier
// (extract_test.go).
func TestDeriveTier_BashCatalogRowWithCommandFieldClassifiesReadOnly(t *testing.T) {
	entries := []models.ToolCatalogEntry{{ToolName: "Bash", CommandField: strPtr("command")}}
	table := TierTable{Catalog: BuildTierCatalog(entries, DefaultCatalog())}

	cases := []struct {
		raw, normalized string
		want            models.ActionTier
	}{
		{`{"command":"ls -la"}`, "ls -la", models.ActionTierReadOnly},
		{`{"command":"rm -rf /"}`, "rm -rf /", models.ActionTierDestructive},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			got, err := DeriveTier(table, Action{Tool: "Bash", RawInput: c.raw, NormalizedInput: c.normalized})
			if err != nil || got != c.want {
				t.Fatalf("Bash %q (catalogued, NULL tier): got %v, err %v; want %v", c.raw, got, err, c.want)
			}
		})
	}
}
