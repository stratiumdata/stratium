package authz

import "github.com/stratiumdata/stratium/pkg/models"

// DefaultCatalog returns the shipped tool-name -> tier table. The caller
// merges it into TierTable.Catalog when building a tenant's decision
// configuration (pdpgrpc.Server.Decide sets it alongside DefaultTrustTable).
// DeriveTier already consults Catalog, between Overrides and BuiltinTier, in
// the order spec §4.4 documents; before this function existed that step was
// a no-op because the map it read was always empty.
//
// A fresh map is built and returned on every call, the same choice
// DefaultTrustTable makes for TrustTable: this is a per-tenant, per-request
// configuration value on a multi-tenant platform, so handing back one shared
// package-level map would let a mutation made under one caller's
// configuration leak into every other caller holding the same map.
//
// # Why a catalog, and why these tools
//
// Extraction cannot fix the defect this closes. BuiltinTier's shell
// classifier (tier.go) works because a Bash command is a string with a verb
// in it — "rm", "ls", "cat" — for its patterns to match. A file tool's input
// is a bare path or bare content with no verb: Read called on
// "/tmp/notes.txt" carries no token classifyInput recognizes, so it falls
// through to classifyInput's "unrecognized -> assume it modifies" default
// and comes out INTERNAL_MODIFY — wrong, and indistinguishable from what
// Write on the same path would produce. The tool name is the only signal
// available. Read is read-only because it is spelled Read, not because of
// anything in its argument, so the fix has to live in a name -> tier table,
// not in a smarter regex.
//
// READ_ONLY — Read, Glob, Grep, NotebookRead, LS, WebFetch, WebSearch.
// Retrieval without mutation: every one of these hands data back to the
// agent and changes no state as a side effect of being called.
//
// WebFetch and WebSearch read data from outside the tenant's trust boundary.
// That is a real risk dimension, but it is a different axis from tier — tier
// answers "what does calling this tool do to state," not "where did the
// bytes come from" (EXTERNAL_COMMS, the tier that axis maps to, is reserved
// for actions that reach OUT: send, publish, webhook — see verbTiers in
// tier.go). A tenant that wants external reads treated as more sensitive
// than local ones does not get a different built-in default here for it;
// it gets there through ValidateOverride's raise-only mechanism, which
// exists precisely so a tenant can be stricter than the shipped default
// without the platform guessing every tenant's risk tolerance up front.
//
// INTERNAL_MODIFY — Write, Edit, NotebookEdit, TodoWrite. Each mutates state
// that stays inside the agent's own workspace — a file, a notebook cell, the
// session's todo list — without reaching outside the trust boundary and
// without being irreversible or financially binding (the properties that
// would earn DESTRUCTIVE). This is the same tier BuiltinTier's verb table
// already assigns "write"/"create"/"update" to, so this is not a new
// judgment about what "write" means, only that judgment reaching a tool
// call that carries no verb to look up.
//
// No entry — Bash, and anything this catalog does not name.
//
// Bash's absence from THIS map is still deliberate, but the reason has
// narrowed. DefaultCatalog is a bare map[string]ActionTier: every entry
// fixes one tier, with no way to say "extract a field and classify it
// instead" — so it could never express Bash correctly no matter what this
// function did. Bash's RawInput IS a shell command, so BuiltinTier's
// command classifier can and does tell "rm -rf /" (DESTRUCTIVE) from
// "ls -la" (READ_ONLY) — that is Phase 3b's fix, and it depends on
// DeriveTier actually reaching BuiltinTier for Bash. A fixed entry for
// "Bash" here would be checked first (Catalog sits above BuiltinTier in
// DeriveTier's resolution order) and would assign every shell command the
// same single tier regardless of what it does, silently undoing Phase 3b
// for every Bash call. See TestDeriveTier_BashHasNoCatalogEntry
// (catalog_test.go), which pins both directions of this — rm -rf / still
// derives DESTRUCTIVE, ls -la still derives READ_ONLY — through DeriveTier
// with this catalog wired in, not just through BuiltinTier in isolation.
//
// Until migrations/000014_tool_catalog_nullable_tier, that map-shaped
// limitation was ALSO the tenant's: action_tier was NOT NULL, so a real
// tool_catalog row for Bash could not exist either, and command_field —
// the only way the PDP learns which raw_input field holds the command —
// went with it. Phase 8 Task 3 disclosed the resulting regression: a
// Bash call arriving as Claude Code's JSON tool_input
// ({"command":"ls -la"}) had no catalog row to supply command_field, so it
// fell to BuiltinTier's own JSON-blob default, INTERNAL_MODIFY, instead of
// classifying READ_ONLY — Phase 3b's defect, reintroduced. That migration
// makes action_tier nullable specifically so a TENANT's own row — unlike
// this hardcoded map — CAN catalog Bash: a NULL ActionTier
// (pkg/models.ToolCatalogEntry's own doc comment) plus a command_field
// naming where the command lives. BuildTierCatalog (below) folds such a
// row in as no fixed-tier entry at all, so DeriveTier still reaches
// BuiltinTier for it, exactly as an entirely absent row always has — a
// NULL-tier row is that same "let BuiltinTier decide" behavior, now
// something a tenant can write instead of only something this package can
// omit. See TestDeriveTier_BashCatalogRowWithCommandFieldClassifiesReadOnly
// (catalog_test.go) and
// TestApplyExtraction_NullTierCatalogRowCannotMaskDestructiveRawEvidence
// (extract_test.go) for both directions of that proof, end to end through
// extraction and DeriveTier together — TestDeriveTier_BashHasNoCatalogEntry
// above still pins this map's own, separate omission on its own.
//
// A tool this catalog has never heard of gets no entry for the same reason:
// an absent key means "no name-implies-tier shortcut for this one," not
// "safe" or "unsafe." DeriveTier falls through to BuiltinTier, and if that
// also has nothing, to the tenant's configured UnknownTier floor or
// DenyUnknown, exactly as it did before this catalog existed.
func DefaultCatalog() map[string]models.ActionTier {
	return map[string]models.ActionTier{
		// READ_ONLY: retrieval without mutation.
		"Read":         models.ActionTierReadOnly,
		"Glob":         models.ActionTierReadOnly,
		"Grep":         models.ActionTierReadOnly,
		"NotebookRead": models.ActionTierReadOnly,
		"LS":           models.ActionTierReadOnly,
		"WebFetch":     models.ActionTierReadOnly,
		"WebSearch":    models.ActionTierReadOnly,

		// INTERNAL_MODIFY: mutates state local to the agent's own workspace.
		"Write":        models.ActionTierInternalModify,
		"Edit":         models.ActionTierInternalModify,
		"NotebookEdit": models.ActionTierInternalModify,
		"TodoWrite":    models.ActionTierInternalModify,

		// Bash: no entry, deliberately — falls through to the command
		// classifier. See the doc comment above.
	}
}

// BuildTierCatalog merges a tenant's own tool_catalog rows (Task 1;
// store.LoadToolCatalog) over DefaultCatalog(), tenant rows winning per
// tool. This is §4.4.2 T1's "catalog" step of DeriveTier's resolution order,
// connected to the database for the first time: DeriveTier itself is
// unchanged (it has always consulted whatever TierTable.Catalog holds), only
// what populates that field is new.
//
// A tenant with zero rows — every tenant, until the control plane populates
// one — gets back a catalog equal to DefaultCatalog() itself, so DeriveTier
// resolves every tool exactly as it did before this table existed. That is
// the regression guard that makes shipping the table safe on day one, and it
// is pinned end to end through DeriveTier, not merely as a map comparison,
// by TestDeriveTier_EmptyTenantCatalogFallsBackToDefaultCatalog
// (catalog_test.go) — the same "prove it through DeriveTier, not just the
// map" discipline TestDeriveTier_BashHasNoCatalogEntry already established
// for this file.
//
// The merge is per tool, not per tenant: a tenant that catalogs ONE tool
// (an MCP server's read_file, say) must not lose DefaultCatalog()'s entries
// for every OTHER tool it never mentioned. Only names actually present in
// entries override a default; every other name falls through unchanged. A
// tenant CAN catalog a built-in name — including "Bash", which
// DefaultCatalog() deliberately omits (see that function's own doc comment)
// — and that is the tenant's own choice to make: DeriveTier's evidence rule
// protects a destructive raw input regardless of what any catalog, built-in
// or tenant-supplied, claims about the tool's tier.
//
// defaults is read, never mutated: a fresh map is returned, the same
// per-call-fresh-map discipline DefaultCatalog() itself follows (see that
// function's own doc comment), so a caller still holding the map DefaultCatalog()
// handed back never sees a tenant's row leak into it.
//
// A tenant row with a NULL ActionTier (e.ActionTier == nil — Bash-shaped;
// see DefaultCatalog's own doc comment) contributes NO entry to the merged
// map, on purpose, and DELETES whatever entry that tool name already held
// from defaults rather than leaving it in place. Both halves matter:
// deriveTierByName (tier.go) returns whatever this map holds for a tool
// immediately, before ever reaching BuiltinTier, so inserting a
// placeholder tier here — even ActionTierReasoning, ActionTier's own zero
// value — would fix every call to that tool at one tier, bypassing
// per-command classification entirely, the exact failure a mistakenly
// catalogued Bash entry always risked (DefaultCatalog's own doc comment);
// and leaving a stale default entry in place instead of deleting it would
// mean a tenant's own NULL-tier row loses the fold for the one tool it
// most needs to win it for. Omitting the entry is what lets DeriveTier
// fall through to BuiltinTier for that tool, exactly as it would for a
// tool with no catalog row at all — and that fallthrough is safe
// regardless of what BuiltinTier decides, because DeriveTier re-scans
// RawInput for destructive-or-external evidence unconditionally, after
// this map has already had its say (tier.go's own doc comment on
// destructiveEvidence).
func BuildTierCatalog(entries []models.ToolCatalogEntry, defaults map[string]models.ActionTier) map[string]models.ActionTier {
	merged := make(map[string]models.ActionTier, len(defaults)+len(entries))
	for tool, tier := range defaults {
		merged[tool] = tier
	}
	for _, e := range entries {
		if e.ActionTier == nil {
			delete(merged, e.ToolName)
			continue
		}
		merged[e.ToolName] = *e.ActionTier
	}
	return merged
}
