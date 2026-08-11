package authz

import "stratium/pkg/models"

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
// Bash's absence is the constraint the rest of this catalog is built around,
// not an oversight. Bash's RawInput IS a shell command, so BuiltinTier's
// command classifier can and does tell "rm -rf /" (DESTRUCTIVE) from
// "ls -la" (READ_ONLY) — that is Phase 3b's fix, and it depends on
// DeriveTier actually reaching BuiltinTier for Bash. A catalog entry for
// "Bash" would be checked first (Catalog sits above BuiltinTier in
// DeriveTier's resolution order) and would assign every shell command the
// same single tier regardless of what it does, silently undoing Phase 3b
// for every Bash call. See TestDeriveTier_BashHasNoCatalogEntry
// (catalog_test.go), which pins both directions of this — rm -rf / still
// derives DESTRUCTIVE, ls -la still derives READ_ONLY — through DeriveTier
// with this catalog wired in, not just through BuiltinTier in isolation.
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
