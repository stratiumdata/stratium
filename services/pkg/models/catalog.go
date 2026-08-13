package models

// ToolCatalogEntry is one tenant's declared metadata for one tool: the
// action tier and verb §4.4's resolution order looks up ahead of the
// built-in classifier (spec §4.4.2 T1), and which raw_input field names, if
// any, carry the tool call's resource identity and command (T2).
//
// Defined here, not in internal/store where Task 1 first put it (that
// package's own catalog.go doc comment flagged this choice for Task 2 to
// make explicitly -- internal/authz was off-limits for Task 1 -- the same
// way approval.go's doc comment did for Approval): internal/authz now needs
// to both resolve a tool's tier from a whole slice of these and extract a
// call's resource identity and command from one, and internal/authz must
// not import internal/store to get it (that package's own doc comment: no
// database handle, no network, no ambient clock -- the catalog is loaded
// elsewhere and passed in, exactly as policies are). pkg/models is the
// shared, dependency-free leaf both internal/store and internal/authz
// already import, the same role it plays for Approval and Delegation.
//
// ResourceField and CommandField are pointers, not plain strings: plenty of
// tools have no resource field, and most have no command field at all --
// only a shell-shaped tool does -- so a bare string could not tell "this
// tool has no such field" (nil) apart from "this tool's field name happens
// to be empty" (the zero value). Same nullable-pointer discipline
// scanDelegation applies to Purpose and EscalateAt (internal/store/store.go).
//
// ActionTier is a *ActionTier for the same reason Delegation.EscalateAt is
// (that field's own doc comment, Phase 5 Task 1): ActionTierReasoning is
// tier 0 (ActionTier's own doc comment), so a bare ActionTier field could
// not tell "this row fixes no tier at all" (nil) apart from "this row fixes
// REASONING" (the zero value) -- and unlike EscalateAt, where defaulting to
// zero mainly changes when a delegation escalates, defaulting a mis-scanned
// NULL tier to zero here is a silent under-classification: deriveTierByName
// (internal/authz/tier.go) returns whatever BuildTierCatalog put in its map
// for a tool immediately, without ever reaching BuiltinTier's per-command
// classifier, so a fixed REASONING entry would flatten every call to that
// tool -- destructive ones included, were it not for DeriveTier's separate,
// unconditional evidence re-scan -- to "no side effects."
//
// nil means this row fixes no tier: classify the tool's calls with the
// command classifier instead, by extracting CommandField from raw_input
// (internal/authz/extract.go) the normal way and letting BuiltinTier
// (internal/authz/tier.go) rate the result. This is Bash's shape: no fixed
// tier could ever describe it (DefaultCatalog's own doc comment,
// internal/authz/catalog.go), only its command can, and this field's
// nullability (migrations/000014_tool_catalog_nullable_tier) is what lets a
// tenant catalog it at all -- CommandField must be non-nil whenever this is
// nil, enforced by that migration's own CHECK constraint, since a NULL tier
// with no command_field names no field to classify.
type ToolCatalogEntry struct {
	ToolName   string
	ActionTier *ActionTier

	// Verb is stored but not yet consumed by tier or extraction resolution
	// (Task 2): DeriveTier keys tier lookups on the incoming Action's own
	// Verb, never on a catalog row's. Whether the PDP should derive
	// DecideRequest's verb from this column instead is Task 3's own open
	// question (it retires normalized_input and the PEP's toolVerbs table in
	// the same breath) -- left here, unused, rather than dropped, so that
	// decision has data to decide with.
	Verb string

	ResourceField *string
	CommandField  *string
}
