package models

import (
	"github.com/google/uuid"

	"stratium/pkg/classification"
)

// ResourceLabelRule is one row of the resource_label_rules table
// (migrations/000019_resource_label_rules) as the PAP's admin plane sees it —
// a tenant-authored mapping from a resource-id PREFIX to a level in a
// classification hierarchy (spec §3.9.1, R4-R7).
//
// # Why this is not classification.Rule
//
// pkg/classification already has a Rule with these three fields, and the
// decision path uses exactly that one: Store.LoadResourceLabelRules returns
// []classification.Rule and Resolve consumes it. This type is deliberately a
// SECOND shape rather than two fields bolted onto that one, which is the
// opposite of the call pkg/models made for ToolCatalogEntry (one type, ID and
// TenantID left zero on the decision path). Two reasons, both specific to
// this table rather than to the general question:
//
//   - pkg/classification is pure and mutation-verified — "no clock, no I/O,
//     no ambient state," per its own package doc — and Resolve reads only
//     Prefix, Hierarchy and Level. A surrogate id and a set of JSON wire tags
//     are persistence and transport, not matching, and the one package that
//     must never acquire an opinion about either is the one deciding what a
//     resource IS.
//   - loadResourceLabelRulesQuery deliberately does not select id (see its own
//     doc comment: no reader on the decision path). Had the id lived on
//     classification.Rule, every Match.Rule.ID reachable from a live decision
//     would be uuid.Nil, silently — a zero value that looks like an answer.
//     ToolCatalogEntry carries exactly that asymmetry and documents it, but it
//     is a models type nothing on the decision path serialises; a
//     classification.Match is logged and audited.
//
// What that costs is one conversion, Rule below, and the field set staying in
// step — which NOTHING IN THE COMPILER CHECKS. That was claimed here once and
// it was false: Rule uses a keyed composite literal, so a field added to
// classification.Rule is silently zero-valued through the conversion and a
// field added here is silently ignored by it, and neither direction is even a
// warning. Measured, not reasoned about — adding a Category field to
// classification.Rule left `go build ./...` AND the whole test suite green.
//
// TestResourceLabelRule_RuleCopiesEveryMatcherField (resource_label_test.go)
// is what actually holds the invariant: for every field of classification.Rule
// it requires a same-named field here and requires Rule to carry its value
// through. An unkeyed literal is not the alternative — go vet's composites
// check would refuse it — so a test is where this guarantee can live at all.
//
// What the two structs do NOT cost is a second validator:
// internal/store.validateResourceLabelRule is the only thing anywhere that
// decides whether a (hierarchy, level) pair is legal, and every write path
// calls it.
//
// ID and TenantID are set authoritatively by internal/store on the way out and
// ignored on the way in, the same treatment models.Policy/Agent/TierOverride/
// ToolCatalogEntry each document for their own.
type ResourceLabelRule struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	// Prefix may legitimately be the EMPTY STRING: "" is a prefix of every
	// resource id, which makes such a row R7's catch-all — the answer to "a
	// tenant enabled a cap and now everything denies." Nothing in this
	// package, in internal/store, or in the schema treats it as a missing
	// required field; see migrations/000019's own comment on the absent
	// length(prefix) > 0 CHECK.
	Prefix string `json:"prefix" db:"prefix"`

	// Hierarchy and Level are stored verbatim, never case-folded on the way
	// in — classification.Index and Resolve both fold when they compare, and
	// normalising here would write back a level in casing the operator never
	// typed.
	Hierarchy string `json:"hierarchy" db:"hierarchy"`
	Level     string `json:"level"     db:"level"`
}

// Rule is r as the matcher and the validator see it — the single place the two
// shapes meet. Keyed deliberately (go vet's composites check forbids the
// unkeyed form that would have made this compiler-enforced), which is exactly
// why the drift it permits is pinned by a test rather than by the compiler:
// see TestResourceLabelRule_RuleCopiesEveryMatcherField.
func (r ResourceLabelRule) Rule() classification.Rule {
	return classification.Rule{Prefix: r.Prefix, Hierarchy: r.Hierarchy, Level: r.Level}
}
