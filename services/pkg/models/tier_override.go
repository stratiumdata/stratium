package models

import (
	"time"

	"github.com/google/uuid"
)

// TierOverride is one row of the tier_overrides table
// (migrations/000001_baseline) — a tenant-authored, raise-only correction to
// a tool or verb's built-in action-tier classification (spec §4.4).
//
// Defined here, in pkg/models, for the same reason as Policy in this same
// package (see that file's own doc comment): the PAP's HTTP layer both
// constructs one (an operator authoring an override) and reads one back in
// full (listing existing overrides), the two-sided use this package's other
// store-persisted types already get.
type TierOverride struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	// ToolOrVerb is the lookup key internal/authz.TierTable.Overrides is
	// keyed by — a whole tool name ("Bash") or a bare verb ("read"), per
	// internal/authz.lookupKeys. Never validated against a fixed vocabulary
	// here: the decision path already tolerates a key that matches nothing
	// (deriveTierByName simply falls through), so a typo'd or since-retired
	// name is inert, not dangerous, and rejecting it would require this
	// package to duplicate internal/authz's own key-construction logic.
	ToolOrVerb string `json:"tool_or_verb" db:"tool_or_verb"`

	ActionTier ActionTier `json:"action_tier" db:"action_tier"`

	// BuiltinTier is the floor ValidateOverride compared ActionTier against
	// at write time — never client-supplied (a tenant declaring its own
	// floor would make the raise-only rule vacuous, exactly the "declare a
	// destructive action harmless" hole server-side derivation exists to
	// close), always computed server-side and stored so the row itself
	// records what it was validated against, matching the schema's own
	// tier_overrides_raise_only CHECK (action_tier >= builtin_tier), which
	// reads this exact column.
	BuiltinTier ActionTier `json:"builtin_tier" db:"builtin_tier"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`

	// CreatedBy is the operator who wrote this override (Operator.Subject on
	// the PAP side) — tier_overrides' own NOT NULL created_by column, present
	// on no other table this phase writes, so this is the one CRUD resource
	// that carries its own row-level attribution in addition to the audit
	// chain's Actor field.
	CreatedBy string `json:"created_by" db:"created_by"`
}
