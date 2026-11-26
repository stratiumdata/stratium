package models

import (
	"time"

	"github.com/google/uuid"
)

// Policy is one row of the policies table (migrations/000001_baseline).
//
// Defined here, in pkg/models, rather than in internal/store: the PAP's HTTP
// layer (cmd/stratium-pap) both constructs a value of this type (an operator
// authoring a new policy, before any row exists) and reads nearly every field
// of one back (listing and displaying existing policies) — the same
// two-sided, full-fidelity use models.Agent and models.Approval already get,
// and their own doc comments record the same reasoning for the same choice.
// internal/policy.StoredPolicy is deliberately NOT reused for this: it is a
// reduced, engine-shaped view (no description, effect, enabled, or
// timestamps — see its own doc comment) built for compilation, not
// authoring, the same way internal/authz.AgentInfo is a reduced view distinct
// from this package's own Agent.
type Policy struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	Name        string `json:"name"        db:"name"`
	Description string `json:"description" db:"description"`
	Language    string `json:"language"    db:"language"`

	// Text is policies.policy_content — named to match
	// internal/policy.StoredPolicy.Text, the same column under its
	// engine-facing name, rather than repeating "PolicyContent" as a second
	// spelling for the identical column in this codebase.
	Text string `json:"policy_content" db:"policy_content"`

	// Effect is policies.effect ('allow'/'deny'). No engine reads this
	// column back for a real decision — every engine derives effect from
	// the policy text itself (internal/store/policy.go's own doc comment on
	// LoadAllPolicies) — but internal/store's CreatePolicy/UpdatePolicy
	// validate it at write time via validateEffectAgreement, so the column
	// itself cannot lie once written:
	//
	//   - Cedar and JSON: a stored policy's effect is single-valued and
	//     mechanically derivable from its own text (Cedar's fixed
	//     permit/forbid head keyword; JSON's own literal "effect" key), so
	//     this field must agree with what the text declares, or the write
	//     is refused (store.ErrEffectMismatch).
	//   - Rego and XACML: a single stored policy can itself define rules of
	//     BOTH effects (a Rego module's independent allow/deny rules; an
	//     XACML Policy's several independently-scoped Rules), resolved only
	//     once real request data is known — there is no single text-derived
	//     value this field could ever agree OR disagree with. This field
	//     must equal the fixed sentinel "deny" for these two languages
	//     (store.ErrEffectNotDeclarable otherwise): a constant, provably
	//     uninformative placeholder, never this row's real behavior. A
	//     display screen must not read this field as fact for a rego/xacml
	//     row — only for cedar/json ones.
	Effect string `json:"effect" db:"effect"`

	// Version increments by one on every UpdatePolicy call — never
	// client-supplied, matching how CreateDelegation/CreateApproval ignore
	// every caller-supplied field with no legitimate external value. Loaded,
	// not yet consumed by anything downstream (see StoredPolicy.Version's own
	// doc comment on why it exists ahead of a cache that would key on it).
	Version int64 `json:"version" db:"version"`

	Enabled bool `json:"enabled" db:"enabled"`

	// Protected is set by an admin through PUT /v1/policies/{id}/protection
	// and nothing else: create and update accept the field and ignore it,
	// so a client can send back what it read. While it is set, only an admin
	// may change or disable the policy.
	Protected bool `json:"protected" db:"protected"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// PolicyProtectionView is what PUT /v1/policies/{id}/protection returns.
type PolicyProtectionView struct {
	PolicyID  uuid.UUID `json:"policy_id"`
	Protected bool      `json:"protected"`
}
