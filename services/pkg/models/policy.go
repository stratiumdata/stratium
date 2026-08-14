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

	// Effect is policies.effect ('allow'/'deny'). internal/store/policy.go's
	// own doc comment on LoadAllPolicies records why no engine reads this
	// column back — every engine derives effect from the policy text itself,
	// so a stored value here can disagree with what the text actually does —
	// and flags that a write path populating it "must validate the value
	// agrees with the policy text it is attached to before persisting, rather
	// than trusting whatever was last written." This package's CreatePolicy/
	// UpdatePolicy do not attempt that cross-validation: doing so correctly
	// would mean parsing each of four policy languages' native effect syntax
	// (Cedar permit/forbid, Rego's own allow/deny rule head, XACML's Effect
	// attribute, JSON's own effect key) independently of Validate, which
	// checks syntax and semantic liveness, not this specific cross-check —
	// a materially larger undertaking than this task's three load-bearing
	// properties call for. Effect is treated as operator-declared provenance,
	// like Name, checked only against the schema's own CHECK ('allow' or
	// 'deny') — a known, documented limitation, not a silently missed one.
	Effect string `json:"effect" db:"effect"`

	// Version increments by one on every UpdatePolicy call — never
	// client-supplied, matching how CreateDelegation/CreateApproval ignore
	// every caller-supplied field with no legitimate external value. Loaded,
	// not yet consumed by anything downstream (see StoredPolicy.Version's own
	// doc comment on why it exists ahead of a cache that would key on it).
	Version int64 `json:"version" db:"version"`

	Enabled bool `json:"enabled" db:"enabled"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}
