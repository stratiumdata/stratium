package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent is a registered non-person entity that acts on a principal's behalf.
type Agent struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	Name     string `json:"name"     db:"name"`
	Provider string `json:"provider" db:"provider"`
	ModelID  string `json:"model_id" db:"model_id"`

	TrustTier AgentTrustTier `json:"trust_tier" db:"trust_tier"`
	Enabled   bool           `json:"enabled"    db:"enabled"`
	Suspended bool           `json:"suspended"  db:"suspended"`

	AllowedTools []string `json:"allowed_tools" db:"allowed_tools"`

	// ClassificationCaps is the per-hierarchy ceiling copied onto every ROOT
	// delegation this agent is issued (internal/pdpgrpc/delegation.go). An
	// empty map means no classification enforcement -- classification.CheckCap
	// returns allow for len(caps) == 0 -- so nil and {} are the same thing
	// here and both mean OFF. Children copy their parent's map, never this
	// one, so changing it affects only delegations issued after the change.
	ClassificationCaps map[string]string `json:"classification_caps" db:"classification_caps"`

	// ResourceConstraints is the scope copied onto every ROOT delegation at
	// issuance, the same way ClassificationCaps above is. It is NOT consulted
	// at decision time -- the decision reads the delegation's own constraints
	// -- so a change here never affects a delegation already issued.
	ResourceConstraints map[string]string `json:"resource_constraints" db:"resource_constraints"`

	// EscalateAt is the escalation threshold copied onto every ROOT
	// delegation at issuance, the same way ClassificationCaps and
	// ResourceConstraints are: at or above this tier a call waits for a
	// human instead of being allowed outright. nil means never escalate. A
	// caller's CreateDelegation request may LOWER it for that delegation,
	// never raise or remove it. Written only by SetAgentEscalation and
	// ClearAgentEscalation (internal/store/agent_escalation.go).
	EscalateAt *ActionTier `json:"escalate_at" db:"escalate_at"`

	// CreatedAt/UpdatedAt were absent from this type before internal/store's
	// PAP CRUD (Task 3) added them: LoadAgent (internal/store/store.go), the
	// only reader before that task, reduces to authz.AgentInfo and never
	// needed either column. The PAP's admin screen does, the same
	// full-fidelity requirement Policy and TierOverride (pkg/models) state in
	// their own doc comments, so both are added here rather than carried
	// only in a store-local type.
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// HasTool reports whether a tool is within the agent's allowlist. An empty
// allowlist is unrestricted — the delegation is the real constraint, and this
// matches Delegation.HasTool so the two never disagree.
func (a *Agent) HasTool(tool string) bool {
	if len(a.AllowedTools) == 0 {
		return true
	}
	for _, t := range a.AllowedTools {
		if t == tool {
			return true
		}
	}
	return false
}
