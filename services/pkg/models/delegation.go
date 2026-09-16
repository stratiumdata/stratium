package models

import (
	"time"

	"github.com/google/uuid"
)

// Delegation is a bounded, time-limited grant of authority from a principal to
// an agent, or from an agent to a sub-agent. It is the ceiling every runtime
// decision is measured against.
type Delegation struct {
	ID       uuid.UUID `json:"id"        db:"id"`
	TenantID string    `json:"tenant_id" db:"tenant_id"`

	UserID  string    `json:"user_id"  db:"user_id"`
	AgentID uuid.UUID `json:"agent_id" db:"agent_id"`

	ApprovedTools []string   `json:"approved_tools"  db:"approved_tools"`
	MaxActionTier ActionTier `json:"max_action_tier" db:"max_action_tier"`

	// EscalateAt is the tier at or above which this delegation's leg
	// escalates rather than allowing outright, up to and including
	// MaxActionTier: the closed band [EscalateAt, MaxActionTier]
	// (DelegationLeg, internal/authz). A tier above MaxActionTier still
	// denies regardless — deny overrides escalate, so the ceiling is
	// checked first. Nil means this delegation never escalates.
	//
	// A pointer, not a bare ActionTier: REASONING is tier 0 (see that
	// type's own doc comment), so a bare zero value here would mean
	// "escalate on every action" — the opposite of a safe default for
	// every delegation that existed before this field did. Only nil, not
	// zero, can mean "never" — the migration that adds this column leaves
	// it NULL with no default for exactly that reason.
	EscalateAt *ActionTier `json:"escalate_at,omitempty" db:"escalate_at"`

	ClassificationCaps  map[string]string `json:"classification_caps"  db:"classification_caps"`
	ResourceConstraints map[string]string `json:"resource_constraints" db:"resource_constraints"`
	Purpose             string            `json:"purpose"              db:"purpose"`

	ExpiresAt time.Time  `json:"expires_at"           db:"expires_at"`
	CreatedAt time.Time  `json:"created_at"           db:"created_at"`
	Revoked   bool       `json:"revoked"              db:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`

	ParentDelegationID *uuid.UUID  `json:"parent_delegation_id,omitempty" db:"parent_delegation_id"`
	RootDelegationID   uuid.UUID   `json:"root_delegation_id"             db:"root_delegation_id"`
	Depth              int         `json:"depth"                          db:"depth"`
	ChainAgentIDs      []uuid.UUID `json:"chain_agent_ids"                db:"chain_agent_ids"`
}

// IsRoot reports whether this delegation came directly from a principal.
func (d *Delegation) IsRoot() bool { return d.ParentDelegationID == nil }

// IsActive reports whether the delegation is neither revoked nor expired at
// the given instant. Time is a parameter so decisions are deterministic.
func (d *Delegation) IsActive(now time.Time) bool {
	return !d.Revoked && !now.After(d.ExpiresAt)
}

// HasTool reports whether a tool is approved. An empty list is unrestricted,
// matching Agent.HasTool.
func (d *Delegation) HasTool(tool string) bool {
	if len(d.ApprovedTools) == 0 {
		return true
	}
	for _, t := range d.ApprovedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// ResourceIDPrefixKey is the one resource-constraint key with PREFIX
// semantics: its value is matched against every resource identity a call
// resolved to, and every one of them must be under it. Every other key keeps
// exact-match semantics (internal/authz's checkResourceConstraints), for the
// reason that function's own comment gives — an opaque caller-defined string
// has no ordering to narrow along, so interpreting one is a place a widening
// can hide.
//
// It lives here rather than in internal/authz because ScopeNarrows below
// needs it too, and pkg/models cannot import internal/authz — the dependency
// runs the other way.
const ResourceIDPrefixKey = "id_prefix"
