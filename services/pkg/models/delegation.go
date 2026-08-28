package models

import (
	"time"

	"github.com/google/uuid"

	"stratium/pkg/classification"
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

// ScopeNarrows reports whether a child delegation is a valid subset of its
// parent. It returns an empty string when the child is valid, or a description
// of the first widening found.
//
// "Narrows" means no wider — an identical child is valid. Every dimension is
// checked: action tier, escalation threshold, tools, classification caps,
// resource constraints, and expiry. Classification caps are compared by rank
// via classification.Index; an unknown level on either side is a rejection,
// never an equal comparison.
//
// A child may narrow a dimension its parent constrains; it may not introduce
// one the parent leaves open (spec §4.3.1). That is stricter than narrowing
// logic requires — adding a constraint does restrict the child further — and
// is deliberate: it makes a child's shape derivable from its parent's, so
// auditing a chain means comparing values across a fixed set of dimensions
// rather than tracking which hop introduced which dimension.
func ScopeNarrows(parent, child *Delegation) string {
	if child.MaxActionTier > parent.MaxActionTier {
		return "child max_action_tier " + child.MaxActionTier.String() +
			" exceeds parent " + parent.MaxActionTier.String()
	}

	// EscalateAt narrows in the opposite direction from a first guess: a
	// LOWER threshold escalates sooner, so lowering it narrows and raising
	// it widens. Introducing or dropping the threshold is rejected outright
	// rather than judged by whether it happens to narrow — the same §4.3.1
	// rule the caps and resource-constraint loops below enforce, and for the
	// same reason: a child's shape must be derivable from its parent's fixed
	// set of dimensions, not from which hop first introduced one. Every
	// branch is guarded on both pointers explicitly, rather than relying on
	// the preceding cases having already excluded one being nil, so this
	// still reads (and stays) safe if the cases are ever reordered.
	switch {
	case parent.EscalateAt == nil && child.EscalateAt != nil:
		return "child introduces escalate_at " + child.EscalateAt.String() +
			" which parent leaves unset"
	case parent.EscalateAt != nil && child.EscalateAt == nil:
		return "child drops parent escalate_at " + parent.EscalateAt.String()
	case parent.EscalateAt != nil && child.EscalateAt != nil && *child.EscalateAt > *parent.EscalateAt:
		return "child escalate_at " + child.EscalateAt.String() +
			" exceeds parent " + parent.EscalateAt.String()
	}

	// An empty parent list is unrestricted; an empty child list under a
	// restricted parent is a widening, not an inheritance.
	if len(parent.ApprovedTools) > 0 {
		if len(child.ApprovedTools) == 0 {
			return "child has no tool restriction while parent restricts tools"
		}
		allowed := make(map[string]bool, len(parent.ApprovedTools))
		for _, t := range parent.ApprovedTools {
			allowed[t] = true
		}
		for _, t := range child.ApprovedTools {
			if !allowed[t] {
				return "child tool " + t + " not in parent approved_tools"
			}
		}
	}

	// Iterate the PARENT's caps, not the child's. A hierarchy the parent
	// restricts and the child omits is a widening, not an inheritance: at
	// decision time CheckCap treats absent caps as "no restriction", so the
	// child would hold unrestricted access to that hierarchy. This is the same
	// asymmetry enforced above for tools — an empty child side under a
	// restricted parent is a widening.
	for hierarchy, parentCap := range parent.ClassificationCaps {
		childCap, ok := child.ClassificationCaps[hierarchy]
		if !ok {
			return "child does not cap hierarchy " + hierarchy +
				" which parent caps at " + parentCap
		}
		childIdx := classification.Index(hierarchy, childCap)
		if childIdx < 0 {
			return "child cap " + childCap + " is not a known level in hierarchy " + hierarchy
		}
		parentIdx := classification.Index(hierarchy, parentCap)
		if parentIdx < 0 {
			return "parent cap " + parentCap + " is not a known level in hierarchy " + hierarchy
		}
		if childIdx > parentIdx {
			return "child cap " + childCap + " exceeds parent cap " + parentCap +
				" in hierarchy " + hierarchy
		}
	}

	// The child may not introduce a cap on a hierarchy the parent does not cap.
	for hierarchy := range child.ClassificationCaps {
		if _, ok := parent.ClassificationCaps[hierarchy]; !ok {
			return "child caps hierarchy " + hierarchy + " which parent does not cap"
		}
	}

	// Resource constraints may be neither dropped nor altered. Every constraint
	// the parent sets must appear in the child with an identical value. Values
	// are opaque caller-defined strings, so the comparison is exact — it does
	// not try to reason about wildcards or ranges, because every such
	// interpretation is a place a widening could hide.
	for key, parentVal := range parent.ResourceConstraints {
		childVal, ok := child.ResourceConstraints[key]
		if !ok {
			return "child drops parent resource constraint " + key + "=" + parentVal
		}
		if childVal != parentVal {
			return "child resource constraint " + key + "=" + childVal +
				" differs from parent " + key + "=" + parentVal
		}
	}

	// Nor may the child introduce a constraint on a key the parent leaves
	// unconstrained — the same rule the caps loop above applies, for the same
	// reason (spec §4.3.1). Adding a constraint genuinely does narrow, so this
	// is stricter than logic alone requires; it is chosen so a child's shape is
	// derivable from its parent's and not only its values.
	for key := range child.ResourceConstraints {
		if _, ok := parent.ResourceConstraints[key]; !ok {
			return "child constrains resource key " + key + " which parent does not constrain"
		}
	}

	if child.ExpiresAt.After(parent.ExpiresAt) {
		return "child expires_at exceeds parent"
	}

	return ""
}
