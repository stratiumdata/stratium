// Package permset answers one question: is this set of permissions contained
// in that one?
//
// It exists because Stratium had four separate needs for that answer --
// attenuating a child delegation, reviewing a config change, bounding a
// group of sibling agents, and guarding a trust table -- and answered only
// the first, by hand, in a function that fails open on any dimension nobody
// remembered to add (registry.go's own test).
//
// Two operations, with deliberately different precision contracts:
//
//	Contains  EXACT.  It blocks a write; it must be right in both directions.
//	Union     May over-approximate UPWARD. It only ever feeds an advisory
//	          report, where widening makes the report noisier, never blinder.
//
// That asymmetry is load-bearing, not a convenience -- see union.go's
// resource-constraint rule, which is sound only under it. A new BLOCKING
// caller of Union is a design change, not a refactor.
package permset

import (
	"time"

	"stratium/pkg/models"
)

// Set is a permission grant reduced to the dimensions that bound what its
// holder may do. It is the common denominator of four shapes that are
// unrelated types today: a delegation's grant, an agent's registered grant,
// a principal's ceiling, and a computed union.
//
// Agent trust tier is deliberately NOT here. It belongs to the agent leg,
// and folding it in would conflate two conjuncts the architecture keeps
// separate (allow = principal AND agent AND delegation).
type Set struct {
	// Tools is the approved tool list. EMPTY MEANS UNRESTRICTED, matching
	// models.Delegation.HasTool and models.Agent.HasTool. That convention is
	// why an empty child list under a restricted parent is a widening rather
	// than an inheritance.
	Tools []string

	MaxTier models.ActionTier

	// EscalateAt is nil when this grant never escalates. Lower is NARROWER:
	// a lower threshold escalates sooner.
	EscalateAt *models.ActionTier

	ClassificationCaps  map[string]string // hierarchy -> level
	ResourceConstraints map[string]string // models.ResourceIDPrefixKey, today

	ExpiresAt time.Time
}

// FromDelegation reduces a delegation to its permission set. Every field it
// reads is named in dimensions (registry.go), and the test there is what
// keeps those two lists honest with each other.
func FromDelegation(d *models.Delegation) Set {
	return Set{
		Tools:               d.ApprovedTools,
		MaxTier:             d.MaxActionTier,
		EscalateAt:          d.EscalateAt,
		ClassificationCaps:  d.ClassificationCaps,
		ResourceConstraints: d.ResourceConstraints,
		ExpiresAt:           d.ExpiresAt,
	}
}
