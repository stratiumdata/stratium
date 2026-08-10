package policy

import (
	"stratium/internal/authz"
	"stratium/pkg/models"
)

// EvaluationInput is what every engine receives. It carries the agent and
// delegation dimensions so a tenant can write "deny Unverified agents on
// financial tools" in their own policy language (spec Y3). Spec defect D6 was
// the predecessor's EvaluationInput having no such dimension — the structural
// reason the agent authorization path could never call the engines.
//
// Seeing these dimensions does not let a policy widen anything: the agent and
// delegation legs are evaluated separately as independent AND terms, so an
// ALLOW here can only ever be one of three required yeses.
type EvaluationInput struct {
	Principal   authz.Principal
	Action      authz.Action
	DerivedTier models.ActionTier
	Resource    map[string]string
	Environment map[string]string

	Agent      authz.AgentInfo
	Delegation DelegationContext
}

// DelegationContext is the acting delegation reduced to what a policy may
// reasonably condition on. It is not the delegation itself: no identifiers
// that would let a policy pin to one grant, and no fields the delegation leg
// already enforces structurally.
type DelegationContext struct {
	Depth              int
	MaxActionTier      models.ActionTier
	ClassificationCaps map[string]string
	Purpose            string
}
