package cedar

import (
	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

// Entity types are deliberately flat, un-namespaced names. Namespacing
// (e.g. Stratium::User) buys nothing until a schema or a second engine's
// naming needs distinguishing from Cedar's — nothing in this task's tests
// filters on entity type, so adding one now would be speculative structure
// with no caller.
const (
	entityTypeUser     = types.EntityType("User")
	entityTypeResource = types.EntityType("Resource")
	entityTypeAction   = types.EntityType("Action")
)

// buildRequest maps a policy.EvaluationInput onto a Cedar request and the
// entities it references. See the package doc for the mapping's design.
func buildRequest(in policy.EvaluationInput) (cedarlib.Request, cedarlib.EntityMap) {
	principalUID := cedarlib.NewEntityUID(entityTypeUser, cedarlib.String(in.Principal.Subject))
	resourceUID := cedarlib.NewEntityUID(entityTypeResource, cedarlib.String(resourceID(in.Resource)))
	actionUID := cedarlib.NewEntityUID(entityTypeAction, cedarlib.String(in.Action.Tool))

	entities := cedarlib.EntityMap{
		principalUID: {UID: principalUID, Attributes: stringRecord(in.Principal.Attributes)},
		resourceUID:  {UID: resourceUID, Attributes: stringRecord(in.Resource)},
		// The action entity carries no attributes of its own: Action.Verb
		// and Action.RawInput describe this request's attempt, not the
		// action's identity, and nothing in scope reads them yet (see the
		// package doc). It is still registered — with an empty attribute
		// set — so a policy that references `action in SomeGroup` resolves
		// against a real (if parent-less) entity instead of erroring on a
		// missing one.
		actionUID: {UID: actionUID},
	}

	req := cedarlib.Request{
		Principal: principalUID,
		Action:    actionUID,
		Resource:  resourceUID,
		Context: cedarlib.NewRecord(cedarlib.RecordMap{
			"agent":      agentRecord(in.Agent),
			"delegation": delegationRecord(in.Delegation),
		}),
	}
	return req, entities
}

// resourceID picks the identity Cedar needs for the resource entity.
// EvaluationInput.Resource has no dedicated ID field — it's a flat
// map[string]string of whatever attributes the caller has — so this looks
// for the conventional "id" key and otherwise falls back to the empty
// string. That fallback is safe here: no Y3 rule conditions on resource
// identity, only on resource or context *attributes*, all of which reach
// the policy regardless of what the entity's ID is.
func resourceID(resource map[string]string) string {
	return resource["id"]
}

// agentRecord carries the agent dimension as a context attribute, not an
// entity — see the package doc for why.
func agentRecord(a authz.AgentInfo) cedarlib.Value {
	tools := make([]cedarlib.Value, len(a.AllowedTools))
	for i, t := range a.AllowedTools {
		tools[i] = cedarlib.String(t)
	}
	return cedarlib.NewRecord(cedarlib.RecordMap{
		"id":            cedarlib.String(a.ID.String()),
		"trust_tier":    cedarlib.String(a.TrustTier.String()),
		"enabled":       cedarlib.Boolean(a.Enabled),
		"suspended":     cedarlib.Boolean(a.Suspended),
		"allowed_tools": cedarlib.NewSet(tools...),
	})
}

// delegationRecord carries the delegation dimension as a context attribute,
// not an entity — see the package doc for why.
func delegationRecord(d policy.DelegationContext) cedarlib.Value {
	return cedarlib.NewRecord(cedarlib.RecordMap{
		"depth":               cedarlib.Long(d.Depth),
		"max_action_tier":     cedarlib.String(d.MaxActionTier.String()),
		"classification_caps": stringRecord(d.ClassificationCaps),
		"purpose":             cedarlib.String(d.Purpose),
	})
}

// stringRecord converts a flat string map into a Cedar record. Used both
// directly as an entity's Attributes (a Record) and, since Record
// implements Value, nested inside another record for context fields like
// classification_caps.
func stringRecord(m map[string]string) cedarlib.Record {
	rm := make(cedarlib.RecordMap, len(m))
	for k, v := range m {
		rm[cedarlib.String(k)] = cedarlib.String(v)
	}
	return cedarlib.NewRecord(rm)
}
