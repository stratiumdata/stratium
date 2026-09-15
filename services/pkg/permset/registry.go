package permset

// dimensions names every models.Delegation field that bounds what its holder
// may do, mapped to the wire name its reason strings use. Every entry here
// must have a rule in contains.go AND a rule in union.go.
var dimensions = map[string]string{
	"ApprovedTools":       "approved_tools",
	"MaxActionTier":       "max_action_tier",
	"EscalateAt":          "escalate_at",
	"ClassificationCaps":  "classification_caps",
	"ResourceConstraints": "resource_constraints",
	"ExpiresAt":           "expires_at",
}

// notDimensions names every models.Delegation field that is deliberately not
// a permission dimension, with the reason. The reason is the load-bearing
// half: a bare list degrades into a place to silence registry_test.go, and
// "enforced per hop at authz/delegation.go" is falsifiable in review in a
// way that "not relevant" is not.
var notDimensions = map[string]string{
	"ID":        "identity",
	"TenantID":  "identity; the tenant boundary is RLS, not a comparison",
	"UserID":    "identity of the granting principal",
	"Purpose":   "human-readable; carries no authority",
	"CreatedAt": "metadata",

	// Not "identity": a child delegating to a DIFFERENT agent is the entire
	// point of a chain. AgentLeg (internal/authz/agent.go) bounds the acting
	// agent independently, on every decision.
	"AgentID": "acting agent; bounded by AgentLeg, not by containment",

	// Authorization-bearing, but enforced per hop at decision time.
	// DelegationLeg walks every hop and checks Revoked directly.
	"Revoked": "enforced per hop: internal/authz/delegation.go:65",

	// Metadata about the revocation event; the Revoked field is what gates
	// the denial.
	"RevokedAt": "metadata; revocation enforced via Revoked field",

	// Chain structure, validated at issuance as part of ValidateChain
	// (not a grant boundary). Root must be depth 0, each hop must be
	// predecessor + 1.
	"Depth": "chain structure: internal/authz/chain.go:41,68",

	// Derived chain provenance, written server-side at issuance
	// (internal/pdpgrpc/delegation.go:191,209) and never read by any
	// authorization decision.
	"ChainAgentIDs": "derived chain provenance, not used in authorization decisions",

	"ParentDelegationID": "chain structure, not a grant",
	"RootDelegationID":   "chain structure, not a grant",
}
