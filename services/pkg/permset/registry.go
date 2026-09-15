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
	// DelegationLeg walks every hop and checks each of these independently,
	// so a containment rule here would be a second, divergent implementation
	// of a check that already holds -- which is worse than none, because when
	// two implementations disagree the wrong one can silently win.
	"Revoked":       "enforced per hop: internal/authz/delegation.go",
	"RevokedAt":     "enforced per hop: internal/authz/delegation.go",
	"Depth":         "bounded per request by maxDepth: internal/authz/delegation.go",
	"ChainAgentIDs": "enforced per hop: internal/authz/delegation.go",

	"ParentDelegationID": "chain structure, not a grant",
	"RootDelegationID":   "chain structure, not a grant",
}
