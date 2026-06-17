// go/internal/catalog/authorizer.go
package catalog

import "context"

// AuthRequest is a catalog-level authorization request, mapped onto the Agent
// Gateway ExecuteAction call by the adapter in the tools package.
type AuthRequest struct {
	DelegationToken    string
	ToolName           string
	Action             string
	ActionTier         int
	ResourceAttributes map[string]string
}

// AuthDecision is the catalog-level result.
type AuthDecision struct {
	Authorized bool
	Reason     string
}

// Authorizer is the seam to the Agent Gateway. The tools package provides an
// implementation backed by gateway.ExecuteAction; tests provide fakes.
type Authorizer interface {
	Authorize(ctx context.Context, req AuthRequest) (AuthDecision, error)
}
