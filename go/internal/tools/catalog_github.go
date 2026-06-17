package tools

import (
	"context"
	"encoding/json"
	"fmt"

	ag "stratium/services/agent-gateway"

	"stratium/internal/catalog"
	"stratium/internal/catalog/github"
	"stratium/internal/mcp"
)

// gatewayAuthorizer adapts the Agent Gateway client to catalog.Authorizer.
type gatewayAuthorizer struct{ r *Registry }

func (g gatewayAuthorizer) Authorize(ctx context.Context, req catalog.AuthRequest) (catalog.AuthDecision, error) {
	resp, err := g.r.gateway.ExecuteAction(ctx, g.r.accessToken(), g.r.userID(), &ag.ExecuteActionRequest{
		DelegationToken:    req.DelegationToken,
		ToolName:           req.ToolName,
		Action:             req.Action,
		ActionTier:         ag.ActionTier(req.ActionTier),
		ResourceAttributes: req.ResourceAttributes,
	})
	if err != nil {
		return catalog.AuthDecision{}, fmt.Errorf("execute_action RPC failed: %w", err)
	}
	return catalog.AuthDecision{Authorized: resp.Authorized, Reason: extractReason(resp)}, nil
}

// extractReason mirrors the reason logic in handleExecuteAction (actions.go).
func extractReason(resp *ag.ExecuteActionResponse) string {
	reason := ""
	if resp.Decision != nil {
		switch {
		case resp.Decision.DelegationReason != "":
			reason = resp.Decision.DelegationReason
		case resp.Decision.AgentReason != "":
			reason = resp.Decision.AgentReason
		case resp.Decision.UserReason != "":
			reason = resp.Decision.UserReason
		}
		if resp.Decision.DeniedPrincipal != "" {
			reason = fmt.Sprintf("%s (denied by %s)", reason, resp.Decision.DeniedPrincipal)
		}
	}
	if resp.Error != "" {
		reason = resp.Error
	}
	return reason
}

// SetCatalog enables the SaaS tool catalog with its dependencies. Call before RegisterAll.
func (r *Registry) SetCatalog(cfg *catalog.Config, creds catalog.CredentialProvider, classifier *catalog.Classifier, gh github.Client) {
	r.catalog = cfg
	r.creds = creds
	r.classifier = classifier
	r.gh = gh
}

// registerCatalogTools registers SaaS catalog tools when the catalog is enabled.
func (r *Registry) registerCatalogTools(server *mcp.Server) {
	if r.catalog == nil || !r.catalog.Enabled {
		return
	}
	deps := github.Deps{
		Auth:   gatewayAuthorizer{r},
		Creds:  r.creds,
		Class:  r.classifier,
		Client: r.gh,
	}
	specs := github.Specs()
	for _, spec := range specs {
		if err := catalog.GuardTier(spec.Action, spec.Tier); err != nil {
			r.logger.Fatalf("catalog tool %s failed tier guard: %v", spec.Tool.Name, err)
		}
		spec := spec // capture
		server.RegisterTool(spec.Tool, func(args json.RawMessage) (*mcp.ToolCallResult, error) {
			// MCP tool handlers receive no context; use Background like the other
			// stratium-mcp tools. TODO: plumb a deadline if the transport exposes one.
			ctx := context.Background()
			if err := r.ensureAuth(ctx); err != nil {
				return nil, err
			}
			out, err := spec.Handler(ctx, deps, r.accessToken(), r.session.DelegationToken, args)
			if err != nil {
				return nil, err
			}
			// Denial (authorized:false) is returned as a SUCCESS result so the LLM
			// sees the structured reason; check out["authorized"] to detect denial.
			return mcp.SuccessResult(out)
		})
	}
	r.logger.Printf("catalog enabled: registered %d GitHub tools", len(specs))
}
