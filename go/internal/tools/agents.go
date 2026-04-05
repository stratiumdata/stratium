package tools

import (
	"context"
	"encoding/json"
	"fmt"

	ag "stratium/services/agent-gateway"

	"stratium/internal/gateway"
	"stratium/internal/mcp"
)

func (r *Registry) registerAgentTools(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "register_agent",
		Description: "Register a new AI agent in the Stratium authorization platform. Returns agent_id and client_id.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"name":             {Type: "string", Description: "Agent display name"},
				"description":      {Type: "string", Description: "What this agent does"},
				"provider":         {Type: "string", Description: "Agent provider: anthropic, openai, or custom"},
				"model_identifier": {Type: "string", Description: "Model identifier, e.g. claude-sonnet-4-6"},
				"trust_tier":       {Type: "integer", Description: "Trust tier: 0=UNVERIFIED, 1=REGISTERED, 2=CERTIFIED, 3=PLATFORM_TRUSTED"},
				"allowed_tools":    {Type: "array", Description: "Tool whitelist (empty = unrestricted)", Items: &mcp.PropertySchema{Type: "string"}},
				"allowed_actions":  {Type: "array", Description: "Action tier whitelist", Items: &mcp.PropertySchema{Type: "integer"}},
			},
			Required: []string{"name", "provider", "trust_tier"},
		},
	}, r.handleRegisterAgent)

	server.RegisterTool(mcp.Tool{
		Name:        "get_agent",
		Description: "Retrieve details of a registered agent by ID.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"agent_id": {Type: "string", Description: "Agent UUID"},
			},
			Required: []string{"agent_id"},
		},
	}, r.handleGetAgent)

	server.RegisterTool(mcp.Tool{
		Name:        "list_agents",
		Description: "List all registered agents, optionally filtered by provider or trust tier.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"provider":   {Type: "string", Description: "Filter by provider (anthropic, openai, custom)"},
				"trust_tier": {Type: "integer", Description: "Filter by trust tier (0-3)"},
			},
		},
	}, r.handleListAgents)

	server.RegisterTool(mcp.Tool{
		Name:        "suspend_agent",
		Description: "Suspend an agent and revoke all its active delegations. Returns the count of revoked delegations.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"agent_id": {Type: "string", Description: "Agent UUID to suspend"},
				"reason":   {Type: "string", Description: "Reason for suspension"},
			},
			Required: []string{"agent_id", "reason"},
		},
	}, r.handleSuspendAgent)
}

type registerAgentArgs struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Provider        string   `json:"provider"`
	ModelIdentifier string   `json:"model_identifier"`
	TrustTier       int32    `json:"trust_tier"`
	AllowedTools    []string `json:"allowed_tools"`
	AllowedActions  []int32  `json:"allowed_actions"`
}

func (r *Registry) handleRegisterAgent(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[registerAgentArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	actionTiers := make([]ag.ActionTier, len(a.AllowedActions))
	for i, t := range a.AllowedActions {
		actionTiers[i] = ag.ActionTier(t)
	}

	resp, err := r.gateway.RegisterAgent(context.Background(), r.accessToken(), r.userID(), &ag.RegisterAgentRequest{
		Name:            a.Name,
		Description:     a.Description,
		Provider:        a.Provider,
		ModelIdentifier: a.ModelIdentifier,
		TrustTier:       ag.AgentTrustTier(a.TrustTier),
		AllowedTools:    a.AllowedTools,
		AllowedActions:  actionTiers,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}

	r.session.AgentID = resp.AgentId

	return mcp.SuccessResult(map[string]any{
		"agent_id":   resp.AgentId,
		"client_id":  resp.ClientId,
		"created_at": gateway.FormatTimestamp(resp.CreatedAt),
		"message":    fmt.Sprintf("Agent '%s' registered successfully at trust tier %d", a.Name, a.TrustTier),
	})
}

type getAgentArgs struct {
	AgentID string `json:"agent_id"`
}

func (r *Registry) handleGetAgent(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[getAgentArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	resp, err := r.gateway.GetAgent(context.Background(), r.accessToken(), r.userID(), a.AgentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get agent: %w", err)
	}

	agent := resp.Agent
	if agent == nil {
		return nil, fmt.Errorf("agent not found: %s", a.AgentID)
	}

	return mcp.SuccessResult(map[string]any{
		"agent_id":         agent.Id,
		"name":             agent.Name,
		"description":      agent.Description,
		"provider":         agent.Provider,
		"model_identifier": agent.ModelIdentifier,
		"trust_tier":       agent.TrustTier.Number(),
		"trust_tier_name":  agent.TrustTier.String(),
		"allowed_tools":    agent.AllowedTools,
		"cert_status":      agent.CertStatus.String(),
		"enabled":          agent.Enabled,
		"created_at":       gateway.FormatTimestamp(agent.CreatedAt),
	})
}

type listAgentsArgs struct {
	Provider  string `json:"provider"`
	TrustTier *int32 `json:"trust_tier"`
}

func (r *Registry) handleListAgents(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[listAgentsArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	req := &ag.ListAgentsRequest{
		EnabledOnly: true,
	}
	if a.TrustTier != nil {
		req.TrustTierFilter = ag.AgentTrustTier(*a.TrustTier)
	}

	resp, err := r.gateway.ListAgents(context.Background(), r.accessToken(), r.userID(), req)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}

	agents := make([]map[string]any, 0, len(resp.Agents))
	for _, agent := range resp.Agents {
		agents = append(agents, map[string]any{
			"agent_id":    agent.Id,
			"name":        agent.Name,
			"provider":    agent.Provider,
			"trust_tier":  agent.TrustTier.Number(),
			"cert_status": agent.CertStatus.String(),
			"enabled":     agent.Enabled,
		})
	}

	return mcp.SuccessResult(map[string]any{
		"agents": agents,
		"total":  len(agents),
	})
}

type suspendAgentArgs struct {
	AgentID string `json:"agent_id"`
	Reason  string `json:"reason"`
}

func (r *Registry) handleSuspendAgent(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[suspendAgentArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	resp, err := r.gateway.SuspendAgent(context.Background(), r.accessToken(), r.userID(), a.AgentID, a.Reason)
	if err != nil {
		return nil, fmt.Errorf("failed to suspend agent: %w", err)
	}

	return mcp.SuccessResult(map[string]any{
		"suspended":           true,
		"reason":              a.Reason,
		"revoked_delegations": resp.RevokedDelegations,
		"message":             fmt.Sprintf("Agent %s suspended. %d delegation(s) revoked.", a.AgentID, resp.RevokedDelegations),
	})
}
