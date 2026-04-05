package tools

import (
	"context"
	"encoding/json"
	"fmt"

	ag "stratium/services/agent-gateway"

	"stratium/internal/gateway"
	"stratium/internal/mcp"
)

func (r *Registry) registerDelegationTools(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "create_delegation",
		Description: "Create a root delegation token for an agent acting on behalf of the current user. The token is time-bounded and scope-limited.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"agent_id":           {Type: "string", Description: "Target agent UUID. Omit to use the last registered agent."},
				"approved_tools":     {Type: "array", Description: "Tools this delegation permits", Items: &mcp.PropertySchema{Type: "string"}},
				"max_action_tier":    {Type: "integer", Description: "Highest action tier: 0=REASONING, 1=READ_ONLY, 2=INTERNAL_MODIFY, 3=EXTERNAL_COMMS, 4=DESTRUCTIVE"},
				"classification_cap": {Type: "string", Description: "Max classification level: PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED"},
				"purpose":            {Type: "string", Description: "Why this delegation exists"},
				"ttl_seconds":        {Type: "integer", Description: "Time-to-live in seconds (default: 900)", Default: 900},
			},
			Required: []string{"approved_tools", "max_action_tier", "purpose"},
		},
	}, r.handleCreateDelegation)

	server.RegisterTool(mcp.Tool{
		Name:        "create_sub_delegation",
		Description: "Create a child delegation with narrower scope for a sub-agent. The child's scope must be a subset of the parent's.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"parent_delegation_token": {Type: "string", Description: "Parent's delegation token. Omit to use current session delegation."},
				"child_agent_id":          {Type: "string", Description: "Sub-agent UUID receiving the delegation"},
				"approved_tools":          {Type: "array", Description: "Must be a subset of parent's tools", Items: &mcp.PropertySchema{Type: "string"}},
				"max_action_tier":         {Type: "integer", Description: "Must be <= parent's tier"},
				"classification_cap":      {Type: "string", Description: "Must be <= parent's cap"},
				"purpose":                 {Type: "string", Description: "Sub-agent's purpose"},
				"ttl_seconds":             {Type: "integer", Description: "Must be <= parent's remaining TTL"},
			},
			Required: []string{"child_agent_id", "approved_tools", "max_action_tier", "purpose"},
		},
	}, r.handleCreateSubDelegation)

	server.RegisterTool(mcp.Tool{
		Name:        "revoke_delegation",
		Description: "Revoke a delegation and cascade revocation to all child delegations in the chain.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"delegation_id": {Type: "string", Description: "Delegation UUID to revoke. Omit to revoke current session delegation."},
				"reason":        {Type: "string", Description: "Reason for revocation"},
			},
			Required: []string{"reason"},
		},
	}, r.handleRevokeDelegation)

	server.RegisterTool(mcp.Tool{
		Name:        "list_delegations",
		Description: "List delegations for the current user, optionally filtered by agent.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"agent_id":    {Type: "string", Description: "Filter by agent UUID"},
				"active_only": {Type: "boolean", Description: "Only show active (non-expired, non-revoked) delegations", Default: true},
			},
		},
	}, r.handleListDelegations)
}

type createDelegationArgs struct {
	AgentID           string   `json:"agent_id"`
	ApprovedTools     []string `json:"approved_tools"`
	MaxActionTier     int32    `json:"max_action_tier"`
	ClassificationCap string   `json:"classification_cap"`
	Purpose           string   `json:"purpose"`
	TTLSeconds        int32    `json:"ttl_seconds"`
}

func (r *Registry) handleCreateDelegation(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[createDelegationArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	agentID := a.AgentID
	if agentID == "" {
		agentID = r.session.AgentID
	}
	if agentID == "" {
		return nil, fmt.Errorf("agent_id required (no agent registered in this session)")
	}

	ttl := a.TTLSeconds
	if ttl == 0 {
		ttl = 900
	}

	classCaps := map[string]string{}
	if a.ClassificationCap != "" {
		classCaps["financial"] = a.ClassificationCap
	}

	actionTiers := []ag.ActionTier{}
	for i := int32(0); i <= a.MaxActionTier; i++ {
		actionTiers = append(actionTiers, ag.ActionTier(i))
	}

	resp, err := r.gateway.CreateDelegation(context.Background(), r.accessToken(), r.userID(), &ag.CreateDelegationRequest{
		AgentId:            agentID,
		ApprovedTools:      a.ApprovedTools,
		ApprovedActions:    actionTiers,
		MaxActionTier:      ag.ActionTier(a.MaxActionTier),
		ClassificationCaps: classCaps,
		Purpose:            a.Purpose,
		TtlSeconds:         ttl,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create delegation: %w", err)
	}

	r.session.DelegationToken = resp.DelegationToken
	r.session.DelegationID = resp.DelegationId
	r.persistDelegation()

	return mcp.SuccessResult(map[string]any{
		"delegation_id": resp.DelegationId,
		"expires_at":    gateway.FormatTimestamp(resp.ExpiresAt),
		"depth":         resp.Depth,
		"ttl_seconds":   ttl,
		"scope": map[string]any{
			"approved_tools":     a.ApprovedTools,
			"max_action_tier":    a.MaxActionTier,
			"classification_cap": a.ClassificationCap,
		},
		"message": fmt.Sprintf("Delegation created. Expires at %s. Scope: tools=%v, max_tier=%d, cap=%s",
			gateway.FormatTimestamp(resp.ExpiresAt), a.ApprovedTools, a.MaxActionTier, a.ClassificationCap),
		"instructions": "You MUST call execute_action before every action to check authorization. " +
			"If denied, do NOT proceed — explain the denial reason to the user.",
	})
}

type createSubDelegationArgs struct {
	ParentDelegationToken string   `json:"parent_delegation_token"`
	ChildAgentID          string   `json:"child_agent_id"`
	ApprovedTools         []string `json:"approved_tools"`
	MaxActionTier         int32    `json:"max_action_tier"`
	ClassificationCap     string   `json:"classification_cap"`
	Purpose               string   `json:"purpose"`
	TTLSeconds            int32    `json:"ttl_seconds"`
}

func (r *Registry) handleCreateSubDelegation(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[createSubDelegationArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	parentToken := a.ParentDelegationToken
	if parentToken == "" {
		parentToken = r.session.DelegationToken
	}
	if parentToken == "" {
		return nil, fmt.Errorf("parent_delegation_token required (no active delegation in this session)")
	}

	ttl := a.TTLSeconds
	if ttl == 0 {
		ttl = 900
	}

	classCaps := map[string]string{}
	if a.ClassificationCap != "" {
		classCaps["financial"] = a.ClassificationCap
	}

	actionTiers := []ag.ActionTier{}
	for i := int32(0); i <= a.MaxActionTier; i++ {
		actionTiers = append(actionTiers, ag.ActionTier(i))
	}

	resp, err := r.gateway.CreateDelegation(context.Background(), r.accessToken(), r.userID(), &ag.CreateDelegationRequest{
		AgentId:                a.ChildAgentID,
		ApprovedTools:          a.ApprovedTools,
		ApprovedActions:        actionTiers,
		MaxActionTier:          ag.ActionTier(a.MaxActionTier),
		ClassificationCaps:     classCaps,
		Purpose:                a.Purpose,
		TtlSeconds:             ttl,
		ParentDelegationToken:  parentToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sub-delegation: %w", err)
	}

	return mcp.SuccessResult(map[string]any{
		"delegation_id":      resp.DelegationId,
		"delegation_token":   resp.DelegationToken,
		"expires_at":         gateway.FormatTimestamp(resp.ExpiresAt),
		"depth":              resp.Depth,
		"root_delegation_id": resp.RootDelegationId,
		"scope": map[string]any{
			"approved_tools":     a.ApprovedTools,
			"max_action_tier":    a.MaxActionTier,
			"classification_cap": a.ClassificationCap,
		},
		"message": fmt.Sprintf("Sub-delegation created at depth %d for agent %s (scope narrowed from parent)", resp.Depth, a.ChildAgentID),
	})
}

type revokeDelegationArgs struct {
	DelegationID string `json:"delegation_id"`
	Reason       string `json:"reason"`
}

func (r *Registry) handleRevokeDelegation(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[revokeDelegationArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	delegationID := a.DelegationID
	if delegationID == "" {
		delegationID = r.session.DelegationID
	}
	if delegationID == "" {
		return nil, fmt.Errorf("delegation_id required (no active delegation in this session)")
	}

	resp, err := r.gateway.RevokeDelegation(context.Background(), r.accessToken(), r.userID(), delegationID, a.Reason)
	if err != nil {
		return nil, fmt.Errorf("failed to revoke delegation: %w", err)
	}

	if delegationID == r.session.DelegationID {
		r.session.DelegationToken = ""
		r.session.DelegationID = ""
		r.clearDelegation()
	}

	return mcp.SuccessResult(map[string]any{
		"revoked":        true,
		"delegation_id":  delegationID,
		"reason":         a.Reason,
		"revoked_count":  resp.RevokedCount,
		"revoked_ids":    resp.RevokedDelegationIds,
		"message":        fmt.Sprintf("Delegation %s revoked (reason: %s). %d total delegation(s) revoked including children.", delegationID, a.Reason, resp.RevokedCount),
	})
}

type listDelegationsArgs struct {
	AgentID    string `json:"agent_id"`
	ActiveOnly *bool  `json:"active_only"`
}

func (r *Registry) handleListDelegations(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[listDelegationsArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	// ListAgents serves as a proxy here — in the real system, there would be
	// a ListDelegations RPC. For the demo, we return the session's delegation info.
	result := map[string]any{
		"current_session": map[string]any{
			"delegation_id":    r.session.DelegationID,
			"delegation_token": r.session.DelegationToken != "",
			"agent_id":         r.session.AgentID,
		},
	}

	if a.AgentID != "" {
		result["filter"] = map[string]any{"agent_id": a.AgentID}
	}

	return mcp.SuccessResult(result)
}
