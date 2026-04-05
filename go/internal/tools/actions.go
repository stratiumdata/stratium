package tools

import (
	"context"
	"encoding/json"
	"fmt"

	ag "stratium/services/agent-gateway"

	"stratium/internal/gateway"
	"stratium/internal/mcp"
)

func (r *Registry) registerActionTools(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "execute_action",
		Description: "MANDATORY: Call this BEFORE performing any action (reading, writing, executing). Checks authorization against the delegation's scope, agent trust tier, and user permissions. Returns ALLOW or DENY with reasoning. If DENY, do NOT proceed with the action — explain the denial to the user instead.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"delegation_token":        {Type: "string", Description: "Active delegation JWT. Omit to use current session delegation."},
				"tool_name":               {Type: "string", Description: "Tool being invoked (e.g., read_file, write_file)"},
				"action":                  {Type: "string", Description: "Action type: read, write, delete, execute, send"},
				"action_tier":             {Type: "integer", Description: "0=REASONING, 1=READ_ONLY, 2=INTERNAL_MODIFY, 3=EXTERNAL_COMMS, 4=DESTRUCTIVE"},
				"resource_id":             {Type: "string", Description: "Target resource identifier"},
				"resource_classification": {Type: "string", Description: "Resource classification: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED"},
			},
			Required: []string{"tool_name", "action", "action_tier"},
		},
	}, r.handleExecuteAction)

	server.RegisterTool(mcp.Tool{
		Name:        "check_permission",
		Description: "Dry-run permission check without executing the action. Returns the authorization decision that WOULD be made.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"delegation_token":        {Type: "string", Description: "Active delegation JWT. Omit to use current session delegation."},
				"tool_name":               {Type: "string", Description: "Tool to check"},
				"action":                  {Type: "string", Description: "Action type"},
				"action_tier":             {Type: "integer", Description: "Action tier (0-4)"},
				"resource_classification": {Type: "string", Description: "Resource classification level"},
			},
			Required: []string{"tool_name", "action", "action_tier"},
		},
	}, r.handleCheckPermission)

	server.RegisterTool(mcp.Tool{
		Name:        "validate_action_plan",
		Description: "Validate a batch of planned actions against the delegation's scope. Returns per-action allow/deny results without executing anything.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"delegation_id": {Type: "string", Description: "Delegation UUID. Omit to use current session delegation."},
				"actions": {Type: "array", Description: "Actions to validate", Items: &mcp.PropertySchema{
					Type: "object",
				}},
			},
			Required: []string{"actions"},
		},
	}, r.handleValidateActionPlan)

	server.RegisterTool(mcp.Tool{
		Name:        "get_delegation_chain",
		Description: "Inspect the full delegation chain showing each hop's agent, trust tier, scope, and status. Useful for debugging authorization decisions.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"delegation_id": {Type: "string", Description: "Delegation UUID to inspect. Omit to use current session delegation."},
			},
		},
	}, r.handleGetDelegationChain)
}

type executeActionArgs struct {
	DelegationToken        string `json:"delegation_token"`
	ToolName               string `json:"tool_name"`
	Action                 string `json:"action"`
	ActionTier             int32  `json:"action_tier"`
	ResourceID             string `json:"resource_id"`
	ResourceClassification string `json:"resource_classification"`
}

func (r *Registry) handleExecuteAction(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[executeActionArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	token := a.DelegationToken
	if token == "" {
		token = r.session.DelegationToken
	}
	if token == "" {
		return nil, fmt.Errorf("delegation_token required (no active delegation in this session)")
	}

	resourceAttrs := map[string]string{}
	if a.ResourceID != "" {
		resourceAttrs["resource_id"] = a.ResourceID
	}
	if a.ResourceClassification != "" {
		resourceAttrs["classification"] = a.ResourceClassification
	}

	resp, err := r.gateway.ExecuteAction(context.Background(), r.accessToken(), r.userID(), &ag.ExecuteActionRequest{
		DelegationToken:    token,
		ToolName:           a.ToolName,
		Action:             a.Action,
		ActionTier:         ag.ActionTier(a.ActionTier),
		ResourceAttributes: resourceAttrs,
	})
	if err != nil {
		return nil, fmt.Errorf("execute_action RPC failed: %w", err)
	}

	// Build a concise response — Claude needs authorized/denied + reason, not the full decision tree
	reason := ""
	if resp.Decision != nil {
		if resp.Decision.DelegationReason != "" {
			reason = resp.Decision.DelegationReason
		} else if resp.Decision.AgentReason != "" {
			reason = resp.Decision.AgentReason
		} else if resp.Decision.UserReason != "" {
			reason = resp.Decision.UserReason
		}
		if resp.Decision.DeniedPrincipal != "" {
			reason = fmt.Sprintf("%s (denied by %s)", reason, resp.Decision.DeniedPrincipal)
		}
	}
	if resp.Error != "" {
		reason = resp.Error
	}

	result := map[string]any{
		"authorized": resp.Authorized,
		"tool":       a.ToolName,
		"action":     a.Action,
		"tier":       a.ActionTier,
	}

	if a.ResourceClassification != "" {
		result["resource_classification"] = a.ResourceClassification
	}

	if resp.Authorized {
		result["message"] = fmt.Sprintf("ALLOWED: %s %s (tier %d)", a.Action, a.ToolName, a.ActionTier)
	} else {
		result["message"] = fmt.Sprintf("DENIED: %s %s (tier %d) — %s", a.Action, a.ToolName, a.ActionTier, reason)
		result["reason"] = reason
	}

	return mcp.SuccessResult(result)
}

func (r *Registry) handleCheckPermission(args json.RawMessage) (*mcp.ToolCallResult, error) {
	return r.handleExecuteAction(args)
}

type validateActionPlanArgs struct {
	DelegationID string          `json:"delegation_id"`
	Actions      json.RawMessage `json:"actions"`
}

type plannedAction struct {
	ToolName               string `json:"tool_name"`
	Action                 string `json:"action"`
	ActionTier             int32  `json:"action_tier"`
	ResourceClassification string `json:"resource_classification"`
}

func (r *Registry) handleValidateActionPlan(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[validateActionPlanArgs](args)
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

	var actions []plannedAction
	if err := json.Unmarshal(a.Actions, &actions); err != nil {
		return nil, fmt.Errorf("invalid actions array: %w", err)
	}

	protoActions := make([]*ag.PlannedAction, 0, len(actions))
	for _, act := range actions {
		resource := map[string]string{}
		if act.ResourceClassification != "" {
			resource["classification"] = act.ResourceClassification
		}
		protoActions = append(protoActions, &ag.PlannedAction{
			ToolName:     act.ToolName,
			Action:       act.Action,
			DeclaredTier: ag.ActionTier(act.ActionTier),
			Resource:     resource,
		})
	}

	resp, err := r.gateway.ValidateActionPlan(context.Background(), r.accessToken(), r.userID(), &ag.ValidateActionPlanRequest{
		DelegationId: delegationID,
		Actions:      protoActions,
	})
	if err != nil {
		return nil, fmt.Errorf("validate_action_plan RPC failed: %w", err)
	}

	results := make([]map[string]any, 0, len(resp.Results))
	allowedCount := 0
	for i, vr := range resp.Results {
		toolName := ""
		action := ""
		if i < len(actions) {
			toolName = actions[i].ToolName
			action = actions[i].Action
		}
		entry := map[string]any{
			"tool_name":    toolName,
			"action":       action,
			"valid":        vr.Valid,
			"reason":       vr.Reason,
			"actual_tier":  vr.ActualTier.Number(),
			"tier_mismatch": vr.TierMismatch,
		}
		if vr.Valid {
			allowedCount++
		}
		results = append(results, entry)
	}

	return mcp.SuccessResult(map[string]any{
		"valid":   resp.Valid,
		"results": results,
		"message": fmt.Sprintf("Validated %d actions: %d valid, %d invalid",
			len(results), allowedCount, len(results)-allowedCount),
	})
}

type getDelegationChainArgs struct {
	DelegationID string `json:"delegation_id"`
}

func (r *Registry) handleGetDelegationChain(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[getDelegationChainArgs](args)
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

	resp, err := r.gateway.GetDelegationChain(context.Background(), r.accessToken(), r.userID(), delegationID)
	if err != nil {
		return nil, fmt.Errorf("get_delegation_chain RPC failed: %w", err)
	}

	links := make([]map[string]any, 0, len(resp.Chain))
	for _, link := range resp.Chain {
		entry := map[string]any{
			"depth":           link.Depth,
			"agent_id":        link.AgentId,
			"agent_name":      link.AgentName,
			"trust_tier":      link.TrustTier.Number(),
			"approved_tools":  link.ApprovedTools,
			"max_action_tier": link.MaxActionTier.Number(),
			"expires_at":      gateway.FormatTimestamp(link.ExpiresAt),
			"revoked":         link.Revoked,
		}
		if link.ClassificationCaps != nil {
			entry["classification_caps"] = link.ClassificationCaps
		}
		links = append(links, entry)
	}

	return mcp.SuccessResult(map[string]any{
		"delegation_id": delegationID,
		"chain_depth":   len(links),
		"chain":         links,
	})
}
