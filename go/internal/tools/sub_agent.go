package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	ag "stratium/services/agent-gateway"

	"stratium/internal/gateway"
	"stratium/internal/mcp"
)

// SubAgentConfig holds configuration for spawning sub-agents.
type SubAgentConfig struct {
	PythonBinary string
	RunnerScript string
	MCPBinary    string
}

// SetSubAgentConfig sets the sub-agent configuration on the registry.
func (r *Registry) SetSubAgentConfig(cfg SubAgentConfig) {
	r.subAgentCfg = &cfg
}

func (r *Registry) registerSubAgentTools(server *mcp.Server) {
	server.RegisterTool(mcp.Tool{
		Name:        "orchestrate_sub_agent",
		Description: "Spawn a real Claude sub-agent with a narrower delegation. The sub-agent runs in its own session with restricted permissions. Returns the sub-agent's output. Permissions can ONLY be equal to or narrower than the parent delegation.",
		InputSchema: mcp.ToolSchema{
			Type: "object",
			Properties: map[string]mcp.PropertySchema{
				"task":               {Type: "string", Description: "Natural language task for the sub-agent"},
				"sub_agent_name":     {Type: "string", Description: "Display name for the sub-agent"},
				"approved_tools":     {Type: "array", Description: "Tools the sub-agent can use (must be subset of parent's tools)", Items: &mcp.PropertySchema{Type: "string"}},
				"max_action_tier":    {Type: "integer", Description: "Max action tier (must be <= parent's tier)"},
				"classification_cap": {Type: "string", Description: "Max classification (must be <= parent's cap)"},
			},
			Required: []string{"task", "sub_agent_name", "approved_tools", "max_action_tier"},
		},
	}, r.handleOrchestrateSubAgent)
}

type orchestrateSubAgentArgs struct {
	Task              string   `json:"task"`
	SubAgentName      string   `json:"sub_agent_name"`
	ApprovedTools     []string `json:"approved_tools"`
	MaxActionTier     int32    `json:"max_action_tier"`
	ClassificationCap string   `json:"classification_cap"`
}

func (r *Registry) handleOrchestrateSubAgent(args json.RawMessage) (*mcp.ToolCallResult, error) {
	a, err := parseArgs[orchestrateSubAgentArgs](args)
	if err != nil {
		return nil, err
	}

	if err := r.ensureAuth(context.Background()); err != nil {
		return nil, err
	}

	if r.session.DelegationToken == "" {
		return nil, fmt.Errorf("no active delegation — create a delegation first")
	}

	// Step 1: Register the sub-agent
	actionTiers := []ag.ActionTier{}
	for i := int32(0); i <= a.MaxActionTier; i++ {
		actionTiers = append(actionTiers, ag.ActionTier(i))
	}

	regResp, err := r.gateway.RegisterAgent(context.Background(), r.accessToken(), r.userID(), &ag.RegisterAgentRequest{
		Name:           a.SubAgentName,
		Description:    fmt.Sprintf("Sub-agent for: %s", a.Task),
		Provider:       "anthropic",
		TrustTier:      ag.AgentTrustTier_AGENT_TRUST_TIER_UNVERIFIED,
		AllowedTools:   a.ApprovedTools,
		AllowedActions: actionTiers,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register sub-agent: %w", err)
	}
	r.logger.Printf("sub-agent registered: %s (id: %s)", a.SubAgentName, regResp.AgentId)

	// Step 2: Create child delegation
	classCaps := map[string]string{}
	if a.ClassificationCap != "" {
		classCaps["financial"] = a.ClassificationCap
	}

	delResp, err := r.gateway.CreateDelegation(context.Background(), r.accessToken(), r.userID(), &ag.CreateDelegationRequest{
		AgentId:               regResp.AgentId,
		ApprovedTools:         a.ApprovedTools,
		ApprovedActions:       actionTiers,
		MaxActionTier:         ag.ActionTier(a.MaxActionTier),
		ClassificationCaps:    classCaps,
		Purpose:               a.Task,
		TtlSeconds:            300,
		ParentDelegationToken: r.session.DelegationToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sub-delegation: %w", err)
	}
	r.logger.Printf("sub-delegation created at depth %d (id: %s)", delResp.Depth, delResp.DelegationId)

	// Step 3: Run the sub-agent via Python Agent SDK
	output, runErr := r.runSubAgent(a.Task, delResp.DelegationToken, a.SubAgentName)

	// Step 4: Clean up — revoke the child delegation
	_, revokeErr := r.gateway.RevokeDelegation(context.Background(), r.accessToken(), r.userID(), delResp.DelegationId, "sub-agent task completed")
	if revokeErr != nil {
		r.logger.Printf("warning: failed to revoke sub-delegation: %v", revokeErr)
	}

	if runErr != nil {
		return mcp.SuccessResult(map[string]any{
			"sub_agent":     a.SubAgentName,
			"agent_id":      regResp.AgentId,
			"delegation_id": delResp.DelegationId,
			"depth":         delResp.Depth,
			"status":        "error",
			"error":         runErr.Error(),
			"message":       fmt.Sprintf("Sub-agent '%s' failed: %v", a.SubAgentName, runErr),
		})
	}

	return mcp.SuccessResult(map[string]any{
		"sub_agent":     a.SubAgentName,
		"agent_id":      regResp.AgentId,
		"delegation_id": delResp.DelegationId,
		"depth":         delResp.Depth,
		"expires_at":    gateway.FormatTimestamp(delResp.ExpiresAt),
		"status":        "completed",
		"output":        output,
		"message":       fmt.Sprintf("Sub-agent '%s' completed task at depth %d. Delegation revoked after completion.", a.SubAgentName, delResp.Depth),
	})
}

func (r *Registry) runSubAgent(task, delegationToken, agentName string) (string, error) {
	if r.subAgentCfg == nil || r.subAgentCfg.RunnerScript == "" {
		return "", fmt.Errorf("sub-agent runner not configured (set --sub-agent-runner flag)")
	}

	// Write temporary MCP config for the sub-agent
	tmpDir, err := os.MkdirTemp("", "stratium-subagent-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	mcpConfigPath := filepath.Join(tmpDir, "mcp_config.json")
	mcpConfig := map[string]any{
		"mcpServers": map[string]any{
			"stratium": map[string]any{
				"command": r.subAgentCfg.MCPBinary,
				"args":    []string{},
				"env": map[string]string{
					"STRATIUM_DELEGATION_TOKEN": delegationToken,
				},
			},
		},
	}
	configData, _ := json.MarshalIndent(mcpConfig, "", "  ")
	if err := os.WriteFile(mcpConfigPath, configData, 0600); err != nil {
		return "", fmt.Errorf("failed to write MCP config: %w", err)
	}

	pythonBin := r.subAgentCfg.PythonBinary
	if pythonBin == "" {
		pythonBin = "python3"
	}

	cmd := exec.CommandContext(context.Background(), pythonBin, r.subAgentCfg.RunnerScript,
		"--task", task,
		"--agent-name", agentName,
		"--mcp-config", mcpConfigPath,
		"--delegation-token", delegationToken,
	)
	cmd.Env = append(os.Environ(), "STRATIUM_DELEGATION_TOKEN="+delegationToken)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("sub-agent process failed: %w\noutput: %s", err, string(output))
	}

	return string(output), nil
}
