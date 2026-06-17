package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	ag "stratium/services/agent-gateway"

	"stratium/internal/gateway"
)

// CheckRequest is the JSON input for --mode=check.
type CheckRequest struct {
	ToolName               string `json:"tool_name"`
	Action                 string `json:"action"`
	ActionTier             int32  `json:"action_tier"`
	ResourceID             string `json:"resource_id,omitempty"`
	ResourceClassification string `json:"resource_classification,omitempty"`
}

// CheckResponse is the JSON output for --mode=check.
type CheckResponse struct {
	Authorized bool            `json:"authorized"`
	Decision   *CheckDecision  `json:"decision,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// CheckDecision holds the breakdown of the authorization decision.
type CheckDecision struct {
	UserDecision       string `json:"user_decision,omitempty"`
	UserReason         string `json:"user_reason,omitempty"`
	AgentDecision      string `json:"agent_decision,omitempty"`
	AgentReason        string `json:"agent_reason,omitempty"`
	DelegationDecision string `json:"delegation_decision,omitempty"`
	DelegationReason   string `json:"delegation_reason,omitempty"`
}

// RunCheck executes a single authorization check and writes the result to stdout.
// It reads a CheckRequest from stdin, calls the Agent Gateway, and exits.
// The delegation token is read from STRATIUM_DELEGATION_TOKEN env var.
// The OIDC token for the Gateway call is extracted from the delegation token's
// cached session at ~/.stratium/token.json.
func RunCheck(gwClient *gateway.Client, delegationToken, accessToken, userID string) error {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		return writeCheckError("failed to read stdin: %v", err)
	}

	var req CheckRequest
	if err := json.Unmarshal(input, &req); err != nil {
		return writeCheckError("invalid JSON input: %v", err)
	}

	if req.ToolName == "" {
		return writeCheckError("tool_name is required")
	}
	if req.Action == "" {
		return writeCheckError("action is required")
	}

	resourceAttrs := map[string]string{}
	if req.ResourceID != "" {
		resourceAttrs["resource_id"] = req.ResourceID
	}
	if req.ResourceClassification != "" {
		resourceAttrs["classification"] = req.ResourceClassification
	}

	resp, err := gwClient.ExecuteAction(context.Background(), accessToken, userID, &ag.ExecuteActionRequest{
		DelegationToken:    delegationToken,
		ToolName:           req.ToolName,
		Action:             req.Action,
		ActionTier:         ag.ActionTier(req.ActionTier),
		ResourceAttributes: resourceAttrs,
	})
	if err != nil {
		return writeCheckError("gateway call failed: %v", err)
	}

	result := CheckResponse{
		Authorized: resp.Authorized,
	}

	if resp.Decision != nil {
		result.Decision = &CheckDecision{
			UserDecision: decisionString(resp.Decision.UserDecision),
			UserReason:   resp.Decision.UserReason,
		}
		// The Gateway sets agent/delegation decisions on ChainDecisions (per-hop),
		// not on the top-level compound fields. Extract from depth 0 if available.
		if len(resp.Decision.ChainDecisions) > 0 {
			hop := resp.Decision.ChainDecisions[0]
			result.Decision.AgentDecision = decisionString(hop.AgentDecision)
			result.Decision.AgentReason = hop.AgentReason
			result.Decision.DelegationDecision = decisionString(hop.DelegationDecision)
			result.Decision.DelegationReason = hop.DelegationReason
		} else {
			// Fallback to top-level fields (backward compat)
			result.Decision.AgentDecision = decisionString(resp.Decision.AgentDecision)
			result.Decision.AgentReason = resp.Decision.AgentReason
			result.Decision.DelegationDecision = decisionString(resp.Decision.DelegationDecision)
			result.Decision.DelegationReason = resp.Decision.DelegationReason
		}
	}
	if resp.Error != "" {
		result.Error = resp.Error
	}

	return writeCheckResult(result)
}

// decisionString converts a proto Decision enum to a human-readable string.
// Returns "ALLOW", "DENY", "CONDITIONAL", or empty string for unspecified/zero values.
func decisionString(d ag.Decision) string {
	switch d {
	case ag.Decision_DECISION_ALLOW:
		return "ALLOW"
	case ag.Decision_DECISION_DENY:
		return "DENY"
	case ag.Decision_DECISION_CONDITIONAL:
		return "CONDITIONAL"
	default:
		return ""
	}
}

func writeCheckResult(result CheckResponse) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(result)
}

func writeCheckError(format string, args ...any) error {
	result := CheckResponse{
		Authorized: false,
		Error:      fmt.Sprintf(format, args...),
	}
	return writeCheckResult(result)
}
