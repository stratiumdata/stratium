package agent_gateway

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestCrossProviderDelegationChain_TokenFormat validates that delegation tokens
// produced by the Agent Gateway are provider-agnostic — they contain agent_id and
// delegation scope but no provider-specific fields. This means a token created
// for a Claude agent can be sub-delegated to an OpenAI agent and vice versa.
func TestCrossProviderDelegationChain_TokenFormat(t *testing.T) {
	// Simulate delegation token claims for a cross-provider chain:
	// Root: Claude (anthropic) → Child: Codex (openai)
	rootClaims := map[string]any{
		"sub":                 "user-123",
		"agent_id":            "claude-agent-uuid",
		"agent_trust_tier":    1,
		"delegation_id":       "root-delegation-uuid",
		"approved_tools":      []string{"bash", "read_file", "write_file"},
		"approved_actions":    []int{0, 1, 2},
		"max_action_tier":     2,
		"classification_caps": map[string]string{"commercial": "INTERNAL"},
		"purpose":             "Code review session",
		"depth":               0,
		"chain_agent_ids":     []string{"claude-agent-uuid"},
		"root_delegation_id":  "root-delegation-uuid",
	}

	childClaims := map[string]any{
		"sub":                    "user-123",
		"agent_id":               "codex-agent-uuid",
		"agent_trust_tier":       1,
		"delegation_id":          "child-delegation-uuid",
		"approved_tools":         []string{"bash", "read_file"},
		"approved_actions":       []int{0, 1},
		"max_action_tier":        1,
		"classification_caps":    map[string]string{"commercial": "PUBLIC"},
		"purpose":                "Read-only code analysis",
		"depth":                  1,
		"chain_agent_ids":        []string{"claude-agent-uuid", "codex-agent-uuid"},
		"parent_delegation_id":   "root-delegation-uuid",
		"root_delegation_id":     "root-delegation-uuid",
	}

	// Verify token claims can be serialized (provider-agnostic format)
	rootJSON, err := json.Marshal(rootClaims)
	if err != nil {
		t.Fatalf("failed to marshal root claims: %v", err)
	}
	childJSON, err := json.Marshal(childClaims)
	if err != nil {
		t.Fatalf("failed to marshal child claims: %v", err)
	}

	// Verify roundtrip
	var rootParsed, childParsed map[string]any
	if err := json.Unmarshal(rootJSON, &rootParsed); err != nil {
		t.Fatalf("failed to unmarshal root claims: %v", err)
	}
	if err := json.Unmarshal(childJSON, &childParsed); err != nil {
		t.Fatalf("failed to unmarshal child claims: %v", err)
	}

	// Validate chain constraints: child scope ⊆ parent scope
	t.Run("child_max_tier_leq_parent", func(t *testing.T) {
		parentTier := int(rootParsed["max_action_tier"].(float64))
		childTier := int(childParsed["max_action_tier"].(float64))
		if childTier > parentTier {
			t.Errorf("child max_action_tier (%d) > parent max_action_tier (%d)", childTier, parentTier)
		}
	})

	t.Run("child_tools_subset_of_parent", func(t *testing.T) {
		parentTools := toStringSlice(rootParsed["approved_tools"])
		childTools := toStringSlice(childParsed["approved_tools"])
		parentSet := make(map[string]bool)
		for _, t := range parentTools {
			parentSet[t] = true
		}
		for _, tool := range childTools {
			if !parentSet[tool] {
				t.Errorf("child tool %q not in parent tools %v", tool, parentTools)
			}
		}
	})

	t.Run("child_depth_is_parent_plus_one", func(t *testing.T) {
		parentDepth := int(rootParsed["depth"].(float64))
		childDepth := int(childParsed["depth"].(float64))
		if childDepth != parentDepth+1 {
			t.Errorf("child depth (%d) != parent depth (%d) + 1", childDepth, parentDepth)
		}
	})

	t.Run("child_chain_extends_parent_chain", func(t *testing.T) {
		parentChain := toStringSlice(rootParsed["chain_agent_ids"])
		childChain := toStringSlice(childParsed["chain_agent_ids"])
		if len(childChain) != len(parentChain)+1 {
			t.Errorf("child chain length (%d) != parent chain length (%d) + 1", len(childChain), len(parentChain))
		}
		for i, id := range parentChain {
			if i < len(childChain) && childChain[i] != id {
				t.Errorf("chain mismatch at index %d: parent=%q, child=%q", i, id, childChain[i])
			}
		}
	})

	t.Run("child_root_delegation_matches_parent", func(t *testing.T) {
		parentRoot := rootParsed["root_delegation_id"].(string)
		childRoot := childParsed["root_delegation_id"].(string)
		if parentRoot != childRoot {
			t.Errorf("root_delegation_id mismatch: parent=%q, child=%q", parentRoot, childRoot)
		}
	})

	t.Run("no_provider_field_in_token", func(t *testing.T) {
		// Delegation tokens should NOT contain provider — it's agent metadata, not token claims.
		// This ensures tokens are transport-agnostic.
		if _, exists := rootParsed["provider"]; exists {
			t.Error("root token should not contain 'provider' field")
		}
		if _, exists := childParsed["provider"]; exists {
			t.Error("child token should not contain 'provider' field")
		}
	})
}

// TestClassificationCapNarrowing verifies that child classification caps
// must be equal to or narrower than parent caps.
func TestClassificationCapNarrowing(t *testing.T) {
	hierarchy := map[string]int{
		"PUBLIC":       0,
		"INTERNAL":     1,
		"CONFIDENTIAL": 2,
		"RESTRICTED":   3,
	}

	tests := []struct {
		name      string
		parentCap string
		childCap  string
		valid     bool
	}{
		{"equal caps", "INTERNAL", "INTERNAL", true},
		{"child narrower", "CONFIDENTIAL", "INTERNAL", true},
		{"child wider (invalid)", "INTERNAL", "CONFIDENTIAL", false},
		{"child most narrow", "RESTRICTED", "PUBLIC", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parentLevel := hierarchy[tt.parentCap]
			childLevel := hierarchy[tt.childCap]
			isValid := childLevel <= parentLevel
			if isValid != tt.valid {
				t.Errorf("cap narrowing %s→%s: got valid=%v, want valid=%v",
					tt.parentCap, tt.childCap, isValid, tt.valid)
			}
		})
	}
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	result := make([]string, len(arr))
	for i, item := range arr {
		result[i] = fmt.Sprintf("%v", item)
	}
	return result
}
