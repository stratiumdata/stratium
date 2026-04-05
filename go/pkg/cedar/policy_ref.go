package cedar

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PolicyRef represents a Cedar policy reference embedded in a ZTDF manifest.
// When the `policy` field in a WrapDEK/UnwrapDEK request starts with the
// "cedar:" prefix, it is treated as a Cedar policy reference rather than a
// base64-encoded inline policy.
type PolicyRef struct {
	Engine        string `json:"engine"`
	PolicyID      string `json:"policy_id"`
	SchemaVersion string `json:"schema_version,omitempty"`
}

// CedarPolicyRefPrefix is the prefix that identifies a Cedar policy reference
// in the ZTDF manifest policy field.
const CedarPolicyRefPrefix = "cedar:"

// IsCedarPolicyRef checks if a policy string is a Cedar policy reference.
// Cedar policy references use the "cedar:" prefix or are JSON with engine="cedar".
func IsCedarPolicyRef(policy string) bool {
	trimmed := strings.TrimSpace(policy)
	if strings.HasPrefix(trimmed, CedarPolicyRefPrefix) {
		return true
	}
	// Also check for JSON format: {"engine": "cedar", ...}
	if strings.HasPrefix(trimmed, "{") {
		var ref PolicyRef
		if err := json.Unmarshal([]byte(trimmed), &ref); err == nil {
			return ref.Engine == "cedar"
		}
	}
	return false
}

// ParsePolicyRef parses a Cedar policy reference from the policy string.
// Supports two formats:
//   - Simple: "cedar:<policy-id>"
//   - JSON:   {"engine": "cedar", "policy_id": "<id>", "schema_version": "1.0"}
func ParsePolicyRef(policy string) (*PolicyRef, error) {
	trimmed := strings.TrimSpace(policy)

	// Simple format: "cedar:<policy-id>"
	if strings.HasPrefix(trimmed, CedarPolicyRefPrefix) {
		policyID := strings.TrimPrefix(trimmed, CedarPolicyRefPrefix)
		if policyID == "" {
			return nil, fmt.Errorf("cedar policy reference has empty policy ID")
		}
		return &PolicyRef{
			Engine:   "cedar",
			PolicyID: policyID,
		}, nil
	}

	// JSON format
	if strings.HasPrefix(trimmed, "{") {
		var ref PolicyRef
		if err := json.Unmarshal([]byte(trimmed), &ref); err != nil {
			return nil, fmt.Errorf("invalid Cedar policy reference JSON: %w", err)
		}
		if ref.Engine != "cedar" {
			return nil, fmt.Errorf("policy reference engine must be 'cedar', got %q", ref.Engine)
		}
		if ref.PolicyID == "" {
			return nil, fmt.Errorf("policy reference must have a policy_id")
		}
		return &ref, nil
	}

	return nil, fmt.Errorf("unrecognized Cedar policy reference format")
}

// String returns the simple string representation of a PolicyRef.
func (r *PolicyRef) String() string {
	return CedarPolicyRefPrefix + r.PolicyID
}
