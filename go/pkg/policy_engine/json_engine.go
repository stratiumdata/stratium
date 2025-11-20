package policy_engine

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"stratium/pkg/models"
)

// JSONEngine implements PolicyEngine for JSON-based policies
type JSONEngine struct{}

// NewJSONEngine creates a new JSON policy engine
func NewJSONEngine() PolicyEngine {
	return &JSONEngine{}
}

// JSONPolicy represents a JSON policy structure
type JSONPolicy struct {
	Version string     `json:"version"`
	Rules   []JSONRule `json:"rules"`
}

// JSONRule represents a single rule in a JSON policy
type JSONRule struct {
	ID          string                 `json:"id"`
	Description string                 `json:"description,omitempty"`
	Effect      string                 `json:"effect"` // "allow" or "deny"
	Conditions  JSONConditions         `json:"conditions"`
	Priority    int                    `json:"priority,omitempty"`
}

// JSONConditions represents the conditions for a rule
type JSONConditions struct {
	Subject     map[string]interface{} `json:"subject,omitempty"`
	Resource    map[string]interface{} `json:"resource,omitempty"`
	Action      interface{}            `json:"action,omitempty"` // string or []string
	Environment map[string]interface{} `json:"environment,omitempty"`
	AllOf       []JSONConditions       `json:"allOf,omitempty"` // AND logic
	AnyOf       []JSONConditions       `json:"anyOf,omitempty"` // OR logic
}

// ValidatePolicy validates the syntax of a JSON policy
func (e *JSONEngine) ValidatePolicy(ctx context.Context, policyContent string, language models.PolicyLanguage) error {
	if language != models.PolicyLanguageJSON {
		return fmt.Errorf("invalid language for JSON engine: %s", language)
	}

	// Parse the JSON policy
	var policy JSONPolicy
	if err := json.Unmarshal([]byte(policyContent), &policy); err != nil {
		return fmt.Errorf("invalid JSON policy: %w", err)
	}

	// Validate required fields
	if policy.Version == "" {
		return fmt.Errorf("JSON policy must have a version field")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("JSON policy must have at least one rule")
	}

	// Validate each rule
	for i, rule := range policy.Rules {
		if rule.ID == "" {
			return fmt.Errorf("Rule %d must have an id field", i)
		}
		if rule.Effect != "allow" && rule.Effect != "deny" {
			return fmt.Errorf("Rule %s has invalid effect: %s (must be 'allow' or 'deny')", rule.ID, rule.Effect)
		}
	}

	return nil
}

// Evaluate evaluates a JSON policy against input
func (e *JSONEngine) Evaluate(ctx context.Context, policy *models.Policy, input *EvaluationInput) (*EvaluationResult, error) {
	if policy.Language != models.PolicyLanguageJSON {
		return nil, fmt.Errorf("policy language must be JSON")
	}

	// Parse the JSON policy
	var jsonPolicy JSONPolicy
	if err := json.Unmarshal([]byte(policy.PolicyContent), &jsonPolicy); err != nil {
		return nil, fmt.Errorf("failed to parse JSON policy: %w", err)
	}

	result := &EvaluationResult{
		Allow:      false,
		PolicyName: policy.Name,
		Details:    make(map[string]interface{}),
	}

	// Evaluate rules in order
	matchedRules := []string{}
	for _, rule := range jsonPolicy.Rules {
		if e.evaluateRule(rule, input) {
			matchedRules = append(matchedRules, rule.ID)

			if rule.Effect == "allow" {
				result.Allow = true
				result.Reason = fmt.Sprintf("Rule %s permits access", rule.ID)
				if rule.Description != "" {
					result.Reason = fmt.Sprintf("Rule %s permits access: %s", rule.ID, rule.Description)
				}
			} else if rule.Effect == "deny" {
				result.Allow = false
				result.Reason = fmt.Sprintf("Rule %s denies access", rule.ID)
				if rule.Description != "" {
					result.Reason = fmt.Sprintf("Rule %s denies access: %s", rule.ID, rule.Description)
				}
				// Deny takes precedence - stop evaluation
				result.Details["matched_rules"] = matchedRules
				result.Details["total_rules"] = len(jsonPolicy.Rules)
				return result, nil
			}
		}
	}

	if result.Reason == "" {
		result.Reason = "No matching rule found - default deny"
	}

	result.Details["matched_rules"] = matchedRules
	result.Details["total_rules"] = len(jsonPolicy.Rules)

	return result, nil
}

// evaluateRule checks if a rule matches the input
func (e *JSONEngine) evaluateRule(rule JSONRule, input *EvaluationInput) bool {
	return e.evaluateConditions(rule.Conditions, input)
}

// evaluateConditions recursively evaluates conditions
func (e *JSONEngine) evaluateConditions(conditions JSONConditions, input *EvaluationInput) bool {
	// Handle AllOf (AND logic)
	if len(conditions.AllOf) > 0 {
		for _, cond := range conditions.AllOf {
			if !e.evaluateConditions(cond, input) {
				return false
			}
		}
		return true
	}

	// Handle AnyOf (OR logic)
	if len(conditions.AnyOf) > 0 {
		for _, cond := range conditions.AnyOf {
			if e.evaluateConditions(cond, input) {
				return true
			}
		}
		return false
	}

	// Evaluate direct conditions
	matched := true

	// Check subject attributes
	if len(conditions.Subject) > 0 {
		if !e.matchAttributes(conditions.Subject, input.Subject) {
			matched = false
		}
	}

	// Check resource attributes
	if len(conditions.Resource) > 0 {
		if !e.matchAttributes(conditions.Resource, input.Resource) {
			matched = false
		}
	}

	// Check action
	if conditions.Action != nil {
		if !e.matchAction(conditions.Action, input.Action) {
			matched = false
		}
	}

	// Check environment attributes
	if len(conditions.Environment) > 0 {
		if !e.matchAttributes(conditions.Environment, input.Environment) {
			matched = false
		}
	}

	return matched
}

// matchAttributes checks if all required attributes match
func (e *JSONEngine) matchAttributes(required map[string]interface{}, provided map[string]interface{}) bool {
	for key, requiredValue := range required {
		providedValue, exists := provided[key]
		if !exists {
			return false
		}

		// Handle different comparison operators
		if !e.matchValue(requiredValue, providedValue) {
			return false
		}
	}
	return true
}

// matchValue compares two values, supporting operators
func (e *JSONEngine) matchValue(required interface{}, provided interface{}) bool {
	// If required is a map, it might contain operators
	if reqMap, ok := required.(map[string]interface{}); ok {
		// Check for operators
		if eq, ok := reqMap["$eq"]; ok {
			return e.equals(eq, provided)
		}
		if ne, ok := reqMap["$ne"]; ok {
			return !e.equals(ne, provided)
		}
		if in, ok := reqMap["$in"]; ok {
			if inArray, ok := in.([]interface{}); ok {
				for _, val := range inArray {
					if e.equals(val, provided) {
						return true
					}
				}
				return false
			}
		}
		if nin, ok := reqMap["$nin"]; ok {
			if ninArray, ok := nin.([]interface{}); ok {
				for _, val := range ninArray {
					if e.equals(val, provided) {
						return false
					}
				}
				return true
			}
		}
		if contains, ok := reqMap["$contains"]; ok {
			provStr := fmt.Sprint(provided)
			containsStr := fmt.Sprint(contains)
			return strings.Contains(provStr, containsStr)
		}
		if startsWith, ok := reqMap["$startsWith"]; ok {
			provStr := fmt.Sprint(provided)
			startsWithStr := fmt.Sprint(startsWith)
			return strings.HasPrefix(provStr, startsWithStr)
		}
		if endsWith, ok := reqMap["$endsWith"]; ok {
			provStr := fmt.Sprint(provided)
			endsWithStr := fmt.Sprint(endsWith)
			return strings.HasSuffix(provStr, endsWithStr)
		}
		// If no operator matched, try direct equality
		return e.equals(required, provided)
	}

	// Direct equality comparison
	return e.equals(required, provided)
}

// equals performs deep equality check
func (e *JSONEngine) equals(a, b interface{}) bool {
	return reflect.DeepEqual(a, b)
}

// matchAction checks if the action matches
func (e *JSONEngine) matchAction(required interface{}, provided string) bool {
	// Handle string action
	if reqStr, ok := required.(string); ok {
		return reqStr == "*" || reqStr == provided
	}

	// Handle array of actions
	if reqArray, ok := required.([]interface{}); ok {
		for _, action := range reqArray {
			if actionStr, ok := action.(string); ok {
				if actionStr == "*" || actionStr == provided {
					return true
				}
			}
		}
		return false
	}

	// Handle action operators
	if reqMap, ok := required.(map[string]interface{}); ok {
		return e.matchValue(reqMap, provided)
	}

	return false
}

// TestPolicy tests a JSON policy without persisting it
func (e *JSONEngine) TestPolicy(ctx context.Context, policyContent string, language models.PolicyLanguage, input *EvaluationInput) (*EvaluationResult, error) {
	if language != models.PolicyLanguageJSON {
		return nil, fmt.Errorf("invalid language for JSON engine: %s", language)
	}

	// Create a temporary policy for evaluation
	tempPolicy := &models.Policy{
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: policyContent,
	}

	return e.Evaluate(ctx, tempPolicy, input)
}