package policy_engine

import (
	"context"
	"encoding/xml"
	"fmt"
	"strings"

	"stratium/pkg/models"
)

// XACMLEngine implements PolicyEngine for XACML policies
type XACMLEngine struct{}

// NewXACMLEngine creates a new XACML policy engine
func NewXACMLEngine() PolicyEngine {
	return &XACMLEngine{}
}

// XACML 3.0 structures for basic parsing
type XACMLPolicy struct {
	XMLName     xml.Name `xml:"Policy"`
	PolicyID    string   `xml:"PolicyId,attr"`
	Version     string   `xml:"Version,attr"`
	Description string   `xml:"Description"`
	Target      string   `xml:"Target"`
	Rules       []XACMLRule `xml:"Rule"`
}

type XACMLRule struct {
	RuleID      string `xml:"RuleId,attr"`
	Effect      string `xml:"Effect,attr"`
	Description string `xml:"Description"`
	Target      string `xml:"Target"`
	Condition   string `xml:"Condition"`
}

// ValidatePolicy validates XACML policy syntax
func (e *XACMLEngine) ValidatePolicy(ctx context.Context, policyContent string, language models.PolicyLanguage) error {
	if language != models.PolicyLanguageXACML {
		return fmt.Errorf("invalid language for XACML engine: %s", language)
	}

	// Basic XML validation
	var policy XACMLPolicy
	if err := xml.Unmarshal([]byte(policyContent), &policy); err != nil {
		return fmt.Errorf("invalid XACML XML: %w", err)
	}

	// Validate required fields
	if policy.PolicyID == "" {
		return fmt.Errorf("XACML policy must have a PolicyId attribute")
	}

	if len(policy.Rules) == 0 {
		return fmt.Errorf("XACML policy must have at least one Rule")
	}

	// Validate each rule
	for i, rule := range policy.Rules {
		if rule.RuleID == "" {
			return fmt.Errorf("Rule %d must have a RuleId attribute", i)
		}
		if rule.Effect != "Permit" && rule.Effect != "Deny" {
			return fmt.Errorf("Rule %s has invalid Effect: %s (must be Permit or Deny)", rule.RuleID, rule.Effect)
		}
	}

	return nil
}

// Evaluate evaluates an XACML policy against input
func (e *XACMLEngine) Evaluate(ctx context.Context, policy *models.Policy, input *EvaluationInput) (*EvaluationResult, error) {
	if policy.Language != models.PolicyLanguageXACML {
		return nil, fmt.Errorf("policy language must be XACML")
	}

	// Parse the XACML policy
	var xacmlPolicy XACMLPolicy
	if err := xml.Unmarshal([]byte(policy.PolicyContent), &xacmlPolicy); err != nil {
		return nil, fmt.Errorf("failed to parse XACML policy: %w", err)
	}

	// Basic evaluation logic
	// This is a simplified implementation - a full XACML engine would be much more complex
	result := &EvaluationResult{
		Allow:      false,
		PolicyName: policy.Name,
		Details:    make(map[string]interface{}),
	}

	// Evaluate each rule
	for _, rule := range xacmlPolicy.Rules {
		// Simple attribute matching in the condition
		// This is a very basic implementation - real XACML evaluation is much more sophisticated
		ruleMatches := e.evaluateRule(rule, input)

		if ruleMatches {
			if rule.Effect == "Permit" {
				result.Allow = true
				result.Reason = fmt.Sprintf("Rule %s permits access", rule.RuleID)
			} else if rule.Effect == "Deny" {
				result.Allow = false
				result.Reason = fmt.Sprintf("Rule %s denies access", rule.RuleID)
				// Deny takes precedence
				break
			}
		}
	}

	if result.Reason == "" {
		result.Reason = "No matching rule found - default deny"
	}

	result.Details["evaluated_rules"] = len(xacmlPolicy.Rules)
	result.Details["policy_id"] = xacmlPolicy.PolicyID

	return result, nil
}

// evaluateRule performs basic rule evaluation
// This is a simplified implementation - real XACML is much more complex
func (e *XACMLEngine) evaluateRule(rule XACMLRule, input *EvaluationInput) bool {
	// For now, we'll do a simple string matching in the Condition
	// A full implementation would parse the XACML Condition XPath expressions

	// If there's no condition, the rule matches
	if rule.Condition == "" {
		return true
	}

	// Very basic attribute matching
	// Look for common patterns like role="admin"
	conditionLower := strings.ToLower(rule.Condition)

	// Check subject attributes
	for key, value := range input.Subject {
		valueStr := fmt.Sprintf("%v", value)
		if strings.Contains(conditionLower, strings.ToLower(key)) &&
		   strings.Contains(conditionLower, strings.ToLower(valueStr)) {
			return true
		}
	}

	// Check resource attributes
	for key, value := range input.Resource {
		valueStr := fmt.Sprintf("%v", value)
		if strings.Contains(conditionLower, strings.ToLower(key)) &&
		   strings.Contains(conditionLower, strings.ToLower(valueStr)) {
			return true
		}
	}

	// Check action
	if strings.Contains(conditionLower, strings.ToLower(input.Action)) {
		return true
	}

	return false
}

// TestPolicy tests an XACML policy without persisting it
func (e *XACMLEngine) TestPolicy(ctx context.Context, policyContent string, language models.PolicyLanguage, input *EvaluationInput) (*EvaluationResult, error) {
	if language != models.PolicyLanguageXACML {
		return nil, fmt.Errorf("invalid language for XACML engine: %s", language)
	}

	// Create a temporary policy for evaluation
	tempPolicy := &models.Policy{
		Name:          "test-policy",
		Language:      models.PolicyLanguageXACML,
		PolicyContent: policyContent,
	}

	return e.Evaluate(ctx, tempPolicy, input)
}