package policy_engine

import (
	"context"
	"fmt"

	"stratium/pkg/models"

	"github.com/open-policy-agent/opa/rego"
)

// OPAEngine implements PolicyEngine for Open Policy Agent (Rego)
type OPAEngine struct{}

// NewOPAEngine creates a new OPA policy engine
func NewOPAEngine() *OPAEngine {
	return &OPAEngine{}
}

// Evaluate evaluates an OPA policy against the given input
func (e *OPAEngine) Evaluate(ctx context.Context, policy *models.Policy, input *EvaluationInput) (*EvaluationResult, error) {
	if policy.Language != models.PolicyLanguageOPA {
		return nil, fmt.Errorf("invalid policy language for OPA engine: %s", policy.Language)
	}

	// Create a new Rego query
	r := rego.New(
		rego.Query("data.stratium.authz.allow"),
		rego.Module(policy.Name, policy.PolicyContent),
	)

	// Prepare the query
	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare OPA query: %w", err)
	}

	// Build input for OPA
	opaInput := map[string]interface{}{
		"subject":     input.Subject,
		"resource":    input.Resource,
		"action":      input.Action,
		"environment": input.Environment,
	}

	// Evaluate the policy
	results, err := query.Eval(ctx, rego.EvalInput(opaInput))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate OPA policy: %w", err)
	}

	// Parse results
	allow := false
	reason := "Policy evaluation completed"
	details := make(map[string]interface{})

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		// Check if the result is a boolean
		if allowed, ok := results[0].Expressions[0].Value.(bool); ok {
			allow = allowed
			if allow {
				reason = fmt.Sprintf("Access allowed by policy: %s", policy.Name)
			} else {
				reason = fmt.Sprintf("Access denied by policy: %s", policy.Name)
			}
		}

		details["expressions"] = results[0].Expressions
		details["bindings"] = results[0].Bindings
	} else {
		reason = "Policy did not return a result (default deny)"
	}

	return &EvaluationResult{
		Allow:      allow,
		Reason:     reason,
		Details:    details,
		PolicyName: policy.Name,
	}, nil
}

// ValidatePolicy validates the syntax of an OPA policy
func (e *OPAEngine) ValidatePolicy(ctx context.Context, policyContent string, language models.PolicyLanguage) error {
	if language != models.PolicyLanguageOPA {
		return fmt.Errorf("invalid policy language for OPA engine: %s", language)
	}

	// Try to compile the policy to validate syntax
	r := rego.New(
		rego.Query("data.stratium.authz.allow"),
		rego.Module("validation", policyContent),
	)

	_, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("OPA policy validation failed: %w", err)
	}

	return nil
}

// TestPolicy tests an OPA policy against test data without persisting it
func (e *OPAEngine) TestPolicy(ctx context.Context, policyContent string, language models.PolicyLanguage, input *EvaluationInput) (*EvaluationResult, error) {
	if language != models.PolicyLanguageOPA {
		return nil, fmt.Errorf("invalid policy language for OPA engine: %s", language)
	}

	// Create a temporary policy for testing
	testPolicy := &models.Policy{
		Name:          "test-policy",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: policyContent,
	}

	return e.Evaluate(ctx, testPolicy, input)
}
