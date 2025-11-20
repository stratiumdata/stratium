package policy_engine

import (
	"context"

	"stratium/pkg/models"
)

// PolicyEngine defines the interface for policy evaluation engines
type PolicyEngine interface {
	// Evaluate evaluates a policy against the given input
	Evaluate(ctx context.Context, policy *models.Policy, input *EvaluationInput) (*EvaluationResult, error)

	// ValidatePolicy validates the syntax of a policy
	ValidatePolicy(ctx context.Context, policyContent string, language models.PolicyLanguage) error

	// TestPolicy tests a policy against test data without persisting it
	TestPolicy(ctx context.Context, policyContent string, language models.PolicyLanguage, input *EvaluationInput) (*EvaluationResult, error)
}

// EvaluationInput represents the input data for policy evaluation
type EvaluationInput struct {
	Subject     map[string]interface{} `json:"subject"`
	Resource    map[string]interface{} `json:"resource"`
	Action      string                 `json:"action"`
	Environment map[string]interface{} `json:"environment"`
}

// EvaluationResult represents the result of a policy evaluation
type EvaluationResult struct {
	Allow      bool                   `json:"allow"`
	Reason     string                 `json:"reason"`
	Details    map[string]interface{} `json:"details"`
	PolicyName string                 `json:"policy_name,omitempty"`
}

// EngineFactory creates policy engines based on the language
type EngineFactory struct {
	opaEngine   PolicyEngine
	xacmlEngine PolicyEngine
	jsonEngine  PolicyEngine
}

// NewEngineFactory creates a new engine factory
func NewEngineFactory() *EngineFactory {
	return &EngineFactory{
		opaEngine:   NewOPAEngine(),
		xacmlEngine: NewXACMLEngine(),
		jsonEngine:  NewJSONEngine(),
	}
}

// GetEngine returns the appropriate engine for the given language
func (f *EngineFactory) GetEngine(language models.PolicyLanguage) (PolicyEngine, error) {
	switch language {
	case models.PolicyLanguageOPA:
		return f.opaEngine, nil
	case models.PolicyLanguageXACML:
		if f.xacmlEngine == nil {
			return nil, models.ErrNotImplemented
		}
		return f.xacmlEngine, nil
	case models.PolicyLanguageJSON:
		return f.jsonEngine, nil
	default:
		return nil, models.ErrInvalidPolicyLanguage
	}
}
