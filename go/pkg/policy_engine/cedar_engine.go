package policy_engine

import (
	"context"
	"fmt"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"

	"stratium/pkg/cedar"
	"stratium/pkg/models"
)

// CedarEngine implements PolicyEngine for the Cedar policy language.
// It uses the cedar-go native Go library for policy parsing and evaluation.
type CedarEngine struct {
	entityResolver *cedar.EntityResolver
	defaultNS      string
}

// NewCedarEngine creates a new Cedar policy engine with the given default namespace.
func NewCedarEngine(defaultNamespace string) *CedarEngine {
	if defaultNamespace == "" {
		defaultNamespace = "Stratium"
	}
	return &CedarEngine{
		entityResolver: cedar.NewEntityResolver(defaultNamespace),
		defaultNS:      defaultNamespace,
	}
}

// Evaluate evaluates a Cedar policy against the given input.
func (e *CedarEngine) Evaluate(ctx context.Context, policy *models.Policy, input *EvaluationInput) (*EvaluationResult, error) {
	if policy.Language != models.PolicyLanguageCedar {
		return nil, fmt.Errorf("invalid policy language for Cedar engine: %s", policy.Language)
	}

	// Parse Cedar policy text into a PolicySet
	policySet, err := cedarlib.NewPolicySetFromBytes("policy", []byte(policy.PolicyContent))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cedar policy: %w", err)
	}

	// Use the default namespace. Explicit namespace should be provided via
	// EvaluationInput.Environment["namespace"] or policy metadata — not
	// inferred from policy text, which is fragile and error-prone.
	namespace := e.defaultNS
	if ns, ok := input.Environment["namespace"]; ok {
		if nsStr, ok := ns.(string); ok {
			namespace = nsStr
		}
	}

	// Resolve entities from input
	entities := e.entityResolver.Resolve(namespace, input.Subject, input.Resource, input.Action)

	// Build the Cedar request
	principalUID, _ := cedar.MapSubjectToEntity(namespace, input.Subject)
	resourceUID, _ := cedar.MapResourceToEntity(namespace, input.Resource)
	actionUID := cedar.MapActionToEntityUID(namespace, input.Action)
	cedarContext := cedar.MapContextToRecord(input.Environment)

	req := types.Request{
		Principal: principalUID,
		Action:    actionUID,
		Resource:  resourceUID,
		Context:   cedarContext,
	}

	// Evaluate
	decision, diagnostic := cedarlib.Authorize(policySet, entities, req)

	// Map result
	result := &EvaluationResult{
		Allow:      decision == cedarlib.Allow,
		PolicyName: policy.Name,
		Details:    make(map[string]interface{}),
	}

	// Build reason from diagnostic
	if len(diagnostic.Reasons) > 0 {
		policyIDs := make([]string, len(diagnostic.Reasons))
		for i, r := range diagnostic.Reasons {
			policyIDs[i] = string(r.PolicyID)
		}
		if result.Allow {
			result.Reason = fmt.Sprintf("Access allowed by Cedar policies: %s", strings.Join(policyIDs, ", "))
		} else {
			result.Reason = fmt.Sprintf("Access denied by Cedar policies: %s", strings.Join(policyIDs, ", "))
		}
		result.Details["determining_policies"] = policyIDs
	} else {
		result.Reason = "No matching Cedar policy found — default deny"
	}

	// Include any evaluation errors in the details
	if len(diagnostic.Errors) > 0 {
		errMsgs := make([]string, len(diagnostic.Errors))
		for i, e := range diagnostic.Errors {
			errMsgs[i] = e.String()
		}
		result.Details["evaluation_errors"] = errMsgs
	}

	return result, nil
}

// ValidatePolicy validates the syntax of a Cedar policy.
func (e *CedarEngine) ValidatePolicy(ctx context.Context, policyContent string, language models.PolicyLanguage) error {
	if language != models.PolicyLanguageCedar {
		return fmt.Errorf("invalid policy language for Cedar engine: %s", language)
	}

	if strings.TrimSpace(policyContent) == "" {
		return fmt.Errorf("Cedar policy content is empty")
	}

	// Try to parse — this validates syntax
	_, err := cedarlib.NewPolicySetFromBytes("validation", []byte(policyContent))
	if err != nil {
		return fmt.Errorf("Cedar policy validation failed: %w", err)
	}

	return nil
}

// TestPolicy tests a Cedar policy against test data without persisting it.
func (e *CedarEngine) TestPolicy(ctx context.Context, policyContent string, language models.PolicyLanguage, input *EvaluationInput) (*EvaluationResult, error) {
	if language != models.PolicyLanguageCedar {
		return nil, fmt.Errorf("invalid policy language for Cedar engine: %s", language)
	}

	testPolicy := &models.Policy{
		Name:          "test-policy",
		Language:      models.PolicyLanguageCedar,
		PolicyContent: policyContent,
	}

	return e.Evaluate(ctx, testPolicy, input)
}
