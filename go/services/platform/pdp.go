package platform

import (
	"context"
	"fmt"
	"sync"
	"time"

	"stratium/pkg/models"
	"stratium/pkg/policy_engine"
	"stratium/pkg/repository"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PolicyDecisionPoint (PDP) handles policy-based decision making
type PolicyDecisionPoint struct {
	repo           *repository.Repository
	engineFactory  *policy_engine.EngineFactory
	cache          PolicyCache
	policiesMu     sync.RWMutex
	cachedPolicies []*models.Policy
	policiesExpiry time.Time
	policiesTTL    time.Duration
	evalInputPool  sync.Pool
}

// SetPolicyCacheTTL allows overriding the TTL used for caching enabled policies.
func (pdp *PolicyDecisionPoint) SetPolicyCacheTTL(ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	pdp.policiesTTL = ttl
}

// NewPolicyDecisionPoint creates a new PDP instance with in-memory cache
func NewPolicyDecisionPoint(repo *repository.Repository, cache PolicyCache, ttl time.Duration) *PolicyDecisionPoint {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &PolicyDecisionPoint{
		repo:          repo,
		engineFactory: policy_engine.NewEngineFactory(),
		cache:         cache,
		policiesTTL:   ttl,
		evalInputPool: sync.Pool{New: func() interface{} {
			return &policy_engine.EvaluationInput{
				Subject:     make(map[string]interface{}),
				Resource:    make(map[string]interface{}),
				Environment: make(map[string]interface{}),
			}
		}},
	}
}

// EvaluateDecision evaluates a decision request against policies and entitlements
func (pdp *PolicyDecisionPoint) EvaluateDecision(ctx context.Context, req *GetDecisionRequest) (*DecisionResult, error) {
	logger.Info("PDP: Evaluating decision for subject_attributes=%v, resource_attributes=%v, action=%s",
		req.SubjectAttributes, req.ResourceAttributes, req.Action)

	// Step 1: Check entitlements first (more specific)
	entitlementDecision, err := pdp.evaluateEntitlements(ctx, req)
	if err != nil {
		logger.Info("PDP: Entitlement evaluation error: %v", err)
		// Continue to policy evaluation even if entitlement check fails
	} else if entitlementDecision != nil {
		logger.Info("PDP: Entitlement match found: %s", entitlementDecision.Reason)
		return entitlementDecision, nil
	}

	// Step 2: Evaluate policies (more general rules)
	policyDecision, err := pdp.evaluatePolicies(ctx, req)
	if err != nil {
		logger.Info("PDP: Policy evaluation error: %v", err)
		return pdp.defaultDenyDecision(req, fmt.Sprintf("Policy evaluation failed: %v", err)), nil
	}

	if policyDecision != nil {
		return policyDecision, nil
	}

	// Step 3: Default deny
	return pdp.defaultDenyDecision(req, "No matching policies or entitlements found"), nil
}

// evaluateEntitlements checks if the request matches any entitlements
func (pdp *PolicyDecisionPoint) evaluateEntitlements(ctx context.Context, req *GetDecisionRequest) (*DecisionResult, error) {
	// Build subject attributes from request subject_attributes map
	subjectAttrs := make(map[string]interface{})
	for k, v := range req.SubjectAttributes {
		// Extract actual string value from protobuf Value
		subjectAttrs[k] = v.GetStringValue()
	}

	// Merge context attributes into subject attributes
	for k, v := range req.Context {
		subjectAttrs[k] = v
	}

	// Find matching entitlements
	matchReq := &models.EntitlementMatchRequest{
		SubjectAttributes: subjectAttrs,
		Action:            req.Action,
	}

	entitlements, err := pdp.repo.Entitlement.FindMatching(ctx, matchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching entitlements: %w", err)
	}

	// Build combined resource attributes (including context for matching)
	combinedResourceAttrs := make(map[string]string)
	for k, v := range req.ResourceAttributes {
		combinedResourceAttrs[k] = v
	}
	// Also include context in resource matching
	for k, v := range req.Context {
		combinedResourceAttrs[k] = v
	}

	// Check each entitlement
	for _, ent := range entitlements {
		// Verify entitlement is active
		if !ent.IsActive() {
			logger.Info("PDP: Skipping expired/disabled entitlement: %s", ent.Name)
			continue
		}

		// Check if resource attributes match (if specified)
		if len(ent.ResourceAttributes) > 0 {
			if !pdp.matchesResourceAttributes(ent.ResourceAttributes, combinedResourceAttrs) {
				continue
			}
		}

		// Entitlement matches!
		logger.Info("PDP: Entitlement match: %s (ID: %s)", ent.Name, ent.ID)

		// Create audit log entry
		pdp.logDecision(ctx, models.EntityTypeEntitlement, &ent.ID, req, true, "Entitlement match")

		return &DecisionResult{
			Decision: Decision_DECISION_ALLOW,
			Reason:   fmt.Sprintf("Access granted by entitlement: %s", ent.Name),
			Details: map[string]string{
				"entitlement_id":   ent.ID.String(),
				"entitlement_name": ent.Name,
			},
			PolicyID: ent.ID.String(),
		}, nil
	}

	return nil, nil
}

// evaluatePolicies evaluates all enabled policies

func (pdp *PolicyDecisionPoint) evaluatePolicies(ctx context.Context, req *GetDecisionRequest) (*DecisionResult, error) {
	policies, err := pdp.getEnabledPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	logger.Info("PDP: Evaluating %d enabled policies", len(policies))

	// Build evaluation input using attribute maps
	evalInput := pdp.acquireEvalInput()
	evalInput.Action = req.Action

	// Copy subject attributes from request
	for k, v := range req.SubjectAttributes {
		// Extract actual string value from protobuf Value
		evalInput.Subject[k] = v.GetStringValue()
	}

	// Merge context attributes into subject attributes
	// This allows policies to evaluate based on contextual information
	for k, v := range req.Context {
		evalInput.Subject[k] = v
	}

	// Copy resource attributes from request
	for k, v := range req.ResourceAttributes {
		evalInput.Resource[k] = v
	}

	// Also add context to environment (for backward compatibility)
	for k, v := range req.Context {
		evalInput.Environment[k] = v
	}

	// Evaluate policies in priority order (highest first)
	for _, policy := range policies {
		engine, err := pdp.engineFactory.GetEngine(policy.Language)
		if err != nil {
			logger.Info("PDP: Unsupported policy language %s for policy %s", policy.Language, policy.Name)
			continue
		}

		result, err := engine.Evaluate(ctx, policy, evalInput)
		if err != nil {
			logger.Info("PDP: Policy evaluation error for %s: %v", policy.Name, err)
			continue
		}

		logger.Info("PDP: Policy %s (priority %d) evaluated: allow=%v, reason=%s",
			policy.Name, policy.Priority, result.Allow, result.Reason)

		// Check policy effect
		if result.Allow && policy.Effect == models.PolicyEffectAllow {
			// Allow policy matched and evaluated to true
			logger.Info("PDP: Policy ALLOW: %s", policy.Name)

			// Create audit log entry
			pdp.logDecision(ctx, models.EntityTypePolicy, &policy.ID, req, true, result.Reason)

			pdp.releaseEvalInput(evalInput)
			return &DecisionResult{
				Decision: Decision_DECISION_ALLOW,
				Reason:   fmt.Sprintf("Access granted by policy: %s", policy.Name),
				Details: map[string]string{
					"policy_id":   policy.ID.String(),
					"policy_name": policy.Name,
					"language":    string(policy.Language),
				},
				PolicyID: policy.ID.String(),
			}, nil
		} else if result.Allow && policy.Effect == models.PolicyEffectDeny {
			// Deny policy matched and evaluated to true
			logger.Info("PDP: Policy DENY: %s", policy.Name)

			// Create audit log entry
			pdp.logDecision(ctx, models.EntityTypePolicy, &policy.ID, req, false, result.Reason)

			pdp.releaseEvalInput(evalInput)
			return &DecisionResult{
				Decision: Decision_DECISION_DENY,
				Reason:   fmt.Sprintf("Access denied by policy: %s", policy.Name),
				Details: map[string]string{
					"policy_id":   policy.ID.String(),
					"policy_name": policy.Name,
					"language":    string(policy.Language),
				},
				PolicyID: policy.ID.String(),
			}, nil
		}
	}

	pdp.releaseEvalInput(evalInput)
	return nil, nil
}

func (pdp *PolicyDecisionPoint) getEnabledPolicies(ctx context.Context) ([]*models.Policy, error) {
	now := time.Now()
	pdp.policiesMu.RLock()
	if pdp.cachedPolicies != nil && now.Before(pdp.policiesExpiry) {
		policies := pdp.cachedPolicies
		pdp.policiesMu.RUnlock()
		return policies, nil
	}
	pdp.policiesMu.RUnlock()

	policies, err := pdp.repo.Policy.ListEnabled(ctx)
	if err != nil {
		return nil, err
	}

	pdp.policiesMu.Lock()
	pdp.cachedPolicies = policies
	pdp.policiesExpiry = time.Now().Add(pdp.policiesTTL)
	pdp.policiesMu.Unlock()
	return policies, nil
}

func (pdp *PolicyDecisionPoint) acquireEvalInput() *policy_engine.EvaluationInput {
	input := pdp.evalInputPool.Get().(*policy_engine.EvaluationInput)
	return input
}

func (pdp *PolicyDecisionPoint) releaseEvalInput(input *policy_engine.EvaluationInput) {
	input.Action = ""
	for k := range input.Subject {
		delete(input.Subject, k)
	}
	for k := range input.Resource {
		delete(input.Resource, k)
	}
	for k := range input.Environment {
		delete(input.Environment, k)
	}
	pdp.evalInputPool.Put(input)
}

// matchesResourceAttributes checks if resource attributes match required attributes
func (pdp *PolicyDecisionPoint) matchesResourceAttributes(required map[string]interface{}, provided map[string]string) bool {
	for key, requiredValue := range required {
		providedValue, exists := provided[key]
		if !exists {
			return false
		}

		// Simple string comparison (can be enhanced for more complex matching)
		if fmt.Sprint(requiredValue) != providedValue {
			return false
		}
	}
	return true
}

// defaultDenyDecision creates a default deny decision
func (pdp *PolicyDecisionPoint) defaultDenyDecision(req *GetDecisionRequest, reason string) *DecisionResult {
	// Extract subject ID for details
	subjectID := ""
	if val, ok := req.SubjectAttributes["sub"]; ok {
		subjectID = val.GetStringValue()
	}
	if subjectID == "" {
		if val, ok := req.SubjectAttributes["user_id"]; ok {
			subjectID = val.GetStringValue()
		}
	}
	if subjectID == "" {
		if val, ok := req.SubjectAttributes["id"]; ok {
			subjectID = val.GetStringValue()
		}
	}

	// Extract resource ID for details
	resourceID := req.ResourceAttributes["name"]
	if resourceID == "" {
		resourceID = req.ResourceAttributes["id"]
	}
	if resourceID == "" {
		resourceID = req.ResourceAttributes["resource"]
	}

	return &DecisionResult{
		Decision: Decision_DECISION_DENY,
		Reason:   reason,
		Details: map[string]string{
			"subject_attrs_count":  fmt.Sprintf("%d", len(req.SubjectAttributes)),
			"resource_attrs_count": fmt.Sprintf("%d", len(req.ResourceAttributes)),
			"action":               req.Action,
			"subject_id":           subjectID,
			"resource_id":          resourceID,
		},
		PolicyID: "default-deny",
	}
}

// GetEntitlementsForSubject queries entitlements from the database for a given subject
func (pdp *PolicyDecisionPoint) GetEntitlementsForSubject(ctx context.Context, req *GetEntitlementsRequest) ([]*Entitlement, error) {
	logger.Info("PDP: Getting entitlements for subject from database")

	// Build subject attributes from request
	subjectAttrs := make(map[string]interface{})
	for k, v := range req.Subject {
		// Extract actual value from protobuf Value
		if strVal := v.GetStringValue(); strVal != "" {
			subjectAttrs[k] = strVal
		} else if numVal := v.GetNumberValue(); numVal != 0 {
			subjectAttrs[k] = numVal
		} else if boolVal := v.GetBoolValue(); boolVal {
			subjectAttrs[k] = boolVal
		}
	}

	// Build match request
	matchReq := &models.EntitlementMatchRequest{
		SubjectAttributes: subjectAttrs,
	}

	// Add action filter if specified
	if req.ActionFilter != "" {
		matchReq.Action = req.ActionFilter
	}

	// Query database for matching entitlements
	dbEntitlements, err := pdp.repo.Entitlement.FindMatching(ctx, matchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching entitlements: %w", err)
	}

	logger.Info("PDP: Found %d matching entitlements in database", len(dbEntitlements))

	// Convert database models to protobuf
	var result []*Entitlement
	for _, ent := range dbEntitlements {
		// Verify entitlement is active
		if !ent.IsActive() {
			logger.Info("PDP: Skipping expired/disabled entitlement: %s", ent.Name)
			continue
		}

		// Apply resource filter if specified (simple string match on resource name)
		if req.ResourceFilter != "" {
			// Try to match against resource name attribute if it exists
			if resourceName, ok := ent.ResourceAttributes["name"].(string); ok {
				if resourceName != req.ResourceFilter {
					logger.Info("PDP: Skipping entitlement %s - resource name '%s' doesn't match filter '%s'",
						ent.Name, resourceName, req.ResourceFilter)
					continue
				}
			}
		}

		// Extract subject ID (for Subject field - backward compatibility)
		subjectID := ""
		if sub, ok := ent.SubjectAttributes["sub"].(string); ok {
			subjectID = sub
		} else if userID, ok := ent.SubjectAttributes["user_id"].(string); ok {
			subjectID = userID
		} else if id, ok := ent.SubjectAttributes["id"].(string); ok {
			subjectID = id
		}

		// Extract resource ID (for Resource field - backward compatibility)
		resourceID := ""
		if resName, ok := ent.ResourceAttributes["name"].(string); ok {
			resourceID = resName
		} else if resID, ok := ent.ResourceAttributes["id"].(string); ok {
			resourceID = resID
		} else if resType, ok := ent.ResourceAttributes["resource_type"].(string); ok {
			// Use resource_type as the resource field if no name/id exists
			resourceID = resType
		}

		// Convert metadata from map[string]interface{} to map[string]string
		metadata := make(map[string]string)
		for k, v := range ent.ResourceAttributes {
			if strVal, ok := v.(string); ok {
				metadata[k] = strVal
			}
		}

		// Convert to protobuf
		pbEntitlement := &Entitlement{
			Id:       ent.ID.String(),
			Subject:  subjectID,
			Resource: resourceID,
			Actions:  ent.Actions,
			Metadata: metadata,
			Active:   ent.Enabled, // Set active field from database enabled field
		}

		// Set timestamps if available
		if !ent.CreatedAt.IsZero() {
			pbEntitlement.CreatedAt = timestamppb.New(ent.CreatedAt)
		}
		if ent.ExpiresAt != nil && !ent.ExpiresAt.IsZero() {
			pbEntitlement.ExpiresAt = timestamppb.New(*ent.ExpiresAt)
		}

		result = append(result, pbEntitlement)
	}

	logger.Info("PDP: Returning %d active entitlements", len(result))
	return result, nil
}

// logDecision creates an audit log entry for the decision
func (pdp *PolicyDecisionPoint) logDecision(ctx context.Context, entityType models.EntityType, entityID *uuid.UUID, req *GetDecisionRequest, allowed bool, reason string) {
	// Extract subject ID for actor field
	actor := ""
	if val, ok := req.SubjectAttributes["sub"]; ok {
		actor = val.GetStringValue()
	}
	if actor == "" {
		if val, ok := req.SubjectAttributes["user_id"]; ok {
			actor = val.GetStringValue()
		}
	}
	if actor == "" {
		if val, ok := req.SubjectAttributes["id"]; ok {
			actor = val.GetStringValue()
		}
	}
	if actor == "" {
		actor = "unknown"
	}

	auditLog := &models.CreateAuditLogRequest{
		EntityType: entityType,
		EntityID:   entityID,
		Action:     models.AuditActionEvaluate,
		Actor:      actor,
		Changes: map[string]interface{}{
			"subject_attributes":  req.SubjectAttributes,
			"resource_attributes": req.ResourceAttributes,
			"action":              req.Action,
			"context":             req.Context,
		},
		Result: map[string]interface{}{
			"allowed": allowed,
			"reason":  reason,
		},
	}

	if err := pdp.repo.Audit.Create(ctx, auditLog.ToAuditLog()); err != nil {
		logger.Error("PDP: Failed to create audit log: %v", err)
	}
}
