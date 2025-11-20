package platform

import (
	"context"
	"fmt"
	"slices"
	"stratium/config"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements the PlatformServiceServer interface
type Server struct {
	UnimplementedPlatformServiceServer

	// Policy Decision Point for evaluating access decisions
	pdp *PolicyDecisionPoint

	// Legacy in-memory stores (deprecated - will be removed)
	entitlements map[string][]*Entitlement
	policies     map[string]*Policy

	config *config.Config
}

// Policy represents a decision policy (simplified for demo)
type Policy struct {
	ID          string
	Name        string
	Description string
	Rules       []PolicyRule
}

// PolicyRule represents a rule within a policy
type PolicyRule struct {
	Resource  string
	Action    string
	Subject   string
	Condition string
	Effect    string // "allow" or "deny"
}

// NewServer creates a new platform server with sample data (legacy mode)
func NewServer(cfg *config.Config) *Server {
	server := &Server{
		pdp:          nil, // No PDP in legacy mode
		entitlements: make(map[string][]*Entitlement),
		policies:     make(map[string]*Policy),
		config:       cfg,
	}

	// Initialize with sample data
	server.initializeSampleData()

	return server
}

// NewServerWithPDP creates a new platform server with Policy Decision Point
func NewServerWithPDP(pdp *PolicyDecisionPoint, cfg *config.Config) *Server {
	return &Server{
		pdp:          pdp,
		entitlements: make(map[string][]*Entitlement),
		policies:     make(map[string]*Policy),
		config:       cfg,
	}
}

// GetDecision implements the GetDecision RPC method
func (s *Server) GetDecision(ctx context.Context, req *GetDecisionRequest) (*GetDecisionResponse, error) {
	logger.Debug("GetDecision called - SubjectAttributes: %v, ResourceAttributes: %v, Action: %s",
		req.SubjectAttributes, req.ResourceAttributes, req.Action)

	// Validate critical required fields
	if req.Action == "" {
		return nil, fmt.Errorf("action is required")
	}
	// Note: We don't validate SubjectAttributes or ResourceAttributes here
	// to allow evaluateDecision to handle missing attributes gracefully
	// with a DENY decision rather than an error

	var decision *DecisionResult
	var err error

	// Use PDP if available, otherwise fall back to legacy evaluation
	if s.pdp != nil {
		logger.Info("Using Policy Decision Point for evaluation")
		decision, err = s.pdp.EvaluateDecision(ctx, req)
		if err != nil {
			logger.Error("PDP evaluation error: %v, falling back to legacy", err)
			decision = s.evaluateDecision(req)
		}
	} else {
		logger.Info("Using legacy decision evaluation (no PDP configured)")
		decision = s.evaluateDecision(req)
	}

	response := &GetDecisionResponse{
		Decision:        decision.Decision,
		Reason:          decision.Reason,
		Details:         decision.Details,
		Timestamp:       timestamppb.Now(),
		EvaluatedPolicy: decision.PolicyID,
	}

	logger.Info("Decision: %s, Reason: %s", decision.Decision.String(), decision.Reason)
	return response, nil
}

// GetEntitlements implements the GetEntitlements RPC method
func (s *Server) GetEntitlements(ctx context.Context, req *GetEntitlementsRequest) (*GetEntitlementsResponse, error) {
	logger.Debug("GetEntitlements called - Subject: %v, ResourceFilter: %s",
		req.Subject, req.ResourceFilter)

	// Validate required fields
	if len(req.Subject) == 0 {
		return nil, fmt.Errorf("subject is required")
	}

	// Set default page size if not specified
	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = 50
	}
	if pageSize > 1000 {
		pageSize = 1000
	}

	var allEntitlements []*Entitlement

	// Use PDP to query entitlements from database if available
	if s.pdp != nil {
		logger.Info("Using PDP to query entitlements from database")
		dbEntitlements, err := s.pdp.GetEntitlementsForSubject(ctx, req)
		if err != nil {
			logger.Error("error querying entitlements from database: %v, falling back to in-memory", err)
			// Fall back to in-memory map
			subjectID := extractSubjectID(req.Subject)
			if subjectID != "" {
				allEntitlements = s.getEntitlementsForSubject(subjectID, req)
			}
		} else {
			allEntitlements = dbEntitlements
		}
	} else {
		logger.Info("using in-memory entitlements store (no PDP configured)")
		// Legacy mode: use in-memory map
		subjectID := extractSubjectID(req.Subject)
		if subjectID != "" {
			allEntitlements = s.getEntitlementsForSubject(subjectID, req)
		}
	}

	// Apply pagination
	startIdx := 0
	if req.PageToken != "" {
		if idx, err := parsePageToken(req.PageToken); err == nil {
			startIdx = idx
		}
	}

	endIdx := startIdx + int(pageSize)
	if endIdx > len(allEntitlements) {
		endIdx = len(allEntitlements)
	}

	var entitlements []*Entitlement
	var nextPageToken string

	if startIdx < len(allEntitlements) {
		entitlements = allEntitlements[startIdx:endIdx]

		// Set next page token if there are more results
		if endIdx < len(allEntitlements) {
			nextPageToken = fmt.Sprintf("%d", endIdx)
		}
	}

	response := &GetEntitlementsResponse{
		Entitlements:  entitlements,
		NextPageToken: nextPageToken,
		TotalCount:    int64(len(allEntitlements)),
		Timestamp:     timestamppb.Now(),
	}

	logger.Info("Returning %d entitlements (total: %d)", len(entitlements), len(allEntitlements))
	return response, nil
}

// extractSubjectID extracts the subject ID from subject attributes
func extractSubjectID(subject map[string]*structpb.Value) string {
	if subjectID, ok := subject["sub"]; ok {
		return subjectID.GetStringValue()
	}
	if subjectID, ok := subject["user_id"]; ok {
		return subjectID.GetStringValue()
	}
	if subjectID, ok := subject["id"]; ok {
		return subjectID.GetStringValue()
	}
	return ""
}

// DecisionResult represents the result of a decision evaluation
type DecisionResult struct {
	Decision Decision
	Reason   string
	Details  map[string]string
	PolicyID string
}

// evaluateDecision performs the decision evaluation logic (legacy - uses attribute maps)
func (s *Server) evaluateDecision(req *GetDecisionRequest) *DecisionResult {
	// Extract subject ID from subject attributes
	subjectID, ok := req.SubjectAttributes["sub"]
	if !ok {
		subjectID, ok = req.SubjectAttributes["user_id"]
	}
	if !ok {
		subjectID, ok = req.SubjectAttributes["id"]
	}
	if !ok {
		return &DecisionResult{
			Decision: Decision_DECISION_DENY,
			Reason:   "Subject attributes must contain 'sub', 'user_id', or 'id'",
			Details:  map[string]string{},
			PolicyID: "default-deny-policy",
		}
	}

	// Check for admin privileges (from subject attributes)
	if role, ok := req.SubjectAttributes["role"]; ok && slices.Contains(s.config.Encryption.AdminKeys, role.GetStringValue()) {
		return &DecisionResult{
			Decision: Decision_DECISION_ALLOW,
			Reason:   "Subject has admin privileges",
			Details: map[string]string{
				"rule":   "admin-access",
				"policy": "default-admin-policy",
			},
			PolicyID: "admin-policy",
		}
	}

	// Extract resource identifier from resource attributes
	resourceID, ok := req.ResourceAttributes["name"]
	if !ok {
		resourceID, ok = req.ResourceAttributes["id"]
	}
	if !ok {
		resourceID, ok = req.ResourceAttributes["resource"]
	}

	// Check entitlements
	entitlements := s.entitlements[subjectID.GetStringValue()]
	for _, entitlement := range entitlements {
		if s.matchesEntitlement(entitlement, resourceID, req.Action) {
			// Check conditions (use Context for backward compatibility)
			if s.evaluateConditions(entitlement.Conditions, req.Context) {
				return &DecisionResult{
					Decision: Decision_DECISION_ALLOW,
					Reason:   fmt.Sprintf("Allowed by entitlement: %s", entitlement.Id),
					Details: map[string]string{
						"entitlement_id": entitlement.Id,
						"resource":       entitlement.Resource,
					},
					PolicyID: "entitlement-policy",
				}
			} else {
				return &DecisionResult{
					Decision: Decision_DECISION_CONDITIONAL,
					Reason:   "Entitlement exists but conditions not met",
					Details: map[string]string{
						"entitlement_id": entitlement.Id,
						"reason":         "conditions-not-met",
					},
					PolicyID: "entitlement-policy",
				}
			}
		}
	}

	// Default deny
	return &DecisionResult{
		Decision: Decision_DECISION_DENY,
		Reason:   "No matching entitlements found",
		Details: map[string]string{
			"subject_attrs_count":  fmt.Sprintf("%d", len(req.SubjectAttributes)),
			"resource_attrs_count": fmt.Sprintf("%d", len(req.ResourceAttributes)),
			"action":               req.Action,
		},
		PolicyID: "default-deny-policy",
	}
}

// matchesEntitlement checks if an entitlement matches the resource and action
func (s *Server) matchesEntitlement(entitlement *Entitlement, resource, action string) bool {
	// Check resource match (support wildcards)
	if entitlement.Resource != "*" && entitlement.Resource != resource {
		return false
	}

	// Check action match
	for _, allowedAction := range entitlement.Actions {
		if allowedAction == "*" || allowedAction == action {
			return true
		}
	}

	return false
}

// evaluateConditions evaluates entitlement conditions against the request context
func (s *Server) evaluateConditions(conditions []*Condition, context map[string]string) bool {
	for _, condition := range conditions {
		if !s.evaluateCondition(condition, context) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (s *Server) evaluateCondition(condition *Condition, context map[string]string) bool {
	switch condition.Type {
	case "time":
		return s.evaluateTimeCondition(condition)
	case "attribute":
		return s.evaluateAttributeCondition(condition, context)
	default:
		// Unknown condition type, default to true for safety
		return true
	}
}

// evaluateTimeCondition evaluates time-based conditions
func (s *Server) evaluateTimeCondition(condition *Condition) bool {
	now := time.Now()

	switch condition.Operator {
	case "after":
		if t, err := time.Parse(time.RFC3339, condition.Value); err == nil {
			return now.After(t)
		}
	case "before":
		if t, err := time.Parse(time.RFC3339, condition.Value); err == nil {
			return now.Before(t)
		}
	}

	return true
}

// evaluateAttributeCondition evaluates attribute-based conditions
func (s *Server) evaluateAttributeCondition(condition *Condition, context map[string]string) bool {
	attributeName := condition.Parameters["attribute"]
	if attributeName == "" {
		return true
	}

	contextValue, exists := context[attributeName]
	if !exists {
		return false
	}

	switch condition.Operator {
	case "equals":
		return contextValue == condition.Value
	case "contains":
		return fmt.Sprintf("%s", contextValue) == condition.Value
	default:
		return true
	}
}

// getEntitlementsForSubject retrieves entitlements for a subject with optional filtering
func (s *Server) getEntitlementsForSubject(subject string, req *GetEntitlementsRequest) []*Entitlement {
	allEntitlements := s.entitlements[subject]

	if req.ResourceFilter == "" && req.ActionFilter == "" {
		return allEntitlements
	}

	var filtered []*Entitlement
	for _, entitlement := range allEntitlements {
		// Apply resource filter
		if req.ResourceFilter != "" && entitlement.Resource != req.ResourceFilter {
			continue
		}

		// Apply action filter
		if req.ActionFilter != "" {
			actionMatch := false
			for _, action := range entitlement.Actions {
				if action == req.ActionFilter {
					actionMatch = true
					break
				}
			}
			if !actionMatch {
				continue
			}
		}

		filtered = append(filtered, entitlement)
	}

	return filtered
}

// parsePageToken parses a page token to extract the start index
func parsePageToken(token string) (int, error) {
	// Simple implementation - in production you'd use a more robust token system
	var idx int
	if _, err := fmt.Sscanf(token, "%d", &idx); err != nil {
		return 0, err
	}
	return idx, nil
}

// initializeSampleData populates the server with sample entitlements and policies
func (s *Server) initializeSampleData() {
	if s.config != nil && !s.config.Platform.SeedSampleData {
		logger.Info("platform sample data seeding disabled via configuration")
		return
	}

	var seedData *SeedData
	if s.config != nil && s.config.Platform.SeedDataPath != "" {
		data, err := loadSeedDataFromFile(s.config.Platform.SeedDataPath)
		if err != nil {
			logger.Error("failed to load platform seed data from %s: %v", s.config.Platform.SeedDataPath, err)
		} else {
			logger.Info("loaded platform seed data from %s", s.config.Platform.SeedDataPath)
			seedData = data
		}
	}

	if seedData == nil {
		seedData = defaultSeedData()
		logger.Info("using built-in platform sample data")
	}

	if err := s.applySeedData(seedData); err != nil {
		logger.Error("failed to apply platform seed data: %v", err)
	}
}
