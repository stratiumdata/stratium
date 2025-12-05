package stratium

import (
	"context"
	"fmt"
	"time"

	platform "github.com/stratiumdata/go-sdk/gen/services/platform"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

// PlatformClient provides methods for making authorization decisions.
//
// The Platform service evaluates authorization requests against policies
// and entitlements to determine if access should be granted.
type PlatformClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   tokenProvider
	client platform.PlatformServiceClient
}

// Decision represents an authorization decision.
type Decision int32

const (
	DecisionUnspecified Decision = 0
	DecisionAllow       Decision = 1
	DecisionDeny        Decision = 2
	DecisionConditional Decision = 3
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "ALLOW"
	case DecisionDeny:
		return "DENY"
	case DecisionConditional:
		return "CONDITIONAL"
	case DecisionUnspecified:
		return "UNSPECIFIED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", int32(d))
	}
}

// AuthorizationRequest contains the parameters for an authorization decision.
type AuthorizationRequest struct {
	// Subject attributes (user/client making the request)
	SubjectAttributes map[string]string

	// Resource attributes (what is being accessed)
	ResourceAttributes map[string]string

	// Action being performed (e.g., "read", "write", "delete")
	Action string

	// Additional context for the decision
	Context map[string]string
}

// AuthorizationResponse contains the result of an authorization decision.
type AuthorizationResponse struct {
	Decision        Decision          // The authorization decision
	Reason          string            // Explanation for the decision
	EvaluatedPolicy string            // Policy that made the decision
	Details         map[string]string // Additional details
	Timestamp       string            // When the decision was made
}

// Entitlement represents an access entitlement.
type Entitlement struct {
	ID                 string
	Subject            string
	Resource           string
	Actions            []string
	Conditions         []Condition
	Active             bool
	ResourceAttributes map[string]string
}

// Condition represents a conditional access requirement.
type Condition struct {
	Type       string            // Type of condition (e.g., "time", "attribute")
	Operator   string            // Operator (e.g., "equals", "contains", "before", "after")
	Value      string            // Value to compare against
	Parameters map[string]string // Additional parameters
}

// newPlatformClient creates a new Platform client.
func newPlatformClient(conn *grpc.ClientConn, config *Config, auth tokenProvider) *PlatformClient {
	return &PlatformClient{
		conn:   conn,
		config: config,
		auth:   auth,
		client: platform.NewPlatformServiceClient(conn),
	}
}

// helper returns an auth helper for this client
func (c *PlatformClient) helper() *authHelper {
	return newAuthHelper(c.config, c.auth)
}

// GetDecision makes an authorization decision for the given request.
//
// This is the primary method for checking if a subject (user/client) is
// authorized to perform an action on a resource.
//
// Example:
//
//	decision, err := client.Platform.GetDecision(ctx, &stratium.AuthorizationRequest{
//	    SubjectAttributes: map[string]string{
//	        "sub":        "user123",
//	        "email":      "user@example.com",
//	        "department": "engineering",
//	    },
//	    ResourceAttributes: map[string]string{
//	        "name": "document-service",
//	        "type": "service",
//	    },
//	    Action: "read",
//	    Context: map[string]string{
//	        "ip_address": "192.168.1.100",
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if decision.Decision == stratium.DecisionAllow {
//	    // Grant access
//	} else {
//	    // Deny access
//	    log.Printf("Access denied: %s", decision.Reason)
//	}
func (c *PlatformClient) GetDecision(ctx context.Context, req *AuthorizationRequest) (resp *AuthorizationResponse, err error) {
	// Validate request
	if req == nil {
		return nil, ErrRequestNil
	}
	if req.Action == "" {
		return nil, ErrActionRequired
	}
	if len(req.SubjectAttributes) == 0 {
		return nil, ErrSubjectAttributesRequired
	}

	// Validate subject has an identifier
	if err := validateSubjectIdentifier(req.SubjectAttributes); err != nil {
		return nil, err
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.Platform.GetDecision",
		attribute.String("action", req.Action),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "platform.get_decision", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		if resp != nil {
			span.SetAttributes(attribute.String("decision", resp.Decision.String()))
		}
		span.End()
	}()

	// Convert subject attributes to structpb.Value map
	subjectAttrs, err := stringMapToStructMap(req.SubjectAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert subject attributes: %w", err)
	}

	// Call gRPC service
	rpcResp, rpcErr := c.client.GetDecision(ctx, &platform.GetDecisionRequest{
		SubjectAttributes:  subjectAttrs,
		ResourceAttributes: req.ResourceAttributes,
		Action:             req.Action,
		Context:            req.Context,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to get decision: %w", rpcErr)
		return nil, err
	}

	// Convert proto decision to SDK decision
	decision := Decision(rpcResp.Decision)
	resp = &AuthorizationResponse{
		Decision:        decision,
		Reason:          rpcResp.Reason,
		EvaluatedPolicy: rpcResp.EvaluatedPolicy,
		Details:         rpcResp.Details,
		Timestamp:       rpcResp.Timestamp.AsTime().Format("2006-01-02T15:04:05Z07:00"),
	}
	return resp, nil
}

// GetEntitlements retrieves all entitlements for a subject.
//
// Example:
//
//	entitlements, err := client.Platform.GetEntitlements(ctx, map[string]string{
//	    "sub": "user123",
//	})
func (c *PlatformClient) GetEntitlements(ctx context.Context, subjectAttributes map[string]string) ([]*Entitlement, error) {
	// Validate request
	if len(subjectAttributes) == 0 {
		return nil, ErrSubjectAttributesRequired
	}

	// Validate subject has an identifier
	if err := validateSubjectIdentifier(subjectAttributes); err != nil {
		return nil, err
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// TODO: Call gRPC service
	// resp, err := c.client.GetEntitlements(ctx, &platform.GetEntitlementsRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// CheckAccess is a convenience method that returns true if access is allowed.
//
// Example:
//
//	allowed, err := client.Platform.CheckAccess(ctx, &stratium.AuthorizationRequest{
//	    SubjectAttributes: map[string]string{"sub": "user123"},
//	    ResourceAttributes: map[string]string{"name": "document-service"},
//	    Action: "read",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if allowed {
//	    // Grant access
//	} else {
//	    // Deny access
//	}
func (c *PlatformClient) CheckAccess(ctx context.Context, req *AuthorizationRequest) (bool, error) {
	decision, err := c.GetDecision(ctx, req)
	if err != nil {
		return false, err
	}
	return decision.Decision == DecisionAllow, nil
}

// stringMapToStructMap converts a map[string]string to map[string]*structpb.Value
func stringMapToStructMap(m map[string]string) (map[string]*structpb.Value, error) {
	result := make(map[string]*structpb.Value, len(m))
	for k, v := range m {
		result[k] = structpb.NewStringValue(v)
	}
	return result, nil
}
