package key_access

import (
	"context"
	"fmt"
	"stratium/pkg/auth"
	"stratium/pkg/extractors"

	platform "stratium/services/platform"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// GRPCPlatformClient implements PlatformClient by calling the Platform gRPC service
type GRPCPlatformClient struct {
	client platform.PlatformServiceClient
	conn   *grpc.ClientConn
}

// NewGRPCPlatformClient creates a new Platform client that connects to the Platform service
func NewGRPCPlatformClient(platformAddr string) (*GRPCPlatformClient, error) {
	if platformAddr == "" {
		return nil, fmt.Errorf("platform address is required")
	}

	// Connect to Platform service
	conn, err := grpc.NewClient(
		platformAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to platform service: %w", err)
	}

	client := platform.NewPlatformServiceClient(conn)

	logger.Info("Connected to Platform service at %s", platformAddr)

	return &GRPCPlatformClient{
		client: client,
		conn:   conn,
	}, nil
}

// EvaluateAccess calls the Platform service's PDP to evaluate access
func (p *GRPCPlatformClient) EvaluateAccess(ctx context.Context, resourceAttributes map[string]string, action string, context map[string]string) (*AccessDecision, error) {
	initKeyAccessTelemetry()
	ctx, span := startKeyAccessSpan(ctx, "KeyAccess.PlatformEvaluate",
		attribute.String("action", action),
	)
	defer span.End()

	tokenString, err := auth.ExtractTokenFromMetadata(ctx)
	if err != nil {
		span.RecordError(err)
		return &AccessDecision{
			Granted:      false,
			Reason:       "failed to extract token from metadata",
			AppliedRules: []string{},
		}, err
	}

	jwtExtractor := &extractors.JWTClaimsExtractor{}
	subjectAttributes, err := jwtExtractor.ExtractSubjectAttributes(tokenString)
	if err != nil {
		span.RecordError(err)
		return &AccessDecision{
			Granted:      false,
			Reason:       "failed to extract token attributes",
			AppliedRules: []string{},
		}, err
	}

	subject := subjectAttributes["sub"]

	logger.Info("Evaluating access via Platform PDP: subject=%s, resource=%s, action=%s", subject, resourceAttributes, action)

	convertedSubjectAttributes := make(map[string]*structpb.Value)
	for k, v := range subjectAttributes {
		pbValue, err := structpb.NewValue(v)
		if err != nil {
			continue
		}
		convertedSubjectAttributes[k] = pbValue
	}

	// Call Platform service GetDecision with attribute-based structure
	resp, err := p.client.GetDecision(ctx, &platform.GetDecisionRequest{
		SubjectAttributes:  convertedSubjectAttributes,
		ResourceAttributes: resourceAttributes,
		Action:             action,
		Context:            context,
	})
	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("platform PDP evaluation failed: %w", err)
	}

	// Convert Platform decision to AccessDecision
	decision := &AccessDecision{
		Granted:      resp.Decision == platform.Decision_DECISION_ALLOW,
		Reason:       resp.Reason,
		AppliedRules: []string{}, // Platform doesn't expose individual rules
		Context:      resp.Details,
	}

	// Add evaluated policy to applied rules if available
	if resp.EvaluatedPolicy != "" {
		decision.AppliedRules = append(decision.AppliedRules, resp.EvaluatedPolicy)
	}

	if decision.Granted {
		logger.Info("Platform PDP: Access granted for %s to %s (policy: %s)", subject, resourceAttributes["hash"], resp.EvaluatedPolicy)
	} else {
		logger.Info("Platform PDP: Access denied for %s to %s - %s", subject, resourceAttributes["hash"], resp.Reason)
	}
	span.SetAttributes(
		attribute.Bool("access_granted", decision.Granted),
		attribute.String("evaluated_policy", resp.EvaluatedPolicy),
	)
	if !decision.Granted && resp.Reason != "" {
		span.SetAttributes(attribute.String("access_reason", resp.Reason))
	}

	return decision, nil
}

// Close closes the connection to the Platform service
func (p *GRPCPlatformClient) Close() error {
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}
