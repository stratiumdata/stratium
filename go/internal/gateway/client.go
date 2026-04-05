package gateway

import (
	"context"
	"fmt"

	ag "stratium/services/agent-gateway"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Client wraps the Agent Gateway gRPC client with convenience methods.
type Client struct {
	conn   *grpc.ClientConn
	client ag.AgentGatewayServiceClient
}

// ClientConfig holds configuration for connecting to the Agent Gateway.
type ClientConfig struct {
	Address string
	TLS     bool
	CAFile  string
}

// NewClient creates a new Agent Gateway gRPC client.
func NewClient(cfg ClientConfig) (*Client, error) {
	var creds credentials.TransportCredentials
	if cfg.TLS && cfg.CAFile != "" {
		var err error
		creds, err = credentials.NewClientTLSFromFile(cfg.CAFile, "")
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.NewClient(cfg.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent gateway at %s: %w", cfg.Address, err)
	}

	return &Client{
		conn:   conn,
		client: ag.NewAgentGatewayServiceClient(conn),
	}, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// withAuth adds the user's OIDC token and user ID to the gRPC context.
func withAuth(ctx context.Context, token, userID string) context.Context {
	md := metadata.Pairs(
		"authorization", "Bearer "+token,
		"x-user-id", userID,
	)
	return metadata.NewOutgoingContext(ctx, md)
}

// RegisterAgent registers a new agent.
func (c *Client) RegisterAgent(ctx context.Context, token, userID string, req *ag.RegisterAgentRequest) (*ag.RegisterAgentResponse, error) {
	return c.client.RegisterAgent(withAuth(ctx, token, userID), req)
}

// GetAgent retrieves an agent by ID.
func (c *Client) GetAgent(ctx context.Context, token, userID string, agentID string) (*ag.GetAgentResponse, error) {
	return c.client.GetAgent(withAuth(ctx, token, userID), &ag.GetAgentRequest{
		AgentId: agentID,
	})
}

// ListAgents lists registered agents.
func (c *Client) ListAgents(ctx context.Context, token, userID string, req *ag.ListAgentsRequest) (*ag.ListAgentsResponse, error) {
	return c.client.ListAgents(withAuth(ctx, token, userID), req)
}

// SuspendAgent suspends an agent and revokes all its delegations.
func (c *Client) SuspendAgent(ctx context.Context, token, userID string, agentID, reason string) (*ag.SuspendAgentResponse, error) {
	return c.client.SuspendAgent(withAuth(ctx, token, userID), &ag.SuspendAgentRequest{
		AgentId: agentID,
		Reason:  reason,
	})
}

// CreateDelegation creates a delegation token.
func (c *Client) CreateDelegation(ctx context.Context, token, userID string, req *ag.CreateDelegationRequest) (*ag.CreateDelegationResponse, error) {
	return c.client.CreateDelegation(withAuth(ctx, token, userID), req)
}

// RevokeDelegation revokes a delegation and cascades to children.
func (c *Client) RevokeDelegation(ctx context.Context, token, userID string, delegationID, reason string) (*ag.RevokeDelegationResponse, error) {
	return c.client.RevokeDelegation(withAuth(ctx, token, userID), &ag.RevokeDelegationRequest{
		DelegationId: delegationID,
		Reason:       reason,
	})
}

// ExecuteAction executes an action through authorization.
func (c *Client) ExecuteAction(ctx context.Context, token, userID string, req *ag.ExecuteActionRequest) (*ag.ExecuteActionResponse, error) {
	return c.client.ExecuteAction(withAuth(ctx, token, userID), req)
}

// ValidateActionPlan validates planned actions against delegation scope.
func (c *Client) ValidateActionPlan(ctx context.Context, token, userID string, req *ag.ValidateActionPlanRequest) (*ag.ValidateActionPlanResponse, error) {
	return c.client.ValidateActionPlan(withAuth(ctx, token, userID), req)
}

// GetDelegationChain retrieves the full delegation chain.
func (c *Client) GetDelegationChain(ctx context.Context, token, userID string, delegationID string) (*ag.GetDelegationChainResponse, error) {
	return c.client.GetDelegationChain(withAuth(ctx, token, userID), &ag.GetDelegationChainRequest{
		DelegationId: delegationID,
	})
}

// Helper to convert proto timestamp to string.
func FormatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format("2006-01-02T15:04:05Z")
}
