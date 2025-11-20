package platform

import (
	"context"
	"fmt"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// Client wraps the Platform service gRPC client
type Client struct {
	conn   *grpc.ClientConn
	client PlatformServiceClient
}

// NewClient creates a new Platform service client
func NewClient(address string) (*Client, error) {
	conn, err := grpc.NewClient(
		address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to platform service: %w", err)
	}

	client := NewPlatformServiceClient(conn)

	return &Client{
		conn:   conn,
		client: client,
	}, nil
}

// Close closes the gRPC connection
func (c *Client) Close() error {
	return c.conn.Close()
}

// CheckAccess checks if a subject can perform an action on a resource
func (c *Client) CheckAccess(ctx context.Context, subject, resource map[string]string, action string) (bool, string, error) {
	// Convert subject attributes to protobuf Values
	subjectAttrs := make(map[string]*structpb.Value)
	for k, v := range subject {
		val, err := structpb.NewValue(v)
		if err != nil {
			log.Printf("Warning: failed to convert subject attribute %s: %v", k, err)
			continue
		}
		subjectAttrs[k] = val
	}

	// Create request
	req := &GetDecisionRequest{
		SubjectAttributes:  subjectAttrs,
		ResourceAttributes: resource,
		Action:             action,
	}

	// Set timeout for the request
	ctxWithTimeout, cancel := context.WithTimeout(ctx, 360*time.Second)
	defer cancel()

	// Call Platform service
	resp, err := c.client.GetDecision(ctxWithTimeout, req)
	if err != nil {
		return false, "", fmt.Errorf("failed to get decision: %w", err)
	}

	// Check decision
	allowed := resp.Decision == Decision_DECISION_ALLOW
	reason := resp.Reason

	log.Printf("ABAC Decision: action=%s, allowed=%v, reason=%s", action, allowed, reason)

	return allowed, reason, nil
}

// DecisionRequest represents a simplified decision request
type DecisionRequest struct {
	SubjectID    string
	SubjectEmail string
	Department   string
	Role         string
	ResourceType string
	ResourceID   string
	OwnerID      string
	ResourceDept string
	Action       string
}

// CheckAccessSimple provides a simplified interface for access checks
func (c *Client) CheckAccessSimple(ctx context.Context, req DecisionRequest) (bool, string, error) {
	subject := map[string]string{
		"user_id":    req.SubjectID,
		"email":      req.SubjectEmail,
		"department": req.Department,
		"role":       req.Role,
	}

	resource := map[string]string{
		"resource_type": req.ResourceType,
		"resource_id":   req.ResourceID,
		"owner_id":      req.OwnerID,
		"department":    req.ResourceDept,
	}

	return c.CheckAccess(ctx, subject, resource, req.Action)
}
