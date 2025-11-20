package stratium

import (
	"context"
	"fmt"
	"net"
	"testing"

	platform "github.com/stratiumdata/go-sdk/gen/services/platform"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Integration tests for PlatformClient using in-process gRPC server mocking.

const platformBufSize = 1024 * 1024

// mockPlatformServer implements the PlatformServiceServer interface for testing
type mockPlatformServer struct {
	platform.UnimplementedPlatformServiceServer

	// Configure response behavior
	decision       platform.Decision
	shouldDenyAll  bool
	shouldError    bool
	entitlements   []*platform.Entitlement
}

func (m *mockPlatformServer) GetDecision(ctx context.Context, req *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	if m.shouldError {
		return nil, fmt.Errorf("internal server error")
	}

	decision := m.decision
	if m.shouldDenyAll {
		decision = platform.Decision_DECISION_DENY
	}

	return &platform.GetDecisionResponse{
		Decision:        decision,
		Reason:          "Policy evaluation completed",
		EvaluatedPolicy: "test-policy",
		Details:         map[string]string{"evaluation_time_ms": "10"},
		Timestamp:       timestamppb.Now(),
	}, nil
}

func (m *mockPlatformServer) GetEntitlements(ctx context.Context, req *platform.GetEntitlementsRequest) (*platform.GetEntitlementsResponse, error) {
	if m.shouldError {
		return nil, fmt.Errorf("internal server error")
	}

	return &platform.GetEntitlementsResponse{
		Entitlements: m.entitlements,
	}, nil
}

// setupPlatformTest creates an in-process gRPC server for testing
func setupPlatformTest(t *testing.T, mockServer *mockPlatformServer) (*PlatformClient, func()) {
	lis := bufconn.Listen(platformBufSize)

	s := grpc.NewServer()
	platform.RegisterPlatformServiceServer(s, mockServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}

	config := &Config{
		Timeout: 0,
	}
	mockAuth := &mockAuthManager{
		token: "test-token",
	}
	client := newPlatformClient(conn, config, mockAuth)

	cleanup := func() {
		conn.Close()
		s.Stop()
	}

	return client, cleanup
}

// ===== GetDecision Tests =====

func TestPlatformClient_GetDecision(t *testing.T) {
	mockServer := &mockPlatformServer{
		decision: platform.Decision_DECISION_ALLOW,
	}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{
			"sub":   "user123",
			"email": "user@example.com",
		},
		ResourceAttributes: map[string]string{
			"name": "document-service",
		},
		Action: "read",
	}

	ctx := context.Background()
	resp, err := client.GetDecision(ctx, req)
	if err != nil {
		t.Fatalf("GetDecision() error: %v", err)
	}

	if resp == nil {
		t.Fatal("GetDecision() returned nil response")
	}

	if resp.Decision != DecisionAllow {
		t.Errorf("GetDecision() decision = %v, want %v", resp.Decision, DecisionAllow)
	}

	if resp.Reason == "" {
		t.Error("GetDecision() should return a reason")
	}
}

func TestPlatformClient_GetDecision_NilRequest(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.GetDecision(ctx, nil)
	if err != ErrRequestNil {
		t.Errorf("GetDecision() with nil request expected ErrRequestNil, got: %v", err)
	}
}

func TestPlatformClient_GetDecision_MissingAction(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{"sub": "user123"},
	}

	ctx := context.Background()
	_, err := client.GetDecision(ctx, req)
	if err != ErrActionRequired {
		t.Errorf("GetDecision() with missing action expected ErrActionRequired, got: %v", err)
	}
}

func TestPlatformClient_GetDecision_MissingSubjectAttributes(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		Action: "read",
	}

	ctx := context.Background()
	_, err := client.GetDecision(ctx, req)
	if err != ErrSubjectAttributesRequired {
		t.Errorf("GetDecision() with missing subject expected ErrSubjectAttributesRequired, got: %v", err)
	}
}

func TestPlatformClient_GetDecision_NoSubjectIdentifier(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{
			"email": "user@example.com", // Missing sub, user_id, or id
		},
		Action: "read",
	}

	ctx := context.Background()
	_, err := client.GetDecision(ctx, req)
	if err == nil {
		t.Error("GetDecision() expected error for missing subject identifier, got nil")
	}
}

func TestPlatformClient_GetDecision_Deny(t *testing.T) {
	mockServer := &mockPlatformServer{
		decision: platform.Decision_DECISION_DENY,
	}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{"sub": "user123"},
		Action:            "delete",
	}

	ctx := context.Background()
	resp, err := client.GetDecision(ctx, req)
	if err != nil {
		t.Fatalf("GetDecision() error: %v", err)
	}

	if resp.Decision != DecisionDeny {
		t.Errorf("GetDecision() decision = %v, want %v", resp.Decision, DecisionDeny)
	}
}

func TestPlatformClient_GetDecision_ServerError(t *testing.T) {
	mockServer := &mockPlatformServer{
		shouldError: true,
	}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{"sub": "user123"},
		Action:            "read",
	}

	ctx := context.Background()
	_, err := client.GetDecision(ctx, req)
	if err == nil {
		t.Error("GetDecision() expected error for server error, got nil")
	}
}

// ===== CheckAccess Tests =====

func TestPlatformClient_CheckAccess_Allow(t *testing.T) {
	mockServer := &mockPlatformServer{
		decision: platform.Decision_DECISION_ALLOW,
	}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{"sub": "user123"},
		Action:            "read",
	}

	ctx := context.Background()
	allowed, err := client.CheckAccess(ctx, req)
	if err != nil {
		t.Fatalf("CheckAccess() error: %v", err)
	}

	if !allowed {
		t.Error("CheckAccess() should return true for ALLOW decision")
	}
}

func TestPlatformClient_CheckAccess_Deny(t *testing.T) {
	mockServer := &mockPlatformServer{
		decision: platform.Decision_DECISION_DENY,
	}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	req := &AuthorizationRequest{
		SubjectAttributes: map[string]string{"sub": "user123"},
		Action:            "delete",
	}

	ctx := context.Background()
	allowed, err := client.CheckAccess(ctx, req)
	if err != nil {
		t.Fatalf("CheckAccess() error: %v", err)
	}

	if allowed {
		t.Error("CheckAccess() should return false for DENY decision")
	}
}

// ===== GetEntitlements Tests =====

func TestPlatformClient_GetEntitlements_NotImplemented(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.GetEntitlements(ctx, map[string]string{"sub": "user123"})
	if err == nil {
		t.Error("GetEntitlements() expected not implemented error")
	}
}

func TestPlatformClient_GetEntitlements_MissingSubjectAttributes(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.GetEntitlements(ctx, map[string]string{})
	if err != ErrSubjectAttributesRequired {
		t.Errorf("GetEntitlements() with empty attributes expected ErrSubjectAttributesRequired, got: %v", err)
	}
}

func TestPlatformClient_GetEntitlements_NoSubjectIdentifier(t *testing.T) {
	mockServer := &mockPlatformServer{}
	client, cleanup := setupPlatformTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.GetEntitlements(ctx, map[string]string{"email": "user@example.com"})
	if err == nil {
		t.Error("GetEntitlements() expected error for missing subject identifier, got nil")
	}
}

// ===== Helper Function Tests =====

func TestStringMapToStructMap(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]string
		want  int // number of keys
	}{
		{
			name:  "empty map",
			input: map[string]string{},
			want:  0,
		},
		{
			name: "single entry",
			input: map[string]string{
				"key": "value",
			},
			want: 1,
		},
		{
			name: "multiple entries",
			input: map[string]string{
				"sub":   "user123",
				"email": "user@example.com",
				"role":  "admin",
			},
			want: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := stringMapToStructMap(tt.input)
			if err != nil {
				t.Errorf("stringMapToStructMap() error: %v", err)
			}

			if len(result) != tt.want {
				t.Errorf("stringMapToStructMap() length = %v, want %v", len(result), tt.want)
			}

			// Verify each value is a structpb.Value
			for k, v := range result {
				if v == nil {
					t.Errorf("stringMapToStructMap() key %s has nil value", k)
				}
				if _, ok := v.Kind.(*structpb.Value_StringValue); !ok {
					t.Errorf("stringMapToStructMap() key %s is not a string value", k)
				}
			}
		})
	}
}
