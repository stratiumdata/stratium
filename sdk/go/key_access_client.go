package stratium

import (
	"context"
	"fmt"
	"time"

	keyaccess "github.com/stratiumdata/go-sdk/gen/services/key-access"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
)

// KeyAccessClient provides methods for requesting data encryption keys.
//
// The Key Access service issues DEKs (Data Encryption Keys) to authorized
// clients based on policy evaluation.
type KeyAccessClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   tokenProvider

	client keyaccess.KeyAccessServiceClient
}

// DEKRequest contains parameters for requesting a data encryption key.
type DEKRequest struct {
	Resource           string            // Resource identifier being wrapped
	ResourceAttributes map[string]string // Attributes of the resource to encrypt
	Purpose            string            // Purpose of the key (e.g., "encryption", "backup")
	Context            map[string]string // Additional context
	DEK                []byte            // DEK bytes
	Policy             string            // Encoded Base64 Policy
	ClientKeyID        string            // Registered client key identifier
	ClientWrappedDEK   []byte            // DEK wrapped with client's private key
}

// DEKResponse contains the issued data encryption key.
type DEKResponse struct {
	DEK             []byte            // The data encryption key (plaintext)
	WrappedDEK      []byte            // DEK wrapped with client's public key
	KeyID           string            // Identifier for this DEK
	Algorithm       string            // Encryption algorithm to use
	ExpiresAt       string            // When the DEK expires
	PolicyEvaluated string            // Policy that authorized the DEK
	Metadata        map[string]string // Additional metadata
}

// newKeyAccessClient creates a new Key Access client.
func newKeyAccessClient(conn *grpc.ClientConn, config *Config, auth tokenProvider) *KeyAccessClient {
	return &KeyAccessClient{
		conn:   conn,
		config: config,
		auth:   auth,
		client: keyaccess.NewKeyAccessServiceClient(conn),
	}
}

// helper returns an auth helper for this client
func (c *KeyAccessClient) helper() *authHelper {
	return newAuthHelper(c.config, c.auth)
}

// RequestDEK requests a data encryption key for encrypting a resource.
//
// The Key Access service will:
// 1. Evaluate policies to determine if the client is authorized
// 2. Generate a DEK if authorized
// 3. Wrap the DEK with the client's registered public key
// 4. Return both the plaintext and wrapped DEK
//
// Example:
//
//	dek, err := client.KeyAccess.RequestDEK(ctx, &stratium.DEKRequest{
//	    ClientID: "my-app",
//	    ResourceAttributes: map[string]string{
//	        "classification": "secret",
//	        "department":     "engineering",
//	    },
//	    Purpose: "encryption",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use dek.DEK to encrypt data
//	// Store dek.WrappedDEK alongside encrypted data
func (c *KeyAccessClient) RequestDEK(ctx context.Context, req *DEKRequest) (resp *DEKResponse, err error) {
	// Validate request
	if req == nil {
		return nil, ErrRequestNil
	}
	if req.Resource == "" {
		return nil, ErrResourceRequired
	}
	if len(req.ResourceAttributes) == 0 {
		return nil, ErrResourceAttributesRequired
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.KeyAccess.RequestDEK",
		attribute.String("resource", req.Resource),
		attribute.String("purpose", req.Purpose),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "key_access.request_dek", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		if resp != nil {
			span.SetAttributes(attribute.Bool("access_granted", resp.Metadata["access_granted"] == "true"))
		}
		span.End()
	}()

	if req.ClientKeyID == "" {
		return nil, ErrClientKeyRequired
	}
	if len(req.ClientWrappedDEK) == 0 {
		return nil, ErrClientWrapRequired
	}

	// Call gRPC service to wrap DEK
	rpcResp, rpcErr := c.client.WrapDEK(ctx, &keyaccess.WrapDEKRequest{
		Resource:    req.Resource,
		Dek:         req.ClientWrappedDEK,
		Action:      req.Purpose,
		Context:     req.Context,
		Policy:      req.Policy,
		ClientKeyId: req.ClientKeyID,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to wrap DEK: %w", rpcErr)
		return nil, err
	}

	if !rpcResp.AccessGranted {
		err = fmt.Errorf("access denied: %s", rpcResp.AccessReason)
		return nil, err
	}

	resp = &DEKResponse{
		DEK:             []byte{}, // Server doesn't return plaintext DEK for security
		WrappedDEK:      rpcResp.WrappedDek,
		KeyID:           rpcResp.KeyId,
		Algorithm:       "AES-256-GCM", // Default algorithm
		ExpiresAt:       rpcResp.Timestamp.AsTime().Format("2006-01-02T15:04:05Z07:00"),
		PolicyEvaluated: rpcResp.AccessReason,
		Metadata: map[string]string{
			"access_granted": fmt.Sprintf("%t", rpcResp.AccessGranted),
		},
	}

	return resp, nil
}

// UnwrapDEK unwraps a previously issued DEK using the client's private key.
//
// Note: This operation is typically done client-side using the client's
// private key. This method is provided for completeness if server-side
// unwrapping is supported.
//
// Example:
//
//	dek, err := client.KeyAccess.UnwrapDEK(ctx, "my-app", wrappedDEK)
func (c *KeyAccessClient) UnwrapDEK(ctx context.Context, resource, clientKid, kid string, wrappedDEK []byte, policy string) (dek []byte, err error) {
	// Validate request
	if resource == "" {
		return nil, ErrResourceRequired
	}
	if len(wrappedDEK) == 0 {
		return nil, NewValidationError("wrapped_dek", "cannot be empty")
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.KeyAccess.UnwrapDEK",
		attribute.String("resource", resource),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "key_access.unwrap_dek", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	}()

	// Call gRPC service to unwrap DEK
	rpcResp, rpcErr := c.client.UnwrapDEK(ctx, &keyaccess.UnwrapDEKRequest{
		Resource:    resource,
		WrappedDek:  wrappedDEK,
		KeyId:       kid,
		ClientKeyId: clientKid,
		Action:      "unwrap_dek",
		Policy:      policy,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to unwrap DEK: %w", rpcErr)
		return nil, err
	}

	if !rpcResp.AccessGranted {
		err = fmt.Errorf("access denied: %s", rpcResp.AccessReason)
		return nil, err
	}

	return rpcResp.DekForSubject, nil
}
