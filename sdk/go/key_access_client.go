package stratium

import (
	"context"
	"fmt"

	keyaccess "github.com/stratiumdata/go-sdk/gen/services/key-access"

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
func (c *KeyAccessClient) RequestDEK(ctx context.Context, req *DEKRequest) (*DEKResponse, error) {
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

	// Call gRPC service to wrap DEK
	resp, err := c.client.WrapDEK(ctx, &keyaccess.WrapDEKRequest{
		Resource: req.Resource, // Use client ID as resource identifier
		Dek:      req.DEK,
		Action:   req.Purpose,
		Context:  req.Context,
		Policy:   req.Policy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	if !resp.AccessGranted {
		return nil, fmt.Errorf("access denied: %s", resp.AccessReason)
	}

	return &DEKResponse{
		DEK:             []byte{}, // Server doesn't return plaintext DEK for security
		WrappedDEK:      resp.WrappedDek,
		KeyID:           resp.KeyId,
		Algorithm:       "AES-256-GCM", // Default algorithm
		ExpiresAt:       resp.Timestamp.AsTime().Format("2006-01-02T15:04:05Z07:00"),
		PolicyEvaluated: resp.AccessReason,
		Metadata: map[string]string{
			"access_granted": fmt.Sprintf("%t", resp.AccessGranted),
		},
	}, nil
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
func (c *KeyAccessClient) UnwrapDEK(ctx context.Context, resource, clientKid, kid string, wrappedDEK []byte, policy string) ([]byte, error) {
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

	// Call gRPC service to unwrap DEK
	resp, err := c.client.UnwrapDEK(ctx, &keyaccess.UnwrapDEKRequest{
		Resource:    resource,
		WrappedDek:  wrappedDEK,
		KeyId:       kid,
		ClientKeyId: clientKid,
		Action:      "unwrap_dek",
		Policy:      policy,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	if !resp.AccessGranted {
		return nil, fmt.Errorf("access denied: %s", resp.AccessReason)
	}

	return resp.DekForSubject, nil
}
