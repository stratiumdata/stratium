package stratium

import (
	"context"
	"fmt"
	"time"

	keymanager "github.com/stratiumdata/go-sdk/gen/services/key-manager"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// KeyManagerClient provides methods for interacting with the Key Manager service.
//
// The Key Manager service handles:
//   - Client key registration and lifecycle management
//   - Data encryption key (DEK) generation and wrapping
//   - Key integrity verification
type KeyManagerClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   tokenProvider
	client keymanager.KeyManagerServiceClient
}

// KeyType represents the type of cryptographic key.
type KeyType int32

const (
	KeyTypeRSA2048   KeyType = 1
	KeyTypeRSA3072   KeyType = 2
	KeyTypeRSA4096   KeyType = 3
	KeyTypeECC256    KeyType = 4
	KeyTypeECC384    KeyType = 5
	KeyTypeECC521    KeyType = 6
	KeyTypeKyber512  KeyType = 7
	KeyTypeKyber768  KeyType = 8
	KeyTypeKyber1024 KeyType = 9
)

// ClientKey represents a registered client public key.
type ClientKey struct {
	KeyID        string
	ClientID     string
	KeyType      KeyType
	PublicKeyPEM string
	Status       string
	CreatedAt    string
	ExpiresAt    string
	Metadata     map[string]string
}

// RegisterKeyRequest contains the parameters for registering a client key.
type RegisterKeyRequest struct {
	ClientID     string            // Client identifier
	PublicKeyPEM string            // PEM-encoded public key
	KeyType      KeyType           // Type of key (RSA, ECC, Kyber)
	ExpiresAt    string            // Optional expiration time (RFC3339 format)
	Metadata     map[string]string // Optional metadata
}

// GetKeyRequest contains the parameters for retrieving a client key.
type GetKeyRequest struct {
	ClientID string // Client identifier
	KeyID    string // Key identifier
}

// EncryptionResult contains the result of data encryption.
type EncryptionResult struct {
	Ciphertext    []byte // Encrypted data
	WrappedDEK    []byte // Wrapped data encryption key
	EncryptionAlg string // Algorithm used for encryption
}

// DecryptionRequest contains the parameters for data decryption.
type DecryptionRequest struct {
	ClientID      string // Client identifier
	KeyID         string // Key identifier used for encryption
	Ciphertext    []byte // Encrypted data
	WrappedDEK    []byte // Wrapped data encryption key
	EncryptionAlg string // Algorithm used for encryption
}

// newKeyManagerClient creates a new Key Manager client.
func newKeyManagerClient(conn *grpc.ClientConn, config *Config, auth tokenProvider) *KeyManagerClient {
	return &KeyManagerClient{
		conn:   conn,
		config: config,
		auth:   auth,
		client: keymanager.NewKeyManagerServiceClient(conn),
	}
}

// helper returns an auth helper for this client
func (c *KeyManagerClient) helper() *authHelper {
	return newAuthHelper(c.config, c.auth)
}

// RegisterKey registers a new client public key with the Key Manager.
//
// This should be called once per client to register their public key for
// data encryption key (DEK) wrapping.
//
// Example:
//
//	key, err := client.KeyManager.RegisterKey(ctx, &stratium.RegisterKeyRequest{
//	    ClientID:     "my-app",
//	    PublicKeyPEM: publicKeyPEM,
//	    KeyType:      stratium.KeyTypeRSA4096,
//	})
func (c *KeyManagerClient) RegisterKey(ctx context.Context, req *RegisterKeyRequest) (resp *ClientKey, err error) {
	// Validate request
	if req == nil {
		return nil, ErrRequestNil
	}
	if req.ClientID == "" {
		return nil, ErrClientIDRequired
	}
	if req.PublicKeyPEM == "" {
		return nil, NewValidationError("public_key_pem", "is required")
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.KeyManager.RegisterKey",
		attribute.String("client_id", req.ClientID),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "key_manager.register_key", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	}()

	// Parse expiration time if provided
	var expiresAt *timestamppb.Timestamp
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format: %w", err)
		}
		expiresAt = timestamppb.New(t)
	}

	// Call gRPC service
	rpcResp, rpcErr := c.client.RegisterClientKey(ctx, &keymanager.RegisterClientKeyRequest{
		ClientId:     req.ClientID,
		PublicKeyPem: req.PublicKeyPEM,
		KeyType:      keymanager.KeyType(req.KeyType),
		ExpiresAt:    expiresAt,
		Metadata:     req.Metadata,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to register key: %w", rpcErr)
		return nil, err
	}

	if !rpcResp.Success {
		err = fmt.Errorf("key registration failed: %s", rpcResp.ErrorMessage)
		return nil, err
	}

	resp = &ClientKey{
		KeyID:        rpcResp.Key.KeyId,
		ClientID:     rpcResp.Key.ClientId,
		KeyType:      KeyType(rpcResp.Key.KeyType),
		PublicKeyPEM: rpcResp.Key.PublicKeyPem,
		Status:       rpcResp.Key.Status.String(),
		CreatedAt:    rpcResp.Key.CreatedAt.AsTime().Format(time.RFC3339),
		ExpiresAt:    formatTimestamp(rpcResp.Key.ExpiresAt),
		Metadata:     rpcResp.Key.Metadata,
	}
	return resp, nil
}

// GetKey retrieves a registered client key by ID.
//
// Example:
//
//	key, err := client.KeyManager.GetKey(ctx, &stratium.GetKeyRequest{
//	    ClientID: "my-app",
//	    KeyID:    "key-12345",
//	})
func (c *KeyManagerClient) GetKey(ctx context.Context, req *GetKeyRequest) (resp *ClientKey, err error) {
	// Validate request
	if req == nil {
		return nil, ErrRequestNil
	}
	if req.ClientID == "" {
		return nil, ErrClientIDRequired
	}
	if req.KeyID == "" {
		return nil, NewValidationError("key_id", "is required")
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.KeyManager.GetKey",
		attribute.String("client_id", req.ClientID),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "key_manager.get_key", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	}()

	rpcResp, rpcErr := c.client.GetClientKey(ctx, &keymanager.GetClientKeyRequest{
		ClientId: req.ClientID,
		KeyId:    req.KeyID,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to get key: %w", rpcErr)
		return nil, err
	}

	if !rpcResp.Found {
		err = fmt.Errorf("key not found: %s", rpcResp.ErrorMessage)
		return nil, err
	}

	resp = &ClientKey{
		KeyID:        rpcResp.Key.KeyId,
		ClientID:     rpcResp.Key.ClientId,
		KeyType:      KeyType(rpcResp.Key.KeyType),
		PublicKeyPEM: rpcResp.Key.PublicKeyPem,
		Status:       rpcResp.Key.Status.String(),
		CreatedAt:    rpcResp.Key.CreatedAt.AsTime().Format(time.RFC3339),
		ExpiresAt:    formatTimestamp(rpcResp.Key.ExpiresAt),
		Metadata:     rpcResp.Key.Metadata,
	}
	return resp, nil
}

// EncryptData encrypts data using a generated DEK, wrapped with the client's public key.
//
// The Key Manager generates a data encryption key (DEK), encrypts the data,
// and wraps the DEK with the client's public key. The client can then unwrap
// the DEK with their private key to decrypt the data.
//
// Example:
//
//	result, err := client.KeyManager.EncryptData(ctx, "my-app", "key-12345", []byte("sensitive data"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Store result.Ciphertext and result.WrappedDEK
func (c *KeyManagerClient) EncryptData(ctx context.Context, clientID, keyID string, plaintext []byte) (*EncryptionResult, error) {
	// Validate request
	if clientID == "" {
		return nil, ErrClientIDRequired
	}
	if keyID == "" {
		return nil, NewValidationError("key_id", "is required")
	}
	if len(plaintext) == 0 {
		return nil, NewValidationError("plaintext", "cannot be empty")
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// TODO: Call gRPC service
	// resp, err := c.client.EncryptData(ctx, &keymanager.EncryptDataRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// DecryptData decrypts data using the wrapped DEK.
//
// The client must first unwrap the DEK using their private key, then call
// this method to decrypt the data.
//
// Example:
//
//	plaintext, err := client.KeyManager.DecryptData(ctx, &stratium.DecryptionRequest{
//	    ClientID:      "my-app",
//	    KeyID:         "key-12345",
//	    Ciphertext:    ciphertext,
//	    WrappedDEK:    wrappedDEK,
//	    EncryptionAlg: "AES-256-GCM",
//	})
func (c *KeyManagerClient) DecryptData(ctx context.Context, req *DecryptionRequest) ([]byte, error) {
	// Validate request
	if req == nil {
		return nil, ErrRequestNil
	}
	if req.ClientID == "" {
		return nil, ErrClientIDRequired
	}
	if req.KeyID == "" {
		return nil, NewValidationError("key_id", "is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, NewValidationError("ciphertext", "cannot be empty")
	}
	if len(req.WrappedDEK) == 0 {
		return nil, NewValidationError("wrapped_dek", "cannot be empty")
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	// TODO: Call gRPC service
	// resp, err := c.client.DecryptData(ctx, &keymanager.DecryptDataRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// ListKeys lists all registered keys for a client.
//
// Example:
//
//	keys, err := client.KeyManager.ListKeys(ctx, "my-app", false)
func (c *KeyManagerClient) ListKeys(ctx context.Context, clientID string, includeRevoked bool) (keys []*ClientKey, err error) {
	// Validate request
	if clientID == "" {
		return nil, ErrClientIDRequired
	}

	// Get auth context
	ctx, cancel, _, err := c.helper().getTokenAndContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()

	ctx, span := startSDKSpan(ctx, "SDK.KeyManager.ListKeys",
		attribute.String("client_id", clientID),
	)
	start := time.Now()
	defer func() {
		recordSDKRequestMetrics(ctx, "key_manager.list_keys", time.Since(start), err)
		if err != nil {
			span.RecordError(err)
		}
		span.End()
	}()

	resp, rpcErr := c.client.ListClientKeys(ctx, &keymanager.ListClientKeysRequest{
		ClientId:       clientID,
		IncludeRevoked: includeRevoked,
	})
	if rpcErr != nil {
		err = fmt.Errorf("failed to list keys: %w", rpcErr)
		return nil, err
	}

	keys = make([]*ClientKey, len(resp.Keys))
	for i, key := range resp.Keys {
		keys[i] = &ClientKey{
			KeyID:        key.KeyId,
			ClientID:     key.ClientId,
			KeyType:      KeyType(key.KeyType),
			PublicKeyPEM: key.PublicKeyPem,
			Status:       key.Status.String(),
			CreatedAt:    key.CreatedAt.AsTime().Format(time.RFC3339),
			ExpiresAt:    formatTimestamp(key.ExpiresAt),
			Metadata:     key.Metadata,
		}
	}

	return keys, nil
}

// formatTimestamp formats a protobuf timestamp to RFC3339 string, or returns empty if nil
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}
