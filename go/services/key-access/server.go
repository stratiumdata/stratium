package key_access

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"stratium/config"
	"stratium/pkg/auth"
	"stratium/pkg/extractors"
	"sync"
	"time"

	"stratium/pkg/models"
	keyManager "stratium/services/key-manager"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type KeyAccessServiceConfig struct {
	KeyAccessAddr  string
	KeyManagerAddr string
	KeyStorePath   string
	AuthConfig     *auth.AuthConfig
}

// Server implements the KeyAccessService
type Server struct {
	UnimplementedKeyAccessServiceServer
	mu               sync.RWMutex
	keyManagerClient keyManager.KeyManagerServiceClient
	keyManagerConn   *grpc.ClientConn
	platformConn     *grpc.ClientConn
	platformClient   PlatformClient
	authService      *auth.AuthService
	authProvider     auth.AuthProvider
	serviceKeyCache  *serviceKeyCache
}

// SubjectKeyStore manages public keys for subjects
type SubjectKeyStore interface {
	GetSubjectPublicKey(ctx context.Context, subject string) (crypto.PublicKey, error)
	StoreSubjectPublicKey(ctx context.Context, subject string, publicKey crypto.PublicKey) error
	ListSubjects(ctx context.Context) ([]string, error)
}

// PlatformClient interface for ABAC evaluation
type PlatformClient interface {
	EvaluateAccess(ctx context.Context, resourceAttributes map[string]string, action string, context map[string]string) (*AccessDecision, error)
}

// AccessDecision represents the result of ABAC evaluation
type AccessDecision struct {
	Granted      bool
	Reason       string
	AppliedRules []string
	Context      map[string]string
}

// InMemorySubjectKeyStore provides an in-memory implementation
type InMemorySubjectKeyStore struct {
	mu   sync.RWMutex
	keys map[string]crypto.PublicKey
}

// NewServer creates a new key access server
func NewServer(keyManagerAddr string, cfg *config.Config) (*Server, error) {
	// Connect to key manager service
	conn, err := grpc.NewClient(keyManagerAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to key manager: %w", err)
	}

	keyManagerClient := keyManager.NewKeyManagerServiceClient(conn)

	// Create auth service from the provided auth config
	authService, err := createAuthServiceFromConfig(&cfg.OIDC)
	if err != nil {
		logger.Info("Warning: Failed to create OIDC auth service: %v. Using mock auth.", err)
		return nil, err
	}

	// Create Platform client (PDP) or use mock for testing
	platformClient, platformConn, err := createPlatformClient(&cfg.Services.Platform)
	if err != nil {
		logger.Info("Warning: Failed to connect to Platform service: %v", err)
	}

	// Create auth provider
	authProvider, err := auth.NewKeycloakAuthProvider(&auth.AuthConfig{
		IssuerURL:           cfg.OIDC.IssuerURL,
		ClientID:            cfg.OIDC.ClientID,
		ClientSecret:        cfg.OIDC.ClientSecret,
		AllowInsecureIssuer: cfg.OIDC.AllowInsecureIssuer,
	})
	if err != nil {
		return nil, &models.Error{
			Code:    "AUTH_PROVIDER_INIT_FAILED",
			Message: "failed to create auth provider",
			Err:     err,
		}
	}

	cacheTTL := time.Duration(cfg.Service.ServiceKeyCacheTTLSeconds) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}

	server := &Server{
		keyManagerClient: keyManagerClient,
		keyManagerConn:   conn,
		platformConn:     platformConn,
		platformClient:   platformClient,
		authService:      authService,
		authProvider:     authProvider,
		serviceKeyCache:  newServiceKeyCache(cacheTTL),
	}

	logger.Info("Key Access server initialized successfully")
	return server, nil
}

// createPlatformClient creates a Platform client from environment variables
func createPlatformClient(config *config.ServiceEndpoint) (PlatformClient, *grpc.ClientConn, error) {
	platformAddr := config.Address

	if platformAddr == "" {
		return nil, nil, fmt.Errorf("gRPC Platform Address not configured in environment")
	}

	logger.Info("Connecting to Platform service at: %s", platformAddr)
	client, err := NewGRPCPlatformClient(platformAddr)
	if err != nil {
		return nil, nil, err
	}

	return client, client.conn, nil
}

// createAuthServiceFromConfig creates an auth service from auth config
func createAuthServiceFromConfig(oidcConfig *config.OIDCConfig) (*auth.AuthService, error) {
	if oidcConfig == nil || oidcConfig.IssuerURL == "" || oidcConfig.ClientID == "" {
		return nil, fmt.Errorf("OIDC configuration incomplete: issuer_url and client_id are required")
	}

	logger.Info("Initializing OIDC auth with issuer: %s, client: %s", oidcConfig.IssuerURL, oidcConfig.ClientID)
	authService, err := auth.NewAuthService(oidcConfig)
	if err != nil {
		return nil, errors.New("OIDC provider unreachable: " + err.Error())
	}
	return authService, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := getEnv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnv(key string) string {
	return os.Getenv(key)
}

// Close closes the server connections
func (s *Server) Close() error {
	var err error
	if s.keyManagerConn != nil {
		if closeErr := s.keyManagerConn.Close(); closeErr != nil {
			err = closeErr
		}
	}
	if s.platformConn != nil {
		if closeErr := s.platformConn.Close(); closeErr != nil {
			err = closeErr
		}
	}
	return err
}

// GetAuthService returns the authentication service
func (s *Server) GetAuthService() *auth.AuthService {
	return s.authService
}

// WrapDEK wraps a Data Encryption Key using the current encryption key
func (s *Server) WrapDEK(ctx context.Context, req *WrapDEKRequest) (*WrapDEKResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if tokenString, ok := ctx.Value("user_token").(string); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tokenString)
	}

	// Step 1: Extract user claims from OIDC token
	jwtExtractor := &extractors.JWTClaimsExtractor{}
	subjectAttributes, err := jwtExtractor.ExtractSubjectAttributesFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return s.createWrapDeniedResponse(req, fmt.Sprintf("failed to extract subject attributes: %v", err)), nil
	}

	subject := subjectAttributes["sub"]

	// Use preferred_username for ABAC matching (falls back to sub if not available)
	userIdentifier := subjectAttributes["preferred_username"]
	if userIdentifier == "" {
		userIdentifier = subject
	}

	logger.Info("WrapDEK called - User: %s (sub: %s), Resource: %s", userIdentifier, subject, req.Resource)

	// Step 2: Validate input
	if err := s.validateWrapRequest(req); err != nil {
		return s.createWrapDeniedResponse(req, fmt.Sprintf("Invalid request: %v", err)), nil
	}

	// Step 3: Evaluate ABAC rules with user from token
	resourceAttributes, err := extractors.ExtractResourceAttributes(req.Policy)
	if err != nil {
		return s.createWrapDeniedResponse(req, fmt.Sprintf("failed to extract resource policy: %v", err)), nil
	}

	accessDecision, err := s.platformClient.EvaluateAccess(ctx, resourceAttributes, req.Action, req.Context)
	if err != nil {
		return s.createWrapDeniedResponse(req, fmt.Sprintf("ABAC evaluation failed: %v", err)), nil
	}

	if !accessDecision.Granted {
		return s.createWrapDeniedResponse(req, accessDecision.Reason), nil
	}

	// Step 4: Get current encryption key from key manager
	keyID := req.KeyId
	if keyID == "" {
		// Use a default key or get the current active key
		keyID, err = s.getCurrentActiveKeyID(ctx)
		if err != nil {
			return s.createWrapDeniedResponse(req, fmt.Sprintf("Failed to get current key: %v", err)), nil
		}
	}

	// Step 5: Use the DEK directly
	// Note: In production, the DEK would be encrypted with the user's private key
	// and we would verify it here using their public key. For simplicity in this demo,
	// we accept the DEK as-is.
	plaintextDEK := req.Dek

	// Step 6: Retrieve (and cache) the service public key used to encrypt the DEK
	servicePublicKey, err := s.getServicePublicKey(ctx, keyID)
	if err != nil {
		return s.createWrapDeniedResponse(req, err.Error()), nil
	}

	wrappedDEK, err := s.encryptDEK(servicePublicKey, plaintextDEK)
	if err != nil {
		return s.createWrapDeniedResponse(req, fmt.Sprintf("Failed to wrap DEK with service key: %v", err)), nil
	}

	logger.Info("DEK wrapped successfully for user %s", userIdentifier)

	return &WrapDEKResponse{
		WrappedDek:    wrappedDEK,
		KeyId:         keyID,
		AccessGranted: true,
		AccessReason:  accessDecision.Reason,
		AppliedRules:  accessDecision.AppliedRules,
		Timestamp:     timestamppb.Now(),
	}, nil
}

// UnwrapDEK unwraps a Data Encryption Key with ABAC verification
func (s *Server) UnwrapDEK(ctx context.Context, req *UnwrapDEKRequest) (*UnwrapDEKResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if tokenString, ok := ctx.Value("user_token").(string); ok {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tokenString)
	}

	// Step 1: Extract user claims from OIDC token
	jwtExtractor := &extractors.JWTClaimsExtractor{}
	subjectAttributes, err := jwtExtractor.ExtractSubjectAttributesFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return s.createUnwrapDeniedResponse(req, fmt.Sprintf("failed to extract subject attributes: %v", err)), nil
	}

	subject := fmt.Sprintf("%s", subjectAttributes["sub"])

	// Use preferred_username for ABAC matching (falls back to sub if not available)
	userIdentifier := subjectAttributes["preferred_username"]
	if userIdentifier == "" {
		userIdentifier = subject
	}

	logger.Info("UnwrapDEK called - User: %s (sub: %s), Resource: %s", userIdentifier, subject, req.Resource)

	// Step 2: Validate input
	if err := s.validateUnwrapRequest(req); err != nil {
		return s.createUnwrapDeniedResponse(req, fmt.Sprintf("Invalid request: %v", err)), nil
	}

	// Step 3: Evaluate ABAC rules with user from token
	resourceAttributes, err := extractors.ExtractResourceAttributes(req.Policy)
	if err != nil {
		return s.createUnwrapDeniedResponse(req, fmt.Sprintf("failed to extract resource policy: %v", err)), nil
	}

	accessDecision, err := s.platformClient.EvaluateAccess(ctx, resourceAttributes, req.Action, req.Context)
	if err != nil {
		return s.createUnwrapDeniedResponse(req, fmt.Sprintf("ABAC evaluation failed: %v", err)), nil
	}

	if !accessDecision.Granted {
		return s.createUnwrapDeniedResponse(req, accessDecision.Reason), nil
	}

	// Step 4: Unwrap the DEK using the key manager's private key, then re-encrypt for the subject
	// The key manager has access to the private key needed to decrypt the wrapped DEK
	unwrapResp, err := s.keyManagerClient.UnwrapDEK(ctx, &keyManager.UnwrapDEKRequest{
		Subject:      subject,
		Resource:     req.Resource,
		EncryptedDek: req.WrappedDek,
		ClientKeyId:  req.ClientKeyId,
		KeyId:        req.KeyId,
		Action:       req.Action,
		Context:      req.Context,
	})
	if err != nil {
		return s.createUnwrapDeniedResponse(req, fmt.Sprintf("Failed to unwrap DEK: %v", err)), nil
	}

	if !unwrapResp.AccessGranted {
		return s.createUnwrapDeniedResponse(req, unwrapResp.AccessReason), nil
	}

	logger.Info("DEK unwrapped successfully for user %s", userIdentifier)

	return &UnwrapDEKResponse{
		DekForSubject: unwrapResp.EncryptedDekForSubject,
		AccessGranted: true,
		AccessReason:  accessDecision.Reason,
		AppliedRules:  accessDecision.AppliedRules,
		Timestamp:     timestamppb.Now(),
	}, nil
}

// Helper methods

func (s *Server) validateWrapRequest(req *WrapDEKRequest) error {
	// Note: Subject is extracted from OIDC token, not from request
	if req.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if len(req.Dek) == 0 {
		return fmt.Errorf("DEK is required")
	}

	if req.Action == "" {
		req.Action = "wrap_dek" // Default action
	}
	return nil
}

func (s *Server) validateUnwrapRequest(req *UnwrapDEKRequest) error {
	// Note: Subject is extracted from OIDC token, not from request
	if req.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if req.KeyId == "" {
		return fmt.Errorf("key ID is required")
	}
	if len(req.WrappedDek) == 0 {
		return fmt.Errorf("wrapped DEK is required")
	}
	if req.Action == "" {
		req.Action = "unwrap_dek" // Default action
	}
	return nil
}

func (s *Server) getCurrentActiveKeyID(ctx context.Context) (string, error) {
	// List keys and find an active one
	listResp, err := s.keyManagerClient.ListKeys(ctx, &keyManager.ListKeysRequest{
		PageSize: 1,
	})
	if err != nil {
		return "", err
	}

	if len(listResp.Keys) == 0 {
		return "", fmt.Errorf("no keys available")
	}

	// Return the first active key
	for _, key := range listResp.Keys {
		if key.Status == keyManager.KeyStatus_KEY_STATUS_ACTIVE {
			return key.KeyId, nil
		}
	}

	return "", fmt.Errorf("no active keys found")
}

func (s *Server) parsePublicKeyPEM(pemData string, keyType keyManager.KeyType) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Handle KYBER keys differently - they use binary encoding, not ASN.1
	switch keyType {
	case keyManager.KeyType_KEY_TYPE_KYBER_512:
		pub, err := kyber512.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-512 public key: %w", err)
		}
		logger.Info("Parsed KYBER-512 public key")
		return pub, nil

	case keyManager.KeyType_KEY_TYPE_KYBER_768:
		pub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-768 public key: %w", err)
		}
		logger.Info("Parsed KYBER-768 public key")
		return pub, nil

	case keyManager.KeyType_KEY_TYPE_KYBER_1024:
		pub, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-1024 public key: %w", err)
		}
		logger.Info("Parsed KYBER-1024 public key")
		return pub, nil

	default:
		// For RSA and ECC, use standard x509 parsing
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		logger.Info("Parsed public key type: %T", publicKey)
		return publicKey, nil
	}
}

func (s *Server) encryptDEK(publicKey crypto.PublicKey, dek []byte) ([]byte, error) {
	switch pubKey := publicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dek, nil)

	case *ecdsa.PublicKey:
		// For ECC, we use ECIES (Elliptic Curve Integrated Encryption Scheme)
		// Generate ephemeral key pair
		ephemeralKey, err := ecdsa.GenerateKey(pubKey.Curve, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}

		// Derive shared secret using ECDH
		sharedX, _ := pubKey.Curve.ScalarMult(pubKey.X, pubKey.Y, ephemeralKey.D.Bytes())

		// Derive encryption key using HKDF
		kdf := hkdf.New(sha256.New, sharedX.Bytes(), nil, []byte("key-access-dek-wrap"))
		encKey := make([]byte, 32) // AES-256
		if _, err := kdf.Read(encKey); err != nil {
			return nil, fmt.Errorf("failed to derive encryption key: %w", err)
		}

		// Encrypt DEK using AES-GCM
		block, err := aes.NewCipher(encKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}

		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}

		ciphertext := gcm.Seal(nonce, nonce, dek, nil)

		// Return: ephemeral public key || ciphertext
		ephemeralPubKey := append(ephemeralKey.PublicKey.X.Bytes(), ephemeralKey.PublicKey.Y.Bytes()...)
		return append(ephemeralPubKey, ciphertext...), nil

	case *kyber512.PublicKey:
		// KYBER is a KEM - use it to encapsulate a shared secret, then use that to encrypt the DEK
		ciphertext, sharedSecret, err := kyber512.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encapsulate with KYBER-512: %w", err)
		}
		return s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)

	case *kyber768.PublicKey:
		ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encapsulate with KYBER-768: %w", err)
		}
		return s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)

	case *kyber1024.PublicKey:
		ciphertext, sharedSecret, err := kyber1024.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encapsulate with KYBER-1024: %w", err)
		}
		return s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// encryptDEKWithSharedSecret encrypts the DEK using a KEM shared secret
func (s *Server) encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext []byte) ([]byte, error) {
	// Use the shared secret to encrypt the DEK with AES-GCM
	block, err := aes.NewCipher(sharedSecret[:32]) // Use first 32 bytes for AES-256
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the DEK
	encryptedDEK := gcm.Seal(nonce, nonce, dek, nil)

	// Return: KEM ciphertext || encrypted DEK
	// The KEM ciphertext is needed to decapsulate and recover the shared secret
	return append(kemCiphertext, encryptedDEK...), nil
}

// getServicePublicKey returns the cached service public key for the given key ID, fetching and parsing it if needed.
func (s *Server) getServicePublicKey(ctx context.Context, keyID string) (crypto.PublicKey, error) {
	if pub, ok := s.serviceKeyCache.Get(keyID); ok {
		return pub, nil
	}

	getKeyResp, err := s.keyManagerClient.GetKey(ctx, &keyManager.GetKeyRequest{
		KeyId:            keyID,
		IncludePublicKey: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get service key: %w", err)
	}

	publicKey, err := s.parsePublicKeyPEM(getKeyResp.Key.PublicKeyPem, getKeyResp.Key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse service public key: %w", err)
	}

	s.serviceKeyCache.Set(keyID, publicKey)
	return publicKey, nil
}

type serviceKeyCache struct {
	ttl time.Duration
	mu  sync.RWMutex
	key map[string]cachedServiceKey
}

type cachedServiceKey struct {
	publicKey crypto.PublicKey
	expires   time.Time
}

func newServiceKeyCache(ttl time.Duration) *serviceKeyCache {
	return &serviceKeyCache{
		ttl: ttl,
		key: make(map[string]cachedServiceKey),
	}
}

func (c *serviceKeyCache) Get(keyID string) (crypto.PublicKey, bool) {
	c.mu.RLock()
	entry, ok := c.key[keyID]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		if ok {
			c.mu.Lock()
			// Remove expired entry to avoid repeated expiration checks under read lock.
			delete(c.key, keyID)
			c.mu.Unlock()
		}
		return nil, false
	}
	return entry.publicKey, true
}

func (c *serviceKeyCache) Set(keyID string, publicKey crypto.PublicKey) {
	c.mu.Lock()
	c.key[keyID] = cachedServiceKey{
		publicKey: publicKey,
		expires:   time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

func (s *Server) decryptDEK(publicKey crypto.PublicKey, encryptedDek []byte) ([]byte, error) {
	switch pubKey := publicKey.(type) {
	case *rsa.PublicKey:
		// Note: This is unusual - typically you decrypt with a private key, not public key
		// This assumes the DEK was encrypted with the corresponding private key
		// This is more like signature verification than decryption

		// For RSA "decryption" with public key (reverse of private key encryption),
		// we need to use the low-level RSA operations
		return s.rsaPublicDecrypt(pubKey, encryptedDek)
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
}

func (s *Server) rsaPublicDecrypt(pubKey *rsa.PublicKey, ciphertext []byte) ([]byte, error) {
	// Convert ciphertext to big.Int
	c := new(big.Int).SetBytes(ciphertext)

	// Perform RSA public key operation: m = c^e mod n
	e := big.NewInt(int64(pubKey.E))
	m := new(big.Int).Exp(c, e, pubKey.N)

	// Convert back to bytes
	plaintext := m.Bytes()

	// For OAEP padding, we need to remove the padding
	// This is a simplified version - in production, you'd want proper OAEP unpadding
	return plaintext, nil
}

func (s *Server) createWrapDeniedResponse(req *WrapDEKRequest, reason string) *WrapDEKResponse {
	return &WrapDEKResponse{
		WrappedDek:    nil,
		KeyId:         "",
		AccessGranted: false,
		AccessReason:  reason,
		AppliedRules:  []string{},
		Timestamp:     timestamppb.Now(),
	}
}

func (s *Server) createUnwrapDeniedResponse(req *UnwrapDEKRequest, reason string) *UnwrapDEKResponse {
	return &UnwrapDEKResponse{
		DekForSubject: nil,
		AccessGranted: false,
		AccessReason:  reason,
		AppliedRules:  []string{},
		Timestamp:     timestamppb.Now(),
	}
}

// InMemorySubjectKeyStore implementation
func NewInMemorySubjectKeyStore() *InMemorySubjectKeyStore {
	store := &InMemorySubjectKeyStore{
		keys: make(map[string]crypto.PublicKey),
	}
	store.addSampleKeys()
	return store
}

func (s *InMemorySubjectKeyStore) GetSubjectPublicKey(ctx context.Context, subject string) (crypto.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[subject]
	if !exists {
		return nil, fmt.Errorf("public key not found for subject: %s", subject)
	}

	return key, nil
}

func (s *InMemorySubjectKeyStore) StoreSubjectPublicKey(ctx context.Context, subject string, publicKey crypto.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys[subject] = publicKey
	return nil
}

func (s *InMemorySubjectKeyStore) ListSubjects(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	subjects := make([]string, 0, len(s.keys))
	for subject := range s.keys {
		subjects = append(subjects, subject)
	}

	return subjects, nil
}

func (s *InMemorySubjectKeyStore) addSampleKeys() {
	// Generate sample RSA keys for testing subjects
	subjects := []string{"user123", "service-account-1", "admin456", "test-user"}

	for _, subject := range subjects {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Info("Failed to generate sample key for %s: %v", subject, err)
			continue
		}

		s.keys[subject] = &privateKey.PublicKey
		logger.Info("Added sample public key for subject: %s", subject)
	}
}
