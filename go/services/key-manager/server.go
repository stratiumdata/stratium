package key_manager

import (
	"context"
	"fmt"
	"stratium/config"
	"stratium/pkg/auth"
	"stratium/pkg/security/encryption"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements the KeyManagerService gRPC interface
type Server struct {
	UnimplementedKeyManagerServiceServer
	mu              sync.RWMutex
	keyStore        KeyStore
	clientKeyStore  ClientKeyStore
	providerFactory *DefaultProviderFactory
	rotationManager KeyRotationManager
	dekService      *DEKUnwrappingService
	integrityMgr    *KeyIntegrityManager
	authService     *auth.AuthService
	fipsEnabled     bool
}

const (
	clientKeyProviderMetadataKey   = "client_key_provider"
	clientKeyProviderYubiKey       = "yubikey"
	yubiKeyEnvelopeVersionSignedV1 = "yubikey-signed-dek-v1"
)

type yubiKeySignedDEKEnvelope struct {
	Version   string `json:"version"`
	DEK       string `json:"dek"`
	Signature string `json:"signature"`
}

// NewServer creates a new key manager server
func NewServer(encryptionAlgo encryption.Algorithm, cfg *config.Config) (*Server, error) {
	// Build database URL from config
	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Database,
		cfg.Database.SSLMode,
	)

	// Get admin key configuration from config
	adminKeyProvider := cfg.Encryption.AdminKeyProvider
	if adminKeyProvider == "" {
		adminKeyProvider = "composite"
	}
	adminKeyConfig := cfg.Encryption.AdminKeyConfig
	if adminKeyConfig == "" {
		adminKeyConfig = "/var/run/secrets/stratium/admin-key/admin.key"
	}

	// Create key store (PostgreSQL with encryption or in-memory fallback)
	var keyStore KeyStore
	var clientKeyStore ClientKeyStore
	var err error

	cacheTTL := time.Duration(cfg.Service.ServiceKeyCacheTTLSeconds) * time.Second
	if cacheTTL <= 0 {
		cacheTTL = 5 * time.Minute
	}

	// Try to initialize PostgreSQL key store with admin key encryption
	postgresResult, err := initializePostgresKeyStore(databaseURL, adminKeyProvider, adminKeyConfig, cacheTTL)
	if err != nil {
		return nil, err
	} else {
		keyStore = postgresResult.KeyStore
		clientKeyStore = postgresResult.ClientKeyStore
	}

	// Create provider factory with encryption algorithm
	providerFactory := NewDefaultProviderFactory(encryptionAlgo)

	// Inject KeyStore into all providers
	for _, providerType := range providerFactory.GetAvailableProviders() {
		provider, err := providerFactory.GetProvider(providerType)
		if err != nil {
			logger.Error("Failed to get provider %v: %v", providerType, err)
			continue
		}

		// Only inject for software provider (others may not need it)
		if softwareProvider, ok := provider.(*SoftwareKeyProvider); ok {
			softwareProvider.SetKeyStore(keyStore)
		}
	}

	// Create rotation manager
	rotationManager := NewDefaultKeyRotationManager(keyStore, providerFactory)

	// Create DEK service with client key store (for subject public key lookups)
	dekService := NewDEKUnwrappingService(keyStore, providerFactory, clientKeyStore, cfg.Security.FIPS.Enabled)
	logger.Info("DEK service initialized with client key store")

	// Create auth service from config (nil is acceptable for tests)
	authService, err := createAuthServiceFromConfig(cfg)
	if err != nil {
		logger.Warn("failed to create OIDC auth service: %v", err)
		return nil, err
	}
	if authService == nil {
		logger.Info("running without OIDC authentication")
	}

	// Create key integrity manager for client key verification
	integrityMgr := NewKeyIntegrityManager()

	server := &Server{
		keyStore:        keyStore,
		providerFactory: providerFactory,
		rotationManager: rotationManager,
		dekService:      dekService,
		clientKeyStore:  clientKeyStore,
		integrityMgr:    integrityMgr,
		authService:     authService,
		fipsEnabled:     cfg.Security.FIPS.Enabled,
	}

	// Start rotation manager
	if err := rotationManager.Start(); err != nil {
		logger.Info("Failed to start rotation manager: %v", err)
	}

	defaultKeyType, err := AlgorithmToKeyType(encryptionAlgo)
	if err != nil {
		logger.Error("Failed to convert algorithm to key type: %v, using default RSA2048", err)
		defaultKeyType = KeyType_KEY_TYPE_RSA_2048
	}

	if cfg.KeyManager.SeedSampleData {
		server.initializeSeedData(cfg, defaultKeyType)
	} else {
		logger.Info("Key Manager sample data seeding disabled via configuration")
		server.createInitialKey(cfg, defaultKeyType)
	}

	// Load externally managed keys if configured
	if cfg.ExternalKeys.Enabled {
		loader := NewExternalKeyLoader(cfg.ExternalKeys, keyStore)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		report := loader.Load(ctx)
		cancel()

		if report != nil {
			logger.Info("External key loader processed %d/%d sources: %d imported (%d failures)",
				report.SourcesProcessed, report.SourcesConfigured, report.KeysImported, report.KeysFailed)
			for _, sourceReport := range report.SourceReports {
				logger.Info("  - source=%s type=%s path=%s loaded=%d/%d failures=%d",
					sourceReport.Name, sourceReport.Type, sourceReport.Location,
					sourceReport.KeysImported, sourceReport.KeysDiscovered, sourceReport.KeysFailed)
				for _, errMsg := range sourceReport.Errors {
					logger.Info("      • %s", errMsg)
				}
			}
		}
	}

	logger.Startup("Key Manager server initialized successfully")
	return server, nil
}

// PostgresKeyStoreResult contains both the key store and database connection
type PostgresKeyStoreResult struct {
	KeyStore       KeyStore
	ClientKeyStore ClientKeyStore
	DB             *sqlx.DB
}

// initializePostgresKeyStore initializes a PostgreSQL key store with admin key encryption
func initializePostgresKeyStore(databaseURL, adminKeyProvider, adminKeyConfig string, cacheTTL time.Duration) (*PostgresKeyStoreResult, error) {
	// Connect to database
	db, err := sqlx.Connect("postgres", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Startup("✓ Database connection established")

	// Create admin key provider
	provider, err := CreateAdminKeyProvider(adminKeyProvider, adminKeyConfig)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create admin key provider: %w", err)
	}

	logger.Startup("✓ Admin key provider created: %s", provider.GetProviderType())

	// Create admin key manager
	adminKeyMgr := NewAdminKeyManager(provider)

	// Get or create admin key
	ctx := context.Background()
	adminKey, err := adminKeyMgr.GetOrCreateAdminKey(ctx)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to get or create admin key: %w", err)
	}

	logger.Startup("✓ Admin key loaded successfully")

	// Store admin key in database (for foreign key constraint)
	adminKeyID := "admin-key-v1"
	err = storeAdminKeyInDB(db, adminKeyID, adminKey)
	if err != nil {
		logger.Warn("failed to store admin key in database: %v", err)
		// Don't fail if the key already exists - it's okay
	}

	// Create key encryption utility
	keyEncryption, err := NewKeyEncryption(adminKey)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create key encryption: %w", err)
	}

	// Create PostgreSQL key store
	keyStore := NewPostgresKeyStore(db, keyEncryption, adminKeyID, cacheTTL)

	// Create key integrity manager for client keys
	integrityMgr := NewKeyIntegrityManager()

	// Create PostgreSQL client key store
	clientKeyStore := NewPostgresClientKeyStore(db, integrityMgr, cacheTTL)

	logger.Startup("✓ PostgreSQL key store initialized with encryption")
	logger.Startup("✓ PostgreSQL client key store initialized")
	logger.Startup("==================================================================")
	logger.Startup("IMPORTANT: All private keys are encrypted with the admin key")
	logger.Startup("Ensure the admin key is backed up to your secrets manager!")
	logger.Startup("==================================================================")

	return &PostgresKeyStoreResult{
		KeyStore:       keyStore,
		ClientKeyStore: clientKeyStore,
		DB:             db,
	}, nil
}

// createAuthServiceFromConfig creates an auth service from configuration
func createAuthServiceFromConfig(cfg *config.Config) (*auth.AuthService, error) {
	// Check if OIDC is enabled
	if !cfg.OIDC.Enabled {
		logger.Info("OIDC is disabled in configuration - auth service will be nil")
		return nil, nil // Return nil service, not an error
	}

	// Validate OIDC configuration
	if cfg.OIDC.IssuerURL == "" {
		logger.Warn("OIDC configuration incomplete (issuer URL) - auth service will be nil")
		return nil, nil // Return nil service for incomplete config in tests
	}

	if cfg.OIDC.ClientID == "" {
		logger.Warn("OIDC configuration incomplete (client ID) - auth service will be nil")
		return nil, nil // Return nil service for incomplete config in tests
	}

	// Set default scopes if not specified
	if len(cfg.OIDC.Scopes) == 0 {
		logger.Warn("OIDC configuration incomplete (scopes)")
		cfg.OIDC.Scopes = []string{"profile", "email", "groups"}
	}

	logger.Info("Initializing OIDC auth with issuer: %s, client: %s", cfg.OIDC.IssuerURL, cfg.OIDC.ClientID)
	authService, err := auth.NewAuthService(&cfg.OIDC)
	if err != nil {
		// If OIDC provider is unreachable (development without Docker), return nil
		logger.Warn("OIDC provider unreachable: %v - auth service will be nil", err)
		return nil, nil
	}
	return authService, nil
}

// storeAdminKeyInDB stores the admin key reference in the database
// This is required for the foreign key constraint on key_pairs table
func storeAdminKeyInDB(db *sqlx.DB, keyID string, adminKey []byte) error {
	// Check if admin key already exists
	var count int
	err := db.Get(&count, "SELECT COUNT(*) FROM admin_keys WHERE key_id = $1", keyID)
	if err != nil {
		return fmt.Errorf("failed to check if admin key exists: %w", err)
	}

	if count > 0 {
		// Admin key already exists, no need to insert
		return nil
	}

	// Insert admin key record (without storing the actual key material for security)
	// We store a placeholder as the key material is managed by the admin key provider
	query := `
		INSERT INTO admin_keys (key_id, encrypted_key_material, encryption_algorithm, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (key_id) DO NOTHING
	`

	_, err = db.Exec(query, keyID, []byte("managed-externally"), "external", "active")
	if err != nil {
		return fmt.Errorf("failed to insert admin key record: %w", err)
	}

	logger.Info("✓ Admin key reference stored in database: %s", keyID)
	return nil
}

// createInitialKey initializes the first server key pair using the defined key type
func (s *Server) createInitialKey(cfg *config.Config, defaultKeyType KeyType) {
	logger.Debug("creating initial key with default key type: %s", defaultKeyType)

	ctx := context.Background()
	provider := KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE
	rotationPolicy := RotationPolicy_ROTATION_POLICY_TIME_BASED
	rotationInterval := int32(90)

	req := &CreateKeyRequest{
		Name:                 "initial",
		KeyType:              defaultKeyType,
		ProviderType:         provider,
		RotationPolicy:       rotationPolicy,
		RotationIntervalDays: rotationInterval,
		Metadata:             map[string]string{},
	}

	if _, err := s.CreateKey(ctx, req); err != nil {
		logger.Error("failed to create initial key: %v", err)
	} else {
		logger.Info("created key: initial")
	}
}

// GetAuthService returns the authentication service
func (s *Server) GetAuthService() *auth.AuthService {
	return s.authService
}

// CreateKey creates a new encryption key
func (s *Server) CreateKey(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	logger.Debug("CreateKey called - Name: %s, Type: %v, Provider: %v",
		req.Name, req.KeyType, req.ProviderType)

	// Validate request
	if err := s.validateCreateKeyRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request: %v", err)
	}

	// Get provider (use cached instance)
	provider, err := s.providerFactory.GetProvider(req.ProviderType)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to get provider: %v", err)
	}

	// Configure provider if needed
	if len(req.ProviderConfig) > 0 {
		err = provider.Configure(req.ProviderConfig)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to configure provider: %v", err)
		}
	}

	// Generate unique key ID
	keyID := fmt.Sprintf("key-%d", time.Now().UnixNano())

	// Create key pair
	keyPair, err := provider.GenerateKeyPair(ctx, req.KeyType, keyID, req.ProviderConfig)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate key pair: %v", err)
	}

	// Convert to Key message
	key := s.keyPairToKey(keyPair)
	key.Name = req.Name
	key.RotationPolicy = req.RotationPolicy
	key.RotationIntervalDays = req.RotationIntervalDays
	key.MaxUsageCount = req.MaxUsageCount

	if req.ExpiresAt != nil {
		key.ExpiresAt = req.ExpiresAt
	}

	for k, v := range req.Metadata {
		key.Metadata[k] = v
	}

	// Store key (public metadata)
	err = s.keyStore.StoreKey(ctx, key)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to store key: %v", err)
	}

	// Store key pair (private key material) for cryptographic operations
	// This works for both PostgreSQL (with encryption) and in-memory stores
	err = s.keyStore.StoreKeyPair(ctx, keyPair)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to store key pair: %v", err)
	}

	// Schedule rotation if needed
	if req.RotationPolicy != RotationPolicy_ROTATION_POLICY_MANUAL && req.RotationIntervalDays > 0 {
		interval := time.Duration(req.RotationIntervalDays) * 24 * time.Hour
		err = s.rotationManager.ScheduleRotation(keyID, req.RotationPolicy, interval)
		if err != nil {
			logger.Error("failed to schedule rotation for key %s: %v", keyID, err)
		}
	}

	logger.Info("Created key %s successfully", keyID)

	return &CreateKeyResponse{
		Key:       key,
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetKey retrieves a key by ID
func (s *Server) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	logger.Debug("GetKey called - KeyID: %s", req.KeyId)

	if req.KeyId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Key ID is required")
	}

	key, err := s.keyStore.GetKey(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Key not found: %v", err)
	}

	// Optionally exclude public key
	if !req.IncludePublicKey {
		key.PublicKeyPem = ""
	}

	return &GetKeyResponse{
		Key:       key,
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListKeys lists keys with optional filtering
func (s *Server) ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error) {
	logger.Debug("ListKeys called with filters")

	// Build filters
	filters := make(map[string]interface{})
	if req.SubjectFilter != "" {
		filters["subject"] = req.SubjectFilter
	}
	if req.ResourceFilter != "" {
		filters["resource"] = req.ResourceFilter
	}
	if req.ProviderTypeFilter != KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED {
		filters["provider_type"] = req.ProviderTypeFilter
	}
	if req.StatusFilter != KeyStatus_KEY_STATUS_UNSPECIFIED {
		filters["status"] = req.StatusFilter
	}

	// Get keys from store
	keys, err := s.keyStore.ListKeys(ctx, filters)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to list keys: %v", err)
	}

	// Apply pagination
	totalCount := int64(len(keys))
	pageSize := int(req.PageSize)
	if pageSize == 0 {
		pageSize = 50 // Default page size
	}

	startIndex := 0
	if req.PageToken != "" {
		// Simple pagination token (in production, use proper token encoding)
		if token, err := time.Parse(time.RFC3339, req.PageToken); err == nil {
			for i, key := range keys {
				if key.CreatedAt.AsTime().After(token) {
					startIndex = i
					break
				}
			}
		}
	}

	endIndex := startIndex + pageSize
	if endIndex > len(keys) {
		endIndex = len(keys)
	}

	var paginatedKeys []*Key
	var nextPageToken string

	if startIndex < len(keys) {
		paginatedKeys = keys[startIndex:endIndex]
		if endIndex < len(keys) {
			nextPageToken = keys[endIndex].CreatedAt.AsTime().Format(time.RFC3339)
		}
	}

	logger.Info("Returning %d keys (total: %d)", len(paginatedKeys), totalCount)

	return &ListKeysResponse{
		Keys:          paginatedKeys,
		NextPageToken: nextPageToken,
		TotalCount:    totalCount,
		Timestamp:     timestamppb.Now(),
	}, nil
}

// DeleteKey deletes a key
func (s *Server) DeleteKey(ctx context.Context, req *DeleteKeyRequest) (*DeleteKeyResponse, error) {
	logger.Debug("DeleteKey called - KeyID: %s, Force: %t", req.KeyId, req.Force)

	if req.KeyId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Key ID is required")
	}

	// Get key to check if it exists
	key, err := s.keyStore.GetKey(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Key not found: %v", err)
	}
	if key.ExternallyManaged {
		return nil, status.Errorf(codes.FailedPrecondition, "Key %s is externally managed and must be removed at the source", req.KeyId)
	}

	// Check if key is in use (unless force is specified)
	if !req.Force && key.UsageCount > 0 {
		return &DeleteKeyResponse{
			Success:   false,
			Message:   "Key is in use and cannot be deleted (use force=true to override)",
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Cancel any scheduled rotation
	err = s.rotationManager.CancelRotation(req.KeyId)
	if err != nil {
		logger.Error("failed to cancel rotation for key %s: %v", req.KeyId, err)
	}

	// Get provider and delete from provider
	provider, err := s.providerFactory.GetProvider(key.ProviderType)
	if err == nil {
		err = provider.DeleteKeyPair(ctx, req.KeyId)
		if err != nil {
			logger.Error("failed to delete key from provider: %v", err)
		}
	}

	// Delete from key store
	err = s.keyStore.DeleteKey(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to delete key: %v", err)
	}

	logger.Info("Deleted key %s successfully", req.KeyId)

	return &DeleteKeyResponse{
		Success:   true,
		Message:   "Key deleted successfully",
		Timestamp: timestamppb.Now(),
	}, nil
}

// RotateKey rotates a key
func (s *Server) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	logger.Debug("RotateKey called - KeyID: %s, Force: %t", req.KeyId, req.Force)

	if req.KeyId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Key ID is required")
	}

	key, err := s.keyStore.GetKey(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "Key not found: %v", err)
	}
	if key.ExternallyManaged {
		return nil, status.Errorf(codes.FailedPrecondition, "Key %s is externally managed and cannot be rotated via API", req.KeyId)
	}

	// Perform rotation
	response, err := s.rotationManager.PerformRotation(ctx, req.KeyId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to rotate key: %v", err)
	}

	logger.Info("Rotated key %s successfully", req.KeyId)
	return response, nil
}

// UnwrapDEK unwraps a Data Encryption Key with ABAC verification
func (s *Server) UnwrapDEK(ctx context.Context, req *UnwrapDEKRequest) (*UnwrapDEKResponse, error) {
	logger.Debug("UnwrapDEK called - Subject: %s, Resource: %s", req.Subject, req.Resource)

	response, err := s.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to unwrap DEK: %v", err)
	}

	return response, nil
}

func (s *Server) RewrapClientDEK(ctx context.Context, req *RewrapClientDEKRequest) (*RewrapClientDEKResponse, error) {
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	if req.GetClientKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "client_key_id is required")
	}
	if len(req.GetClientWrappedDek()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "client_wrapped_dek is required")
	}
	if req.GetServiceKeyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "service_key_id is required")
	}

	clientKey, err := s.clientKeyStore.GetKey(ctx, req.GetClientKeyId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "client key not found: %v", err)
	}

	var plaintext []byte
	if isYubiKeyClientKey(clientKey) {
		if recovered, recErr := recoverYubiKeySignedDEK(clientKey, req.GetClientWrappedDek()); recErr == nil {
			plaintext = recovered
		} else if shouldAllowYubiKeyPlainClientEnvelope(clientKey) {
			// Plain passthrough is restricted to explicitly touch-required YubiKey registrations.
			plaintext = req.GetClientWrappedDek()
		} else {
			return nil, status.Errorf(codes.InvalidArgument, "failed to unwrap client DEK: %v", recErr)
		}
	} else {
		plaintext, err = decryptClientWrappedDEKWithKey(clientKey, req.GetClientWrappedDek())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "failed to unwrap client DEK: %v", err)
		}
	}

	serviceWrapped, err := s.wrapWithServiceKey(ctx, req.GetServiceKeyId(), plaintext)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to wrap DEK with service key: %v", err)
	}

	return &RewrapClientDEKResponse{
		ServiceWrappedDek: serviceWrapped,
		ServiceKeyId:      req.GetServiceKeyId(),
		Timestamp:         timestamppb.Now(),
	}, nil
}

// ListProviders lists available key providers
func (s *Server) ListProviders(ctx context.Context, req *ListProvidersRequest) (*ListProvidersResponse, error) {
	logger.Debug("ListProviders called - AvailableOnly: %t", req.AvailableOnly)

	providers := s.providerFactory.GetProviderInfo()

	if s.fipsEnabled {
		fipsProviders := make([]*KeyProvider, 0, len(providers))
		for _, provider := range providers {
			provider.SupportedKeyTypes = filterFIPSKeyTypes(provider.SupportedKeyTypes)
			if len(provider.SupportedKeyTypes) == 0 {
				continue
			}
			fipsProviders = append(fipsProviders, provider)
		}
		providers = fipsProviders
	}

	// Filter by availability if requested
	if req.AvailableOnly {
		availableProviders := make([]*KeyProvider, 0)
		for _, provider := range providers {
			if provider.Available {
				availableProviders = append(availableProviders, provider)
			}
		}
		providers = availableProviders
	}

	return &ListProvidersResponse{
		Providers: providers,
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetProviderInfo gets information about a specific provider
func (s *Server) GetProviderInfo(ctx context.Context, req *GetProviderInfoRequest) (*GetProviderInfoResponse, error) {
	logger.Debug("GetProviderInfo called - Type: %v", req.ProviderType)

	providers := s.providerFactory.GetProviderInfo()
	for _, provider := range providers {
		if provider.Type == req.ProviderType {
			if s.fipsEnabled {
				provider.SupportedKeyTypes = filterFIPSKeyTypes(provider.SupportedKeyTypes)
				if len(provider.SupportedKeyTypes) == 0 {
					return nil, status.Errorf(codes.NotFound, "Provider type not found: %v", req.ProviderType)
				}
			}
			return &GetProviderInfoResponse{
				Provider:  provider,
				Timestamp: timestamppb.Now(),
			}, nil
		}
	}

	return nil, status.Errorf(codes.NotFound, "Provider type not found: %v", req.ProviderType)
}
