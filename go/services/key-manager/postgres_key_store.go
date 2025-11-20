package key_manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PostgresKeyStore provides a PostgreSQL-backed implementation of KeyStore
// with encrypted private key storage using the admin key
type PostgresKeyStore struct {
	db            *sqlx.DB
	keyEncryption *KeyEncryption
	adminKeyID    string // ID of the admin key used for encryption
	keyCache      *ttlCache[*Key]
	keyPairCache  *ttlCache[*KeyPair]
}

// NewPostgresKeyStore creates a new PostgreSQL key store
func NewPostgresKeyStore(db *sqlx.DB, keyEncryption *KeyEncryption, adminKeyID string, cacheTTL time.Duration) *PostgresKeyStore {
	return &PostgresKeyStore{
		db:            db,
		keyEncryption: keyEncryption,
		adminKeyID:    adminKeyID,
		keyCache:      newTTLCache[*Key](cacheTTL),
		keyPairCache:  newTTLCache[*KeyPair](cacheTTL),
	}
}

// Database models for key storage

type dbKeyPair struct {
	ID                  string        `db:"id"`
	KeyID               string        `db:"key_id"`
	KeyType             string        `db:"key_type"`
	KeySize             sql.NullInt64 `db:"key_size"`
	ProviderType        string        `db:"provider_type"`
	PublicKeyPEM        string        `db:"public_key_pem"`
	PublicKeyDER        []byte        `db:"public_key_der"`
	EncryptedPrivateKey []byte        `db:"encrypted_private_key"`
	EncryptionAlgorithm string        `db:"encryption_algorithm"`
	EncryptionKeyID     string        `db:"encryption_key_id"`
	Nonce               []byte        `db:"nonce"`
	Status              string        `db:"status"`
	CreatedAt           time.Time     `db:"created_at"`
	UpdatedAt           time.Time     `db:"updated_at"`
	ExpiresAt           sql.NullTime  `db:"expires_at"`
	LastRotated         sql.NullTime  `db:"last_rotated"`
	UsageCount          int64         `db:"usage_count"`
	MaxUsageCount       sql.NullInt64 `db:"max_usage_count"`
	LastUsedAt          sql.NullTime  `db:"last_used_at"`
	Metadata            string        `db:"metadata"` // JSON
	Tags                string        `db:"tags"`     // JSON
}

type dbClientKey struct {
	ID           string       `db:"id"`
	SubjectID    string       `db:"subject_id"`
	KeyID        string       `db:"key_id"`
	KeyType      string       `db:"key_type"`
	PublicKeyPEM string       `db:"public_key_pem"`
	PublicKeyDER []byte       `db:"public_key_der"`
	Status       string       `db:"status"`
	CreatedAt    time.Time    `db:"created_at"`
	ExpiresAt    sql.NullTime `db:"expires_at"`
	Metadata     string       `db:"metadata"` // JSON
}

// ===========================================================================================
// KEY OPERATIONS
// ===========================================================================================

// StoreKey stores a key in the database
func (s *PostgresKeyStore) StoreKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	// Keys without private key material are stored in client_keys table
	// This is for public keys of subjects/clients
	// For now, we'll just validate - full implementation would store in client_keys
	if cached := cloneKey(key); cached != nil {
		s.keyCache.Set(key.KeyId, cached)
	}
	return nil
}

// GetKey retrieves a key from the database
func (s *PostgresKeyStore) GetKey(ctx context.Context, keyID string) (*Key, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	if cached, ok := s.keyCache.Get(keyID); ok {
		return cloneKey(cached), nil
	}

	// Try to get from key_pairs table first
	query := `
		SELECT key_id, key_type, provider_type, public_key_pem, status, created_at, expires_at, metadata
		FROM key_pairs
		WHERE key_id = $1
	`

	var dbKey struct {
		KeyID        string       `db:"key_id"`
		KeyType      string       `db:"key_type"`
		ProviderType string       `db:"provider_type"`
		PublicKeyPEM string       `db:"public_key_pem"`
		Status       string       `db:"status"`
		CreatedAt    time.Time    `db:"created_at"`
		ExpiresAt    sql.NullTime `db:"expires_at"`
		Metadata     string       `db:"metadata"`
	}

	err := s.db.GetContext(ctx, &dbKey, query, keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key with ID %s not found", keyID)
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Convert to Key
	key := &Key{
		KeyId:        dbKey.KeyID,
		KeyType:      parseKeyType(dbKey.KeyType),
		ProviderType: parseProviderType(dbKey.ProviderType),
		PublicKeyPem: dbKey.PublicKeyPEM,
		Status:       parseKeyStatus(dbKey.Status),
		CreatedAt:    timestamppb.New(dbKey.CreatedAt),
	}

	if dbKey.ExpiresAt.Valid {
		key.ExpiresAt = timestamppb.New(dbKey.ExpiresAt.Time)
	}

	if dbKey.Metadata != "" {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
			key.Metadata = metadata
		}
	}

	hydrateKeyFromMetadata(key)
	s.keyCache.Set(keyID, cloneKey(key))
	return key, nil
}

// ListKeys returns all keys matching the filters
func (s *PostgresKeyStore) ListKeys(ctx context.Context, filters map[string]interface{}) ([]*Key, error) {
	query := `
		SELECT key_id, key_type, provider_type, public_key_pem, status, created_at, expires_at, metadata
		FROM key_pairs
		WHERE 1=1
	`
	args := []interface{}{}
	argCounter := 1

	// Apply filters
	if providerType, ok := filters["provider_type"].(KeyProviderType); ok {
		query += fmt.Sprintf(" AND provider_type = $%d", argCounter)
		args = append(args, providerType.String())
		argCounter++
	}

	if status, ok := filters["status"].(KeyStatus); ok {
		query += fmt.Sprintf(" AND status = $%d", argCounter)
		args = append(args, status.String())
		argCounter++
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		var dbKey struct {
			KeyID        string       `db:"key_id"`
			KeyType      string       `db:"key_type"`
			ProviderType string       `db:"provider_type"`
			PublicKeyPEM string       `db:"public_key_pem"`
			Status       string       `db:"status"`
			CreatedAt    time.Time    `db:"created_at"`
			ExpiresAt    sql.NullTime `db:"expires_at"`
			Metadata     string       `db:"metadata"`
		}

		err := rows.Scan(
			&dbKey.KeyID,
			&dbKey.KeyType,
			&dbKey.ProviderType,
			&dbKey.PublicKeyPEM,
			&dbKey.Status,
			&dbKey.CreatedAt,
			&dbKey.ExpiresAt,
			&dbKey.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key: %w", err)
		}

		key := &Key{
			KeyId:        dbKey.KeyID,
			KeyType:      parseKeyType(dbKey.KeyType),
			ProviderType: parseProviderType(dbKey.ProviderType),
			PublicKeyPem: dbKey.PublicKeyPEM,
			Status:       parseKeyStatus(dbKey.Status),
			CreatedAt:    timestamppb.New(dbKey.CreatedAt),
		}

		if dbKey.ExpiresAt.Valid {
			key.ExpiresAt = timestamppb.New(dbKey.ExpiresAt.Time)
		}

		if dbKey.Metadata != "" {
			var metadata map[string]string
			if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
				key.Metadata = metadata
			}
		}

		hydrateKeyFromMetadata(key)

		keys = append(keys, key)
	}

	return keys, nil
}

// DeleteKey deletes a key from the database
func (s *PostgresKeyStore) DeleteKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	query := `DELETE FROM key_pairs WHERE key_id = $1`
	result, err := s.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	s.keyCache.Delete(keyID)
	s.keyPairCache.Delete(keyID)
	return nil
}

// UpdateKey updates a key in the database
func (s *PostgresKeyStore) UpdateKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	metadataJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE key_pairs
		SET status = $1, metadata = $2, updated_at = NOW()
		WHERE key_id = $3
	`

	result, err := s.db.ExecContext(ctx, query, key.Status.String(), string(metadataJSON), key.KeyId)
	if err != nil {
		return fmt.Errorf("failed to update key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("key with ID %s not found", key.KeyId)
	}

	if cached := cloneKey(key); cached != nil {
		s.keyCache.Set(key.KeyId, cached)
	}
	return nil
}

// ===========================================================================================
// KEY PAIR OPERATIONS (WITH PRIVATE KEY MATERIAL)
// ===========================================================================================

// StoreKeyPair stores a complete key pair with encrypted private key material
func (s *PostgresKeyStore) StoreKeyPair(ctx context.Context, keyPair *KeyPair) error {
	if keyPair == nil {
		return fmt.Errorf("key pair cannot be nil")
	}
	if keyPair.KeyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	if keyPair.ExternallyManaged {
		loadedAt := time.Now().UTC()
		if keyPair.ExternalLoadedAt != nil {
			loadedAt = keyPair.ExternalLoadedAt.UTC()
		}
		desc := externalMetadataDescriptor{
			SourceName:       keyPair.ExternalSource,
			ManifestPath:     keyPair.ExternalManifestPath,
			LoaderType:       keyPair.ExternalLoaderType,
			PrivateKeySource: keyPair.PrivateKeySource,
			LoadedAt:         loadedAt,
		}
		keyPair.Metadata = applyExternalMetadata(keyPair.Metadata, desc)
		keyPair.ExternalLoadedAt = &loadedAt
	}

	// Encrypt the private key
	encryptedData, err := s.keyEncryption.EncryptPrivateKey(keyPair.PrivateKey, keyPair.KeyType)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Prepare metadata
	metadataJSON, err := json.Marshal(keyPair.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Convert expires at
	var expiresAt sql.NullTime
	if keyPair.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *keyPair.ExpiresAt, Valid: true}
	}

	// Convert last rotated
	var lastRotated sql.NullTime
	if keyPair.LastRotated != nil {
		lastRotated = sql.NullTime{Time: *keyPair.LastRotated, Valid: true}
	}

	// Convert max usage count
	var maxUsageCount sql.NullInt64
	if keyPair.MaxUsageCount > 0 {
		maxUsageCount = sql.NullInt64{Int64: keyPair.MaxUsageCount, Valid: true}
	}

	// Insert into database
	query := `
		INSERT INTO key_pairs (
			key_id, key_type, provider_type, public_key_pem,
			encrypted_private_key, encryption_algorithm, encryption_key_id, nonce,
			status, expires_at, last_rotated, usage_count, max_usage_count, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (key_id) DO UPDATE SET
			public_key_pem = EXCLUDED.public_key_pem,
			encrypted_private_key = EXCLUDED.encrypted_private_key,
			encryption_algorithm = EXCLUDED.encryption_algorithm,
			encryption_key_id = EXCLUDED.encryption_key_id,
			nonce = EXCLUDED.nonce,
			status = EXCLUDED.status,
			expires_at = EXCLUDED.expires_at,
			last_rotated = EXCLUDED.last_rotated,
			usage_count = EXCLUDED.usage_count,
			max_usage_count = EXCLUDED.max_usage_count,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
	`

	_, err = s.db.ExecContext(ctx, query,
		keyPair.KeyID,
		keyTypeToString(keyPair.KeyType),
		providerTypeToString(keyPair.ProviderType),
		keyPair.PublicKeyPEM,
		encryptedData.EncryptedData,
		encryptedData.Algorithm,
		s.adminKeyID,
		encryptedData.Nonce,
		"active",
		expiresAt,
		lastRotated,
		keyPair.UsageCount,
		maxUsageCount,
		string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to store key pair: %w", err)
	}

	// Audit log
	s.auditLog(ctx, keyPair.KeyID, "create", "system", "success", nil)

	metaKey := &Key{
		KeyId:        keyPair.KeyID,
		KeyType:      keyPair.KeyType,
		ProviderType: keyPair.ProviderType,
		PublicKeyPem: keyPair.PublicKeyPEM,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
	}
	s.keyCache.Set(keyPair.KeyID, metaKey)
	s.keyPairCache.Set(keyPair.KeyID, cloneKeyPair(keyPair))

	return nil
}

// GetKeyPair retrieves a complete key pair with decrypted private key material
func (s *PostgresKeyStore) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	if cached, ok := s.keyPairCache.Get(keyID); ok {
		return cloneKeyPair(cached), nil
	}

	query := `
		SELECT key_id, key_type, provider_type, public_key_pem,
			   encrypted_private_key, encryption_algorithm, nonce,
			   status, created_at, expires_at, last_rotated, usage_count, max_usage_count, metadata
		FROM key_pairs
		WHERE key_id = $1
	`

	var dbKey struct {
		KeyID               string        `db:"key_id"`
		KeyType             string        `db:"key_type"`
		ProviderType        string        `db:"provider_type"`
		PublicKeyPEM        string        `db:"public_key_pem"`
		EncryptedPrivateKey []byte        `db:"encrypted_private_key"`
		EncryptionAlgorithm string        `db:"encryption_algorithm"`
		Nonce               []byte        `db:"nonce"`
		Status              string        `db:"status"`
		CreatedAt           time.Time     `db:"created_at"`
		ExpiresAt           sql.NullTime  `db:"expires_at"`
		LastRotated         sql.NullTime  `db:"last_rotated"`
		UsageCount          int64         `db:"usage_count"`
		MaxUsageCount       sql.NullInt64 `db:"max_usage_count"`
		Metadata            string        `db:"metadata"`
	}

	err := s.db.GetContext(ctx, &dbKey, query, keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key pair with ID %s not found", keyID)
		}
		return nil, fmt.Errorf("failed to get key pair: %w", err)
	}

	// Decrypt the private key
	keyType := parseKeyType(dbKey.KeyType)
	encryptedData := &EncryptedKeyData{
		EncryptedData: dbKey.EncryptedPrivateKey,
		Nonce:         dbKey.Nonce,
		Algorithm:     dbKey.EncryptionAlgorithm,
	}

	privateKey, err := s.keyEncryption.DecryptPrivateKey(encryptedData, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Parse public key from PEM
	publicKey, err := parsePublicKeyFromPEM(dbKey.PublicKeyPEM, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Build KeyPair
	keyPair := &KeyPair{
		KeyID:        dbKey.KeyID,
		KeyType:      keyType,
		ProviderType: parseProviderType(dbKey.ProviderType),
		PublicKey:    publicKey,
		PrivateKey:   privateKey,
		PublicKeyPEM: dbKey.PublicKeyPEM,
		CreatedAt:    dbKey.CreatedAt,
		UsageCount:   dbKey.UsageCount,
	}

	if dbKey.ExpiresAt.Valid {
		keyPair.ExpiresAt = &dbKey.ExpiresAt.Time
	}

	if dbKey.LastRotated.Valid {
		keyPair.LastRotated = &dbKey.LastRotated.Time
	}

	if dbKey.MaxUsageCount.Valid {
		keyPair.MaxUsageCount = dbKey.MaxUsageCount.Int64
	}

	if dbKey.Metadata != "" {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
			keyPair.Metadata = metadata
		}
	}

	hydrateKeyPairFromMetadata(keyPair)
	s.keyPairCache.Set(keyID, cloneKeyPair(keyPair))

	// Audit log
	s.auditLog(ctx, keyID, "read", "system", "success", nil)

	return keyPair, nil
}

// DeleteKeyPair deletes a key pair from the database
func (s *PostgresKeyStore) DeleteKeyPair(ctx context.Context, keyID string) error {
	if err := s.DeleteKey(ctx, keyID); err != nil {
		return err
	}
	s.keyPairCache.Delete(keyID)
	return nil
}

// ===========================================================================================
// HELPER FUNCTIONS
// ===========================================================================================

func (s *PostgresKeyStore) auditLog(ctx context.Context, keyID, operation, actor, result string, metadata map[string]interface{}) {
	metadataJSON, _ := json.Marshal(metadata)

	query := `
		INSERT INTO key_audit_logs (key_id, operation, actor, result, metadata)
		VALUES ($1, $2, $3, $4, $5)
	`

	s.db.ExecContext(ctx, query, keyID, operation, actor, result, string(metadataJSON))
}

func parseKeyType(s string) KeyType {
	switch s {
	case "RSA2048":
		return KeyType_KEY_TYPE_RSA_2048
	case "RSA3072":
		return KeyType_KEY_TYPE_RSA_3072
	case "RSA4096":
		return KeyType_KEY_TYPE_RSA_4096
	case "ECC256":
		return KeyType_KEY_TYPE_ECC_P256
	case "ECC384":
		return KeyType_KEY_TYPE_ECC_P384
	case "ECC521":
		return KeyType_KEY_TYPE_ECC_P521
	case "Kyber512":
		return KeyType_KEY_TYPE_KYBER_512
	case "Kyber768":
		return KeyType_KEY_TYPE_KYBER_768
	case "Kyber1024":
		return KeyType_KEY_TYPE_KYBER_1024
	default:
		return KeyType_KEY_TYPE_RSA_2048
	}
}

func keyTypeToString(kt KeyType) string {
	switch kt {
	case KeyType_KEY_TYPE_RSA_2048:
		return "RSA2048"
	case KeyType_KEY_TYPE_RSA_3072:
		return "RSA3072"
	case KeyType_KEY_TYPE_RSA_4096:
		return "RSA4096"
	case KeyType_KEY_TYPE_ECC_P256:
		return "ECC256"
	case KeyType_KEY_TYPE_ECC_P384:
		return "ECC384"
	case KeyType_KEY_TYPE_ECC_P521:
		return "ECC521"
	case KeyType_KEY_TYPE_KYBER_512:
		return "Kyber512"
	case KeyType_KEY_TYPE_KYBER_768:
		return "Kyber768"
	case KeyType_KEY_TYPE_KYBER_1024:
		return "Kyber1024"
	default:
		return "RSA2048"
	}
}

func parseProviderType(s string) KeyProviderType {
	switch s {
	case "software":
		return KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE
	case "hsm":
		return KeyProviderType_KEY_PROVIDER_TYPE_HSM
	case "smartcard":
		return KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD
	default:
		return KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE
	}
}

func providerTypeToString(pt KeyProviderType) string {
	switch pt {
	case KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE:
		return "software"
	case KeyProviderType_KEY_PROVIDER_TYPE_HSM:
		return "hsm"
	case KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD:
		return "smartcard"
	default:
		return "software"
	}
}

func parseKeyStatus(s string) KeyStatus {
	switch s {
	case "active":
		return KeyStatus_KEY_STATUS_ACTIVE
	case "inactive":
		return KeyStatus_KEY_STATUS_INACTIVE
	case "deprecated":
		return KeyStatus_KEY_STATUS_DEPRECATED
	case "revoked":
		return KeyStatus_KEY_STATUS_REVOKED
	case "compromised":
		return KeyStatus_KEY_STATUS_COMPROMISED
	default:
		return KeyStatus_KEY_STATUS_ACTIVE
	}
}

// parsePublicKeyFromPEM is a placeholder - real implementation would parse PEM
func parsePublicKeyFromPEM(pemData string, keyType KeyType) (any, error) {
	// This would normally parse the PEM data to extract the public key
	// For now, we return nil since the public key is mainly used for display
	return nil, nil
}

// ===========================================================================================
// CLIENT KEY STORE (PostgreSQL Implementation)
// ===========================================================================================

// PostgresClientKeyStore provides a PostgreSQL-backed implementation of ClientKeyStore
type PostgresClientKeyStore struct {
	db                *sqlx.DB
	integrityMgr      *KeyIntegrityManager
	keyCache          *ttlCache[*Key]
	activeClientCache *ttlCache[*Key]
}

// NewPostgresClientKeyStore creates a new PostgreSQL client key store
func NewPostgresClientKeyStore(db *sqlx.DB, integrityMgr *KeyIntegrityManager, cacheTTL time.Duration) *PostgresClientKeyStore {
	return &PostgresClientKeyStore{
		db:                db,
		integrityMgr:      integrityMgr,
		keyCache:          newTTLCache[*Key](cacheTTL),
		activeClientCache: newTTLCache[*Key](cacheTTL),
	}
}

// RegisterKey registers a new client public key
func (s *PostgresClientKeyStore) RegisterKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}
	if key.ClientId == "" {
		return fmt.Errorf("client ID cannot be empty")
	}

	// Check if an identical key already exists for this subject
	checkQuery := `
		SELECT key_id, status
		FROM client_keys
		WHERE subject_id = $1 AND public_key_pem = $2
		LIMIT 1
	`
	var existingKey struct {
		KeyID  string `db:"key_id"`
		Status string `db:"status"`
	}
	err := s.db.GetContext(ctx, &existingKey, checkQuery, key.ClientId, key.PublicKeyPem)

	// If an identical key already exists, update its key_id in the input and update the record
	if err == nil {
		// Identical key found - update it instead of creating a duplicate
		key.KeyId = existingKey.KeyID

		// Prepare metadata
		metadataJSON, err := json.Marshal(key.Metadata)
		if err != nil {
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}

		// Convert expires at
		var expiresAt sql.NullTime
		if key.ExpiresAt != nil {
			expiresAt = sql.NullTime{Time: key.ExpiresAt.AsTime(), Valid: true}
		}

		// Update the existing record
		updateQuery := `
			UPDATE client_keys
			SET status = $1, expires_at = $2, metadata = $3, key_integrity_hash = $4
			WHERE key_id = $5
		`
		_, err = s.db.ExecContext(ctx, updateQuery, "active", expiresAt, string(metadataJSON), key.KeyIntegrityHash, existingKey.KeyID)
		if err != nil {
			return fmt.Errorf("failed to update existing client key: %w", err)
		}
		if cached := cloneKey(key); cached != nil {
			s.keyCache.Set(key.KeyId, cached)
			s.activeClientCache.Set(key.ClientId, cloneKey(cached))
		}
		return nil
	} else if err != sql.ErrNoRows {
		// An actual error occurred (not just "no rows found")
		return fmt.Errorf("failed to check for existing key: %w", err)
	}

	// No identical key exists - proceed with insert
	// Prepare metadata
	metadataJSON, err := json.Marshal(key.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Convert expires at
	var expiresAt sql.NullTime
	if key.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: key.ExpiresAt.AsTime(), Valid: true}
	}

	// Insert into database
	query := `
		INSERT INTO client_keys (
			subject_id, key_id, key_type, public_key_pem, key_integrity_hash, status, expires_at, metadata
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = s.db.ExecContext(ctx, query,
		key.ClientId,
		key.KeyId,
		keyTypeToString(key.KeyType),
		key.PublicKeyPem,
		key.KeyIntegrityHash,
		"active",
		expiresAt,
		string(metadataJSON),
	)

	if err != nil {
		return fmt.Errorf("failed to register client key: %w", err)
	}

	if cached := cloneKey(key); cached != nil {
		s.keyCache.Set(key.KeyId, cached)
		s.activeClientCache.Set(key.ClientId, cloneKey(cached))
	}
	return nil
}

// GetKey retrieves a client public key by key ID
func (s *PostgresClientKeyStore) GetKey(ctx context.Context, keyID string) (*Key, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	if cached, ok := s.keyCache.Get(keyID); ok {
		return cloneKey(cached), nil
	}

	query := `
		SELECT subject_id, key_id, key_type, public_key_pem, key_integrity_hash, status, created_at, expires_at, metadata
		FROM client_keys
		WHERE key_id = $1
	`

	var dbKey struct {
		SubjectID        string       `db:"subject_id"`
		KeyID            string       `db:"key_id"`
		KeyType          string       `db:"key_type"`
		PublicKeyPEM     string       `db:"public_key_pem"`
		KeyIntegrityHash string       `db:"key_integrity_hash"`
		Status           string       `db:"status"`
		CreatedAt        time.Time    `db:"created_at"`
		ExpiresAt        sql.NullTime `db:"expires_at"`
		Metadata         string       `db:"metadata"`
	}

	err := s.db.GetContext(ctx, &dbKey, query, keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("client key with ID %s not found", keyID)
		}
		return nil, fmt.Errorf("failed to get client key: %w", err)
	}

	// Convert to Key
	key := &Key{
		ClientId:         dbKey.SubjectID,
		KeyId:            dbKey.KeyID,
		KeyType:          parseKeyType(dbKey.KeyType),
		PublicKeyPem:     dbKey.PublicKeyPEM,
		KeyIntegrityHash: dbKey.KeyIntegrityHash,
		Status:           parseKeyStatus(dbKey.Status),
		CreatedAt:        timestamppb.New(dbKey.CreatedAt),
	}

	if dbKey.ExpiresAt.Valid {
		key.ExpiresAt = timestamppb.New(dbKey.ExpiresAt.Time)
	}

	if dbKey.Metadata != "" {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
			key.Metadata = metadata
		}
	}

	if cached := cloneKey(key); cached != nil {
		s.keyCache.Set(key.KeyId, cached)
		if key.Status == KeyStatus_KEY_STATUS_ACTIVE {
			s.activeClientCache.Set(key.ClientId, cloneKey(cached))
		}
	}

	return key, nil
}

// GetActiveKeyForClient retrieves the active key for a client
func (s *PostgresClientKeyStore) GetActiveKeyForClient(ctx context.Context, clientID string) (*Key, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}

	if cached, ok := s.activeClientCache.Get(clientID); ok {
		return cloneKey(cached), nil
	}

	query := `
		SELECT subject_id, key_id, key_type, public_key_pem, key_integrity_hash, status, created_at, expires_at, metadata
		FROM client_keys
		WHERE subject_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`

	var dbKey struct {
		SubjectID        string       `db:"subject_id"`
		KeyID            string       `db:"key_id"`
		KeyType          string       `db:"key_type"`
		PublicKeyPEM     string       `db:"public_key_pem"`
		KeyIntegrityHash string       `db:"key_integrity_hash"`
		Status           string       `db:"status"`
		CreatedAt        time.Time    `db:"created_at"`
		ExpiresAt        sql.NullTime `db:"expires_at"`
		Metadata         string       `db:"metadata"`
	}

	err := s.db.GetContext(ctx, &dbKey, query, clientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no active key found for client %s", clientID)
		}
		return nil, fmt.Errorf("failed to get active client key: %w", err)
	}

	// Convert to Key
	key := &Key{
		ClientId:         dbKey.SubjectID,
		KeyId:            dbKey.KeyID,
		KeyType:          parseKeyType(dbKey.KeyType),
		PublicKeyPem:     dbKey.PublicKeyPEM,
		KeyIntegrityHash: dbKey.KeyIntegrityHash,
		Status:           parseKeyStatus(dbKey.Status),
		CreatedAt:        timestamppb.New(dbKey.CreatedAt),
	}

	if dbKey.ExpiresAt.Valid {
		key.ExpiresAt = timestamppb.New(dbKey.ExpiresAt.Time)
	}

	if dbKey.Metadata != "" {
		var metadata map[string]string
		if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
			key.Metadata = metadata
		}
	}

	if cached := cloneKey(key); cached != nil {
		s.activeClientCache.Set(clientID, cached)
		s.keyCache.Set(key.KeyId, cloneKey(cached))
	}

	return key, nil
}

// ListKeysForClient lists all keys for a specific client
func (s *PostgresClientKeyStore) ListKeysForClient(ctx context.Context, clientID string, includeRevoked bool) ([]*Key, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}

	query := `
		SELECT subject_id, key_id, key_type, public_key_pem, key_integrity_hash, status, created_at, expires_at, metadata
		FROM client_keys
		WHERE subject_id = $1
	`

	if !includeRevoked {
		query += " AND status != 'revoked'"
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to list client keys: %w", err)
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		var dbKey struct {
			SubjectID        string       `db:"subject_id"`
			KeyID            string       `db:"key_id"`
			KeyType          string       `db:"key_type"`
			PublicKeyPEM     string       `db:"public_key_pem"`
			KeyIntegrityHash string       `db:"key_integrity_hash"`
			Status           string       `db:"status"`
			CreatedAt        time.Time    `db:"created_at"`
			ExpiresAt        sql.NullTime `db:"expires_at"`
			Metadata         string       `db:"metadata"`
		}

		err := rows.Scan(
			&dbKey.SubjectID,
			&dbKey.KeyID,
			&dbKey.KeyType,
			&dbKey.PublicKeyPEM,
			&dbKey.KeyIntegrityHash,
			&dbKey.Status,
			&dbKey.CreatedAt,
			&dbKey.ExpiresAt,
			&dbKey.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan client key: %w", err)
		}

		key := &Key{
			ClientId:         dbKey.SubjectID,
			KeyId:            dbKey.KeyID,
			KeyType:          parseKeyType(dbKey.KeyType),
			PublicKeyPem:     dbKey.PublicKeyPEM,
			KeyIntegrityHash: dbKey.KeyIntegrityHash,
			Status:           parseKeyStatus(dbKey.Status),
			CreatedAt:        timestamppb.New(dbKey.CreatedAt),
		}

		if dbKey.ExpiresAt.Valid {
			key.ExpiresAt = timestamppb.New(dbKey.ExpiresAt.Time)
		}

		if dbKey.Metadata != "" {
			var metadata map[string]string
			if err := json.Unmarshal([]byte(dbKey.Metadata), &metadata); err == nil {
				key.Metadata = metadata
			}
		}

		keys = append(keys, key)
	}

	return keys, nil
}

// RevokeKey revokes a client public key
func (s *PostgresClientKeyStore) RevokeKey(ctx context.Context, keyID, reason string) error {
	if keyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	query := `
		UPDATE client_keys
		SET status = 'revoked'
		WHERE key_id = $1
		RETURNING subject_id
	`

	var subjectID string
	err := s.db.QueryRowContext(ctx, query, keyID).Scan(&subjectID)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("client key with ID %s not found", keyID)
		}
		return fmt.Errorf("failed to revoke client key: %w", err)
	}

	s.keyCache.Delete(keyID)
	if subjectID != "" {
		s.activeClientCache.Delete(subjectID)
	}

	return nil
}

// ListClients lists all subjects that have registered keys
func (s *PostgresClientKeyStore) ListClients(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT subject_id
		FROM client_keys
		ORDER BY subject_id
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list clients: %w", err)
	}
	defer rows.Close()

	var clients []string
	for rows.Next() {
		var clientID string
		if err := rows.Scan(&clientID); err != nil {
			return nil, fmt.Errorf("failed to scan client ID: %w", err)
		}
		clients = append(clients, clientID)
	}

	return clients, nil
}
