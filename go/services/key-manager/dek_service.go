package key_manager

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
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// DEKUnwrappingService handles Data Encryption Key unwrapping
// Note: ABAC verification is performed by the Key Access Service before calling this service
type DEKUnwrappingService struct {
	mu              sync.RWMutex
	keyStore        KeyStore
	providerFactory ProviderFactory
	clientKeyStore  ClientKeyStore
	auditLogger     AuditLogger
}

// AuditLogger logs security and access events
type AuditLogger interface {
	LogDEKAccess(ctx context.Context, event DEKAccessEvent)
	LogSecurityEvent(ctx context.Context, event SecurityEvent)
}

// DEKAccessEvent represents a DEK access event for auditing
type DEKAccessEvent struct {
	Timestamp       int64
	Subject         string
	Resource        string
	Action          string
	KeyID           string
	AccessGranted   bool
	Reason          string
	AppliedRules    []string
	ClientIP        string
	UserAgent       string
	RequestMetadata map[string]string
}

// DefaultAuditLogger provides a default implementation of AuditLogger
type DefaultAuditLogger struct{}

// NewDEKUnwrappingService creates a new DEK unwrapping service
// The clientKeyStore must be provided - use ztdf.NewKASClientKeyStore() to integrate with Key Access Service
func NewDEKUnwrappingService(
	keyStore KeyStore,
	providerFactory ProviderFactory,
	clientKeyStore ClientKeyStore,
) *DEKUnwrappingService {
	return &DEKUnwrappingService{
		keyStore:        keyStore,
		providerFactory: providerFactory,
		clientKeyStore:  clientKeyStore,
		auditLogger:     &DefaultAuditLogger{},
	}
}

// UnwrapDEK unwraps a Data Encryption Key
// Note: ABAC verification is assumed to be already performed by the Key Access Service
func (d *DEKUnwrappingService) UnwrapDEK(ctx context.Context, req *UnwrapDEKRequest) (*UnwrapDEKResponse, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	logger.Info("DEK unwrap request - Subject: %s, Resource: %s, KeyID: %s",
		req.Subject, req.Resource, req.KeyId)

	// Step 1: Validate input
	if err := d.validateUnwrapRequest(req); err != nil {
		return d.createDeniedResponse(req, fmt.Sprintf("Invalid request: %v", err)), nil
	}

	// Step 2: Get the service key for decryption
	serviceKey, err := d.keyStore.GetKey(ctx, req.KeyId)
	if err != nil {
		reason := fmt.Sprintf("Service key not found: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	// Step 3: Get the appropriate key provider (use cached instance)
	provider, err := d.providerFactory.GetProvider(serviceKey.ProviderType)
	if err != nil {
		reason := fmt.Sprintf("Failed to create key provider: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	// Step 4: Decrypt the DEK using the service key
	dekBytes, err := provider.Decrypt(ctx, req.KeyId, req.EncryptedDek)
	if err != nil {
		reason := fmt.Sprintf("Failed to decrypt DEK: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	// Step 5: Get the subject's public key for re-encryption
	if d.clientKeyStore == nil {
		reason := "ClientKeyStore not configured - cannot unwrap DEK"
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	subjectKey, err := d.clientKeyStore.GetKey(ctx, req.ClientKeyId)
	if err != nil {
		reason := fmt.Sprintf("Subject public key not found: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	// Parse the PEM-encoded public key from the Key object
	block, _ := pem.Decode([]byte(subjectKey.PublicKeyPem))
	if block == nil {
		reason := "Failed to decode subject public key PEM"
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	subjectPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		reason := fmt.Sprintf("Failed to parse subject public key: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	logger.Info("Parsed subject public key type: %T", subjectPublicKey)

	// Step 6: Encrypt the DEK with the subject's public key
	encryptedDEKForSubject, subjectKeyID, err := d.encryptDEKForSubject(subjectPublicKey, dekBytes, req.Subject)
	if err != nil {
		reason := fmt.Sprintf("Failed to encrypt DEK for subject: %v", err)
		d.logDEKAccess(ctx, req, false, reason, nil)
		return d.createDeniedResponse(req, reason), nil
	}

	// Step 7: Log successful access
	d.logDEKAccess(ctx, req, true, "DEK unwrapped successfully", nil)

	// Step 8: Create successful response
	response := &UnwrapDEKResponse{
		EncryptedDekForSubject: encryptedDEKForSubject,
		SubjectKeyId:           subjectKeyID,
		AccessGranted:          true,
		AccessReason:           "Access granted by Key Access Service",
		AppliedRules:           []string{},
		Timestamp:              timestamppb.Now(),
	}

	logger.Info("DEK successfully unwrapped for subject %s", req.Subject)
	return response, nil
}

// validateUnwrapRequest validates the unwrap request
func (d *DEKUnwrappingService) validateUnwrapRequest(req *UnwrapDEKRequest) error {
	if req.Subject == "" {
		return fmt.Errorf("subject is required")
	}

	if req.Resource == "" {
		return fmt.Errorf("resource is required")
	}

	if req.KeyId == "" {
		return fmt.Errorf("key ID is required")
	}

	if len(req.EncryptedDek) == 0 {
		return fmt.Errorf("encrypted DEK is required")
	}

	if req.Action == "" {
		req.Action = "unwrap_dek" // Default action
	}

	return nil
}

// encryptDEKForSubject encrypts the DEK using the subject's public key
func (d *DEKUnwrappingService) encryptDEKForSubject(subjectPublicKey crypto.PublicKey, dekBytes []byte, subject string) ([]byte, string, error) {
	switch pubKey := subjectPublicKey.(type) {
	case *rsa.PublicKey:
		encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dekBytes, nil)
		if err != nil {
			return nil, "", fmt.Errorf("RSA encryption failed: %w", err)
		}
		return encryptedDEK, fmt.Sprintf("subject-%s-rsa", subject), nil

	case *ecdsa.PublicKey:
		// For ECC, use ECIES (Elliptic Curve Integrated Encryption Scheme)
		encryptedDEK, err := d.encryptWithECIES(pubKey, dekBytes)
		if err != nil {
			return nil, "", fmt.Errorf("ECDSA encryption failed: %w", err)
		}
		return encryptedDEK, fmt.Sprintf("subject-%s-ecc", subject), nil

	default:
		return nil, "", fmt.Errorf("unsupported public key type for subject %s %v", subject, pubKey)
	}
}

// encryptWithECIES encrypts data using ECIES (Elliptic Curve Integrated Encryption Scheme)
func (d *DEKUnwrappingService) encryptWithECIES(publicKey *ecdsa.PublicKey, plaintext []byte) ([]byte, error) {
	// Import crypto/aes and crypto/cipher at the top of the file
	// Generate ephemeral key pair
	ephemeralKey, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Derive shared secret using ECDH
	sharedX, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralKey.D.Bytes())

	// Derive encryption key using HKDF
	// Import golang.org/x/crypto/hkdf at the top of the file
	kdf := hkdf.New(sha256.New, sharedX.Bytes(), nil, []byte("key-manager-dek-wrap"))
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Return: ephemeral public key || ciphertext
	// Ephemeral public key is 64 bytes (32 bytes X + 32 bytes Y for P-256)
	ephemeralPubKeyX := ephemeralKey.PublicKey.X.FillBytes(make([]byte, 32))
	ephemeralPubKeyY := ephemeralKey.PublicKey.Y.FillBytes(make([]byte, 32))
	ephemeralPubKey := append(ephemeralPubKeyX, ephemeralPubKeyY...)

	return append(ephemeralPubKey, ciphertext...), nil
}

// createDeniedResponse creates a denied response
func (d *DEKUnwrappingService) createDeniedResponse(req *UnwrapDEKRequest, reason string) *UnwrapDEKResponse {
	return &UnwrapDEKResponse{
		EncryptedDekForSubject: nil,
		SubjectKeyId:           "",
		AccessGranted:          false,
		AccessReason:           reason,
		AppliedRules:           []string{},
		Timestamp:              timestamppb.Now(),
	}
}

// logDEKAccess logs DEK access events
func (d *DEKUnwrappingService) logDEKAccess(ctx context.Context, req *UnwrapDEKRequest, granted bool, reason string, appliedRules []string) {
	event := DEKAccessEvent{
		Timestamp:       time.Now().Unix(),
		Subject:         req.Subject,
		Resource:        req.Resource,
		Action:          req.Action,
		KeyID:           req.KeyId,
		AccessGranted:   granted,
		Reason:          reason,
		AppliedRules:    appliedRules,
		ClientIP:        req.Context["client_ip"],
		UserAgent:       req.Context["user_agent"],
		RequestMetadata: req.Context,
	}

	d.auditLogger.LogDEKAccess(ctx, event)
}

// publicKeyToPEM converts a crypto.PublicKey to PEM format and determines the key type
func publicKeyToPEM(publicKey crypto.PublicKey) (string, KeyType, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		// Determine RSA key size
		keySize := key.N.BitLen()
		var keyType KeyType
		switch keySize {
		case 2048:
			keyType = KeyType_KEY_TYPE_RSA_2048
		case 3072:
			keyType = KeyType_KEY_TYPE_RSA_3072
		case 4096:
			keyType = KeyType_KEY_TYPE_RSA_4096
		default:
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported RSA key size: %d", keySize)
		}

		// Marshal to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal RSA public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		return string(pemBlock), keyType, nil

	case *ecdsa.PublicKey:
		// Determine ECC curve
		var keyType KeyType
		switch key.Curve.Params().Name {
		case "P-256":
			keyType = KeyType_KEY_TYPE_ECC_P256
		case "P-384":
			keyType = KeyType_KEY_TYPE_ECC_P384
		case "P-521":
			keyType = KeyType_KEY_TYPE_ECC_P521
		default:
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported ECC curve: %s", key.Curve.Params().Name)
		}

		// Marshal to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal ECC public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		return string(pemBlock), keyType, nil

	case *kyber512.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-512 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-512 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_512, nil

	case *kyber768.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-768 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-768 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_768, nil

	case *kyber1024.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-1024 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-1024 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_1024, nil

	default:
		return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// SetClientKeyStore sets a custom subject key store
func (d *DEKUnwrappingService) SetClientKeyStore(store ClientKeyStore) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.clientKeyStore = store
}

// SetAuditLogger sets a custom audit logger
func (d *DEKUnwrappingService) SetAuditLogger(logger AuditLogger) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.auditLogger = logger
}

// RegisterClientPublicKey registers a public key for a subject
func (d *DEKUnwrappingService) RegisterClientPublicKey(ctx context.Context, subject string, publicKeyPEM string) error {
	// Parse PEM
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	// Parse public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Convert the crypto.PublicKey to PEM format
	publicKeyPEM, keyType, err := publicKeyToPEM(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	// Generate a unique key ID
	keyID := fmt.Sprintf("client-key-%s-%d", subject, time.Now().UnixNano())

	// Create a Key record
	key := &Key{
		KeyId:        keyID,
		PublicKeyPem: publicKeyPEM,
		KeyType:      keyType,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		Metadata:     make(map[string]string),
	}

	// Store the public key
	err = d.clientKeyStore.RegisterKey(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to store subject public key: %w", err)
	}

	logger.Info("Registered public key for subject: %s", subject)
	return nil
}

// LogDEKAccess implementation
func (l *DefaultAuditLogger) LogDEKAccess(ctx context.Context, event DEKAccessEvent) {
	status := "DENIED"
	if event.AccessGranted {
		status = "GRANTED"
	}

	logger.Info("DEK_ACCESS [%s] Subject=%s Resource=%s KeyID=%s Reason=%s Rules=%v IP=%s",
		status, event.Subject, event.Resource, event.KeyID, event.Reason, event.AppliedRules, event.ClientIP)
}

func (l *DefaultAuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) {
	logger.Info("SECURITY_EVENT Type=%s KeyID=%s Subject=%s Severity=%s Description=%s",
		event.EventType, event.KeyID, event.Subject, event.Severity, event.Description)
}
