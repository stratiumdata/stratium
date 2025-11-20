package key_manager

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// Helper functions to check key type families
func isRSAKeyType(kt KeyType) bool {
	return kt == KeyType_KEY_TYPE_RSA_2048 ||
		kt == KeyType_KEY_TYPE_RSA_3072 ||
		kt == KeyType_KEY_TYPE_RSA_4096
}

func isECCKeyType(kt KeyType) bool {
	return kt == KeyType_KEY_TYPE_ECC_P256 ||
		kt == KeyType_KEY_TYPE_ECC_P384 ||
		kt == KeyType_KEY_TYPE_ECC_P521
}

func isKyberKeyType(kt KeyType) bool {
	return kt == KeyType_KEY_TYPE_KYBER_512 ||
		kt == KeyType_KEY_TYPE_KYBER_768 ||
		kt == KeyType_KEY_TYPE_KYBER_1024
}

// KeyEncryption provides utilities for encrypting and decrypting private key material
// using AES-256-GCM with the admin key
type KeyEncryption struct {
	adminKey []byte
}

// NewKeyEncryption creates a new key encryption utility
func NewKeyEncryption(adminKey []byte) (*KeyEncryption, error) {
	if len(adminKey) != 32 {
		return nil, fmt.Errorf("admin key must be 32 bytes (256 bits), got %d bytes", len(adminKey))
	}

	return &KeyEncryption{
		adminKey: adminKey,
	}, nil
}

// EncryptedKeyData holds encrypted private key material along with encryption metadata
type EncryptedKeyData struct {
	EncryptedData []byte
	Nonce         []byte
	Algorithm     string // e.g., "AES-256-GCM"
}

// EncryptPrivateKey encrypts private key material using AES-256-GCM
func (ke *KeyEncryption) EncryptPrivateKey(privateKey any, keyType KeyType) (*EncryptedKeyData, error) {
	// Serialize the private key to bytes
	keyBytes, err := serializePrivateKey(privateKey, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize private key: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(ke.adminKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the key material
	ciphertext := gcm.Seal(nil, nonce, keyBytes, nil)

	return &EncryptedKeyData{
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Algorithm:     "AES-256-GCM",
	}, nil
}

// DecryptPrivateKey decrypts private key material using AES-256-GCM
func (ke *KeyEncryption) DecryptPrivateKey(encryptedData *EncryptedKeyData, keyType KeyType) (any, error) {
	if encryptedData.Algorithm != "AES-256-GCM" {
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", encryptedData.Algorithm)
	}

	// Create AES cipher
	block, err := aes.NewCipher(ke.adminKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the key material
	keyBytes, err := gcm.Open(nil, encryptedData.Nonce, encryptedData.EncryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key material: %w", err)
	}

	// Deserialize the private key
	privateKey, err := deserializePrivateKey(keyBytes, keyType)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %w", err)
	}

	return privateKey, nil
}

// serializePrivateKey converts a private key to bytes based on its type
func serializePrivateKey(privateKey any, keyType KeyType) ([]byte, error) {
	if isRSAKeyType(keyType) {
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		return x509.MarshalPKCS8PrivateKey(rsaKey)
	}

	if isECCKeyType(keyType) {
		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", privateKey)
		}
		return x509.MarshalPKCS8PrivateKey(ecKey)
	}

	if isKyberKeyType(keyType) {
		// Kyber keys implement kem.PrivateKey interface
		// We need to serialize the private key bytes
		switch k := privateKey.(type) {
		case *kyber512.PrivateKey:
			keyBytes := make([]byte, kyber512.Scheme().PrivateKeySize())
			k.Pack(keyBytes)
			return keyBytes, nil
		case *kyber768.PrivateKey:
			keyBytes := make([]byte, kyber768.Scheme().PrivateKeySize())
			k.Pack(keyBytes)
			return keyBytes, nil
		case *kyber1024.PrivateKey:
			keyBytes := make([]byte, kyber1024.Scheme().PrivateKeySize())
			k.Pack(keyBytes)
			return keyBytes, nil
		default:
			// Fallback for generic KEM private key
			if kemKey, ok := privateKey.(kem.PrivateKey); ok {
				// Marshal as bytes (implementation-specific)
				keyBytes, err := kemKey.MarshalBinary()
				if err != nil {
					return nil, fmt.Errorf("failed to marshal KEM key: %w", err)
				}
				return keyBytes, nil
			}
			return nil, fmt.Errorf("unsupported Kyber key type: %T", privateKey)
		}
	}

	return nil, fmt.Errorf("unsupported key type for serialization: %s", keyType)
}

// deserializePrivateKey converts bytes back to a private key based on type
func deserializePrivateKey(keyBytes []byte, keyType KeyType) (any, error) {
	if isRSAKeyType(keyType) {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *rsa.PrivateKey, got %T", key)
		}
		return rsaKey, nil
	}

	if isECCKeyType(keyType) {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECC private key: %w", err)
		}
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected *ecdsa.PrivateKey, got %T", key)
		}
		return ecKey, nil
	}

	if isKyberKeyType(keyType) {
		// For Kyber, we need to determine the variant based on private key size
		// This is a limitation - we should store the variant in metadata
		// For now, we'll try each variant
		var privateKey kem.PrivateKey

		// Try Kyber512
		if len(keyBytes) == kyber512.Scheme().PrivateKeySize() {
			privateKey = new(kyber512.PrivateKey)
			privateKey.(*kyber512.PrivateKey).Unpack(keyBytes)
			return privateKey, nil
		}

		// Try Kyber768
		if len(keyBytes) == kyber768.Scheme().PrivateKeySize() {
			privateKey = new(kyber768.PrivateKey)
			privateKey.(*kyber768.PrivateKey).Unpack(keyBytes)
			return privateKey, nil
		}

		// Try Kyber1024
		if len(keyBytes) == kyber1024.Scheme().PrivateKeySize() {
			privateKey = new(kyber1024.PrivateKey)
			privateKey.(*kyber1024.PrivateKey).Unpack(keyBytes)
			return privateKey, nil
		}

		return nil, fmt.Errorf("failed to deserialize Kyber key: unsupported private key size %d or invalid key", len(keyBytes))
	}

	return nil, fmt.Errorf("unsupported key type for deserialization: %s", keyType)
}

// EncryptPrivateKeyPEM encrypts a PEM-encoded private key
func (ke *KeyEncryption) EncryptPrivateKeyPEM(pemData string) (*EncryptedKeyData, error) {
	// Create AES cipher
	block, err := aes.NewCipher(ke.adminKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the PEM data
	ciphertext := gcm.Seal(nil, nonce, []byte(pemData), nil)

	return &EncryptedKeyData{
		EncryptedData: ciphertext,
		Nonce:         nonce,
		Algorithm:     "AES-256-GCM",
	}, nil
}

// DecryptPrivateKeyPEM decrypts a PEM-encoded private key
func (ke *KeyEncryption) DecryptPrivateKeyPEM(encryptedData *EncryptedKeyData) (string, error) {
	if encryptedData.Algorithm != "AES-256-GCM" {
		return "", fmt.Errorf("unsupported encryption algorithm: %s", encryptedData.Algorithm)
	}

	// Create AES cipher
	block, err := aes.NewCipher(ke.adminKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt the PEM data
	pemBytes, err := gcm.Open(nil, encryptedData.Nonce, encryptedData.EncryptedData, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt PEM data: %w", err)
	}

	return string(pemBytes), nil
}

// ConvertPrivateKeyToPEM converts a private key to PEM format
func ConvertPrivateKeyToPEM(privateKey any, keyType KeyType) (string, error) {
	if isRSAKeyType(keyType) {
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("expected *rsa.PrivateKey, got %T", privateKey)
		}
		keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
		block := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		}
		return string(pem.EncodeToMemory(block)), nil
	}

	if isECCKeyType(keyType) {
		ecKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("expected *ecdsa.PrivateKey, got %T", privateKey)
		}
		keyBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return "", fmt.Errorf("failed to marshal EC key: %w", err)
		}
		block := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}
		return string(pem.EncodeToMemory(block)), nil
	}

	if isKyberKeyType(keyType) {
		// Kyber keys don't have a standard PEM format
		// We'll use a custom format
		keyBytes, err := serializePrivateKey(privateKey, keyType)
		if err != nil {
			return "", fmt.Errorf("failed to serialize Kyber key: %w", err)
		}
		block := &pem.Block{
			Type:  "KYBER PRIVATE KEY",
			Bytes: keyBytes,
		}
		return string(pem.EncodeToMemory(block)), nil
	}

	return "", fmt.Errorf("unsupported key type for PEM conversion: %s", keyType)
}