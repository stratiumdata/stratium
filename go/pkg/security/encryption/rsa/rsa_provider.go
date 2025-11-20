package rsa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"stratium/pkg/security/encryption"
)

type Provider struct {
	keySize    int
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewProvider creates a new RSA provider with the specified key size
func NewProvider(algorithm encryption.Algorithm) (*Provider, error) {
	var keySize int
	switch algorithm {
	case encryption.RSA2048:
		keySize = 2048
	case encryption.RSA3072:
		keySize = 3072
	case encryption.RSA4096:
		keySize = 4096
	default:
		return nil, fmt.Errorf("unsupported RSA algorithm: %s", string(algorithm))
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &Provider{
		keySize:    keySize,
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// Encrypt encrypts data using RSA-OAEP with SHA-256
func (r *Provider) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	// For RSA, we ignore the key parameter and use the public key directly
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.publicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA encryption failed: %w", err)
	}
	return ciphertext, nil
}

// Decrypt decrypts data using RSA-OAEP with SHA-256
func (r *Provider) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	// For RSA, we ignore the key parameter and use the private key directly
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, r.privateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA decryption failed: %w", err)
	}
	return plaintext, nil
}

// GetPublicKeyBytes returns the public key in DER format
func (r *Provider) GetPublicKeyBytes() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(r.publicKey)
}

// GetPrivateKeyBytes returns the private key in PKCS#8 format
func (r *Provider) GetPrivateKeyBytes() ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(r.privateKey)
}

// GetKeySize returns the RSA key size in bits
func (r *Provider) GetKeySize() int {
	return r.keySize
}

// GetMaxPlaintextSize returns the maximum size of plaintext that can be encrypted
func (r *Provider) GetMaxPlaintextSize() int {
	// RSA-OAEP with SHA-256 overhead is 2 * hash_length + 2 = 2 * 32 + 2 = 66 bytes
	return (r.keySize / 8) - 66
}

// EncryptLarge encrypts large data by splitting it into chunks
func (r *Provider) EncryptLarge(plaintext []byte) ([]byte, error) {
	maxChunkSize := r.GetMaxPlaintextSize()
	if len(plaintext) <= maxChunkSize {
		return r.Encrypt(nil, plaintext)
	}

	var result []byte
	for i := 0; i < len(plaintext); i += maxChunkSize {
		end := i + maxChunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		chunk := plaintext[i:end]
		encryptedChunk, err := r.Encrypt(nil, chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt chunk: %w", err)
		}

		// Prepend chunk size (4 bytes) for decryption
		chunkSize := len(encryptedChunk)
		sizeBytes := []byte{
			byte(chunkSize >> 24),
			byte(chunkSize >> 16),
			byte(chunkSize >> 8),
			byte(chunkSize),
		}
		result = append(result, sizeBytes...)
		result = append(result, encryptedChunk...)
	}

	return result, nil
}

// DecryptLarge decrypts large data that was encrypted with EncryptLarge
func (r *Provider) DecryptLarge(ciphertext []byte) ([]byte, error) {
	var result []byte
	offset := 0

	for offset < len(ciphertext) {
		if offset+4 > len(ciphertext) {
			return nil, fmt.Errorf("invalid ciphertext format")
		}

		// Read chunk size
		chunkSize := int(ciphertext[offset])<<24 |
			int(ciphertext[offset+1])<<16 |
			int(ciphertext[offset+2])<<8 |
			int(ciphertext[offset+3])
		offset += 4

		if offset+chunkSize > len(ciphertext) {
			return nil, fmt.Errorf("invalid chunk size")
		}

		// Decrypt chunk
		chunk := ciphertext[offset : offset+chunkSize]
		decryptedChunk, err := r.Decrypt(nil, chunk)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk: %w", err)
		}

		result = append(result, decryptedChunk...)
		offset += chunkSize
	}

	return result, nil
}
