package factory

import (
	"fmt"
	"stratium/pkg/security/encryption"
	"stratium/pkg/security/encryption/ecc"
	"stratium/pkg/security/encryption/kem"
	"stratium/pkg/security/encryption/rsa"
)

// EncryptionProvider interface extends Provider to include key exchange methods
type EncryptionProvider interface {
	encryption.Provider
	// GetAlgorithm returns the algorithm name
	GetAlgorithm() encryption.Algorithm
}

// KEMProvider wraps the KEM interface for consistency
type KEMProvider struct {
	kem.KyberProvider
	algorithm encryption.Algorithm
}

func (k *KEMProvider) GetAlgorithm() encryption.Algorithm {
	return k.algorithm
}

// RSAProviderWrapper wraps RSA provider for consistency
type RSAProviderWrapper struct {
	*rsa.Provider
	algorithm encryption.Algorithm
}

func (r *RSAProviderWrapper) GetAlgorithm() encryption.Algorithm {
	return r.algorithm
}

// For RSA, we need to handle the direct encryption/decryption differently
func (r *RSAProviderWrapper) Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	// Check if we need to use large encryption (for messages larger than max chunk size)
	maxSize := r.Provider.GetMaxPlaintextSize()
	if len(plaintext) > maxSize {
		return r.Provider.EncryptLarge(plaintext)
	}
	// For smaller messages, use direct encryption
	return r.Provider.Encrypt(nil, plaintext)
}

func (r *RSAProviderWrapper) Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	// Try direct decryption first
	decrypted, err := r.Provider.Decrypt(nil, ciphertext)
	if err != nil {
		// If direct decryption fails, try large decryption (chunked format)
		return r.Provider.DecryptLarge(ciphertext)
	}
	return decrypted, nil
}

// ECCProviderWrapper wraps ECC provider for consistency
type ECCProviderWrapper struct {
	*ecc.Provider
	algorithm encryption.Algorithm
}

func (e *ECCProviderWrapper) GetAlgorithm() encryption.Algorithm {
	return e.algorithm
}

// NewEncryptionProvider creates a provider for any supported algorithm
func NewEncryptionProvider(alg encryption.Algorithm) (EncryptionProvider, error) {
	switch alg {
	// Post-Quantum KEM algorithms
	case encryption.KYBER512, encryption.KYBER768, encryption.KYBER1024:
		kemProvider, err := kem.NewKEMProvider(alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create KEM provider: %w", err)
		}
		return &KEMProvider{
			KyberProvider: kemProvider,
			algorithm:     alg,
		}, nil

	// RSA algorithms
	case encryption.RSA2048, encryption.RSA3072, encryption.RSA4096:
		rsaProvider, err := rsa.NewProvider(alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create RSA provider: %w", err)
		}
		return &RSAProviderWrapper{
			Provider:  rsaProvider,
			algorithm: alg,
		}, nil

	// ECC algorithms
	case encryption.ECC_P256, encryption.ECC_P384, encryption.ECC_P521:
		eccProvider, err := ecc.NewECCProvider(alg)
		if err != nil {
			return nil, fmt.Errorf("failed to create ECC P256 provider: %w", err)
		}
		return &ECCProviderWrapper{
			Provider:  eccProvider,
			algorithm: alg,
		}, nil

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", alg)
	}
}

// GetAlgorithmType returns the type of algorithm (KEM, RSA, or ECC)
func GetAlgorithmType(alg encryption.Algorithm) string {
	switch alg {
	case encryption.KYBER512, encryption.KYBER768, encryption.KYBER1024:
		return "KEM"
	case encryption.RSA2048, encryption.RSA3072, encryption.RSA4096:
		return "RSA"
	case encryption.ECC_P256, encryption.ECC_P384, encryption.ECC_P521:
		return "ECC"
	default:
		return "UNKNOWN"
	}
}
