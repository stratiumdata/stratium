//go:build !fips

package key_manager

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func (s *SoftwareKeyProvider) generateKyberKeyPair(keyType KeyType) (any, any, error) {
	switch keyType {
	case KeyType_KEY_TYPE_KYBER_512:
		pub, priv, err := kyber512.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate KYBER-512 key: %w", err)
		}
		return pub, priv, nil
	case KeyType_KEY_TYPE_KYBER_768:
		pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate KYBER-768 key: %w", err)
		}
		return pub, priv, nil
	case KeyType_KEY_TYPE_KYBER_1024:
		pub, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate KYBER-1024 key: %w", err)
		}
		return pub, priv, nil
	default:
		return nil, nil, fmt.Errorf("unsupported Kyber key type: %v", keyType)
	}
}

func (s *SoftwareKeyProvider) encryptWithKyber(publicKey any, plaintext []byte) ([]byte, bool, error) {
	switch key := publicKey.(type) {
	case *kyber512.PublicKey:
		ciphertext, sharedSecret, err := kyber512.Scheme().Encapsulate(key)
		if err != nil {
			return nil, true, fmt.Errorf("KYBER-512 encapsulation failed: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(plaintext, sharedSecret, ciphertext)
		return encrypted, true, err
	case *kyber768.PublicKey:
		ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(key)
		if err != nil {
			return nil, true, fmt.Errorf("KYBER-768 encapsulation failed: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(plaintext, sharedSecret, ciphertext)
		return encrypted, true, err
	case *kyber1024.PublicKey:
		ciphertext, sharedSecret, err := kyber1024.Scheme().Encapsulate(key)
		if err != nil {
			return nil, true, fmt.Errorf("KYBER-1024 encapsulation failed: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(plaintext, sharedSecret, ciphertext)
		return encrypted, true, err
	default:
		return nil, false, nil
	}
}

func (s *SoftwareKeyProvider) decryptWithKyber(privateKey any, ciphertext []byte) ([]byte, bool, error) {
	switch key := privateKey.(type) {
	case *kyber512.PrivateKey:
		plaintext, err := s.decryptWithKyber512(key, ciphertext)
		return plaintext, true, err
	case *kyber768.PrivateKey:
		plaintext, err := s.decryptWithKyber768(key, ciphertext)
		return plaintext, true, err
	case *kyber1024.PrivateKey:
		plaintext, err := s.decryptWithKyber1024(key, ciphertext)
		return plaintext, true, err
	default:
		return nil, false, nil
	}
}

func (s *SoftwareKeyProvider) publicKeyToPEMForKyber(publicKey any) (string, bool, error) {
	switch pub := publicKey.(type) {
	case *kyber512.PublicKey:
		keyBytes, err := pub.MarshalBinary()
		if err != nil {
			return "", true, err
		}
		return encodeKyberPublicKeyPEM("KYBER-512 PUBLIC KEY", keyBytes), true, nil
	case *kyber768.PublicKey:
		keyBytes, err := pub.MarshalBinary()
		if err != nil {
			return "", true, err
		}
		return encodeKyberPublicKeyPEM("KYBER-768 PUBLIC KEY", keyBytes), true, nil
	case *kyber1024.PublicKey:
		keyBytes, err := pub.MarshalBinary()
		if err != nil {
			return "", true, err
		}
		return encodeKyberPublicKeyPEM("KYBER-1024 PUBLIC KEY", keyBytes), true, nil
	default:
		return "", false, nil
	}
}

// decryptWithKyber512 decrypts data encrypted with KYBER-512 KEM.
func (s *SoftwareKeyProvider) decryptWithKyber512(privateKey *kyber512.PrivateKey, ciphertext []byte) ([]byte, error) {
	kemCiphertextSize := kyber512.Scheme().CiphertextSize()
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	sharedSecret, err := kyber512.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-512 decapsulation failed: %w", err)
	}

	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}

// decryptWithKyber768 decrypts data encrypted with KYBER-768 KEM.
func (s *SoftwareKeyProvider) decryptWithKyber768(privateKey *kyber768.PrivateKey, ciphertext []byte) ([]byte, error) {
	kemCiphertextSize := kyber768.Scheme().CiphertextSize()
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	sharedSecret, err := kyber768.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-768 decapsulation failed: %w", err)
	}

	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}

// decryptWithKyber1024 decrypts data encrypted with KYBER-1024 KEM.
func (s *SoftwareKeyProvider) decryptWithKyber1024(privateKey *kyber1024.PrivateKey, ciphertext []byte) ([]byte, error) {
	kemCiphertextSize := kyber1024.Scheme().CiphertextSize()
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	sharedSecret, err := kyber1024.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-1024 decapsulation failed: %w", err)
	}

	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}
