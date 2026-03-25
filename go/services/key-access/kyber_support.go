//go:build !fips

package key_access

import (
	"crypto"
	"fmt"

	keyManager "stratium/services/key-manager"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func parseKyberPublicKey(blockBytes []byte, keyType keyManager.KeyType) (crypto.PublicKey, bool, error) {
	switch keyType {
	case keyManager.KeyType_KEY_TYPE_KYBER_512:
		pub, err := kyber512.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-512 public key: %w", err)
		}
		return pub, true, nil
	case keyManager.KeyType_KEY_TYPE_KYBER_768:
		pub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-768 public key: %w", err)
		}
		return pub, true, nil
	case keyManager.KeyType_KEY_TYPE_KYBER_1024:
		pub, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-1024 public key: %w", err)
		}
		return pub, true, nil
	default:
		return nil, false, nil
	}
}

func (s *Server) encryptDEKWithKyber(publicKey crypto.PublicKey, dek []byte) ([]byte, bool, error) {
	switch pubKey := publicKey.(type) {
	case *kyber512.PublicKey:
		ciphertext, sharedSecret, err := kyber512.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, true, fmt.Errorf("failed to encapsulate with KYBER-512: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)
		return encrypted, true, err
	case *kyber768.PublicKey:
		ciphertext, sharedSecret, err := kyber768.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, true, fmt.Errorf("failed to encapsulate with KYBER-768: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)
		return encrypted, true, err
	case *kyber1024.PublicKey:
		ciphertext, sharedSecret, err := kyber1024.Scheme().Encapsulate(pubKey)
		if err != nil {
			return nil, true, fmt.Errorf("failed to encapsulate with KYBER-1024: %w", err)
		}
		encrypted, err := s.encryptDEKWithSharedSecret(dek, sharedSecret, ciphertext)
		return encrypted, true, err
	default:
		return nil, false, nil
	}
}
