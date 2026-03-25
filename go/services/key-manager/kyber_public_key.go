//go:build !fips

package key_manager

import (
	"crypto"
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func publicKeyToPEMIfKyber(publicKey crypto.PublicKey) (string, KeyType, bool, error) {
	switch key := publicKey.(type) {
	case *kyber512.PublicKey:
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, true, fmt.Errorf("failed to marshal KYBER-512 public key: %w", err)
		}
		return encodeKyberPublicKeyPEM("KYBER-512 PUBLIC KEY", keyBytes), KeyType_KEY_TYPE_KYBER_512, true, nil
	case *kyber768.PublicKey:
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, true, fmt.Errorf("failed to marshal KYBER-768 public key: %w", err)
		}
		return encodeKyberPublicKeyPEM("KYBER-768 PUBLIC KEY", keyBytes), KeyType_KEY_TYPE_KYBER_768, true, nil
	case *kyber1024.PublicKey:
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, true, fmt.Errorf("failed to marshal KYBER-1024 public key: %w", err)
		}
		return encodeKyberPublicKeyPEM("KYBER-1024 PUBLIC KEY", keyBytes), KeyType_KEY_TYPE_KYBER_1024, true, nil
	default:
		return "", KeyType_KEY_TYPE_UNSPECIFIED, false, nil
	}
}

func parseKyberPublicKeyFromPEM(blockBytes []byte, keyType KeyType) (crypto.PublicKey, bool, error) {
	switch keyType {
	case KeyType_KEY_TYPE_KYBER_512:
		pub, err := kyber512.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-512 public key: %w", err)
		}
		return pub, true, nil
	case KeyType_KEY_TYPE_KYBER_768:
		pub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-768 public key: %w", err)
		}
		return pub, true, nil
	case KeyType_KEY_TYPE_KYBER_1024:
		pub, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(blockBytes)
		if err != nil {
			return nil, true, fmt.Errorf("failed to unmarshal KYBER-1024 public key: %w", err)
		}
		return pub, true, nil
	default:
		return nil, false, nil
	}
}

func encodeKyberPublicKeyPEM(label string, keyBytes []byte) string {
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  label,
		Bytes: keyBytes,
	})
	return string(pemBlock)
}
