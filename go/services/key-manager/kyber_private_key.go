//go:build !fips

package key_manager

import (
	"encoding/pem"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func serializeKyberPrivateKey(privateKey any, keyType KeyType) ([]byte, bool, error) {
	switch k := privateKey.(type) {
	case *kyber512.PrivateKey:
		keyBytes := make([]byte, kyber512.Scheme().PrivateKeySize())
		k.Pack(keyBytes)
		return keyBytes, true, nil
	case *kyber768.PrivateKey:
		keyBytes := make([]byte, kyber768.Scheme().PrivateKeySize())
		k.Pack(keyBytes)
		return keyBytes, true, nil
	case *kyber1024.PrivateKey:
		keyBytes := make([]byte, kyber1024.Scheme().PrivateKeySize())
		k.Pack(keyBytes)
		return keyBytes, true, nil
	default:
		if kemKey, ok := privateKey.(kem.PrivateKey); ok {
			keyBytes, err := kemKey.MarshalBinary()
			if err != nil {
				return nil, true, fmt.Errorf("failed to marshal KEM key: %w", err)
			}
			return keyBytes, true, nil
		}
		return nil, false, nil
	}
}

func deserializeKyberPrivateKey(keyBytes []byte, _ KeyType) (any, bool, error) {
	if len(keyBytes) == kyber512.Scheme().PrivateKeySize() {
		privateKey := new(kyber512.PrivateKey)
		privateKey.Unpack(keyBytes)
		return privateKey, true, nil
	}

	if len(keyBytes) == kyber768.Scheme().PrivateKeySize() {
		privateKey := new(kyber768.PrivateKey)
		privateKey.Unpack(keyBytes)
		return privateKey, true, nil
	}

	if len(keyBytes) == kyber1024.Scheme().PrivateKeySize() {
		privateKey := new(kyber1024.PrivateKey)
		privateKey.Unpack(keyBytes)
		return privateKey, true, nil
	}

	return nil, true, fmt.Errorf("failed to deserialize Kyber key: unsupported private key size %d or invalid key", len(keyBytes))
}

func convertKyberPrivateKeyToPEM(privateKey any, keyType KeyType) (string, bool, error) {
	keyBytes, ok, err := serializeKyberPrivateKey(privateKey, keyType)
	if !ok {
		return "", false, nil
	}
	if err != nil {
		return "", true, fmt.Errorf("failed to serialize Kyber key: %w", err)
	}

	block := &pem.Block{
		Type:  "KYBER PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), true, nil
}
