//go:build fips

package key_manager

import (
	"crypto"
	"fmt"
)

func publicKeyToPEMIfKyber(_ crypto.PublicKey) (string, KeyType, bool, error) {
	return "", KeyType_KEY_TYPE_UNSPECIFIED, false, nil
}

func parseKyberPublicKeyFromPEM(_ []byte, keyType KeyType) (crypto.PublicKey, bool, error) {
	switch keyType {
	case KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024:
		return nil, true, fmt.Errorf("kyber is disabled in FIPS builds")
	default:
		return nil, false, nil
	}
}
