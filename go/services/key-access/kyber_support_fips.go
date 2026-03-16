//go:build fips

package key_access

import (
	"crypto"
	"fmt"

	keyManager "stratium/services/key-manager"
)

func parseKyberPublicKey(_ []byte, keyType keyManager.KeyType) (crypto.PublicKey, bool, error) {
	switch keyType {
	case keyManager.KeyType_KEY_TYPE_KYBER_512,
		keyManager.KeyType_KEY_TYPE_KYBER_768,
		keyManager.KeyType_KEY_TYPE_KYBER_1024:
		return nil, true, fmt.Errorf("kyber is disabled in FIPS builds")
	default:
		return nil, false, nil
	}
}

func (s *Server) encryptDEKWithKyber(_ crypto.PublicKey, _ []byte) ([]byte, bool, error) {
	return nil, false, nil
}
