//go:build fips

package key_manager

import "fmt"

func (s *SoftwareKeyProvider) generateKyberKeyPair(_ KeyType) (any, any, error) {
	return nil, nil, fmt.Errorf("kyber is disabled in FIPS builds")
}

func (s *SoftwareKeyProvider) encryptWithKyber(_ any, _ []byte) ([]byte, bool, error) {
	return nil, false, nil
}

func (s *SoftwareKeyProvider) decryptWithKyber(_ any, _ []byte) ([]byte, bool, error) {
	return nil, false, nil
}

func (s *SoftwareKeyProvider) publicKeyToPEMForKyber(_ any) (string, bool, error) {
	return "", false, nil
}
