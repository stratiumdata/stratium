//go:build fips

package key_manager

func serializeKyberPrivateKey(_ any, _ KeyType) ([]byte, bool, error) {
	return nil, false, nil
}

func deserializeKyberPrivateKey(_ []byte, _ KeyType) (any, bool, error) {
	return nil, false, nil
}

func convertKyberPrivateKeyToPEM(_ any, _ KeyType) (string, bool, error) {
	return "", false, nil
}
