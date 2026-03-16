package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestNewKeyEncryption_ValidKey verifies creation with a valid 32-byte key.
func TestNewKeyEncryption_ValidKey(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}
	if ke == nil {
		t.Fatal("NewKeyEncryption() returned nil")
	}
}

// TestNewKeyEncryption_WrongKeySize verifies error for non-32-byte key.
func TestNewKeyEncryption_WrongKeySize(t *testing.T) {
	_, err := NewKeyEncryption([]byte("too-short"))
	if err == nil {
		t.Fatal("NewKeyEncryption() should fail for wrong key size")
	}
}

// TestKeyEncryption_EncryptDecryptRSA verifies RSA private key can be encrypted and decrypted.
func TestKeyEncryption_EncryptDecryptRSA(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}
	if encrypted == nil {
		t.Fatal("EncryptPrivateKey() returned nil")
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("DecryptPrivateKey() error = %v", err)
	}
	if decrypted == nil {
		t.Fatal("DecryptPrivateKey() returned nil")
	}

	rsaDecrypted, ok := decrypted.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey() returned %T, want *rsa.PrivateKey", decrypted)
	}
	if rsaDecrypted.N.Cmp(rsaKey.N) != 0 {
		t.Error("DecryptPrivateKey() returned different RSA key")
	}
}

// TestKeyEncryption_EncryptDecryptECC verifies ECC private key can be encrypted and decrypted.
func TestKeyEncryption_EncryptDecryptECC(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("DecryptPrivateKey() error = %v", err)
	}

	eccDecrypted, ok := decrypted.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey() returned %T, want *ecdsa.PrivateKey", decrypted)
	}
	if eccDecrypted.X.Cmp(eccKey.X) != 0 {
		t.Error("DecryptPrivateKey() returned different ECC key")
	}
}

// TestKeyEncryption_DecryptPrivateKey_WrongAlgorithm verifies error on unknown algorithm.
func TestKeyEncryption_DecryptPrivateKey_WrongAlgorithm(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	badEncrypted := &EncryptedKeyData{
		Algorithm:     "UNKNOWN-ALGO",
		EncryptedData: []byte("fake-data"),
		Nonce:         make([]byte, 12),
	}

	_, err := ke.DecryptPrivateKey(badEncrypted, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey() should fail for unknown algorithm")
	}
}

// TestKeyEncryption_EncryptDecryptPEM verifies PEM data can be encrypted and decrypted.
func TestKeyEncryption_EncryptDecryptPEM(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	pemData := "-----BEGIN RSA PRIVATE KEY-----\nfake-pem-data\n-----END RSA PRIVATE KEY-----"

	encrypted, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM() error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKeyPEM(encrypted)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM() error = %v", err)
	}

	if decrypted != pemData {
		t.Errorf("DecryptPrivateKeyPEM() = %q, want %q", decrypted, pemData)
	}
}

// TestKeyEncryption_DecryptPEM_WrongAlgorithm verifies error on unknown algorithm.
func TestKeyEncryption_DecryptPEM_WrongAlgorithm(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	badEncrypted := &EncryptedKeyData{
		Algorithm:     "AES-128-CBC",
		EncryptedData: []byte("fake-data"),
		Nonce:         make([]byte, 12),
	}

	_, err := ke.DecryptPrivateKeyPEM(badEncrypted)
	if err == nil {
		t.Fatal("DecryptPrivateKeyPEM() should fail for unknown algorithm")
	}
}

// TestConvertPrivateKeyToPEM_RSA verifies RSA private key PEM conversion.
func TestConvertPrivateKeyToPEM_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pemStr, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM() error = %v", err)
	}
	if pemStr == "" {
		t.Error("ConvertPrivateKeyToPEM() returned empty PEM")
	}
}

// TestConvertPrivateKeyToPEM_ECC verifies ECC private key PEM conversion.
func TestConvertPrivateKeyToPEM_ECC(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pemStr, err := ConvertPrivateKeyToPEM(eccKey, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM() error = %v", err)
	}
	if pemStr == "" {
		t.Error("ConvertPrivateKeyToPEM() returned empty PEM")
	}
}

// TestConvertPrivateKeyToPEM_WrongRSAType verifies error when key type doesn't match.
func TestConvertPrivateKeyToPEM_WrongRSAType(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Pass an ECC key but claim it's RSA
	_, err = ConvertPrivateKeyToPEM(eccKey, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("ConvertPrivateKeyToPEM() should fail when key type doesn't match")
	}
}

// TestConvertPrivateKeyToPEM_UnsupportedType verifies error for unsupported key type.
func TestConvertPrivateKeyToPEM_UnsupportedType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, err = ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("ConvertPrivateKeyToPEM() should fail for unsupported key type")
	}
}

// TestKeyEncryption_EncryptPrivateKey_WrongRSAType verifies error when key type doesn't match.
func TestKeyEncryption_EncryptPrivateKey_WrongRSAType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// Pass ECC key but claim it's RSA type
	_, err = ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("EncryptPrivateKey() should fail when key type doesn't match")
	}
}

// TestIsRSAKeyType verifies RSA key type family detection.
func TestIsRSAKeyType(t *testing.T) {
	if !isRSAKeyType(KeyType_KEY_TYPE_RSA_2048) {
		t.Error("isRSAKeyType(RSA_2048) = false, want true")
	}
	if !isRSAKeyType(KeyType_KEY_TYPE_RSA_3072) {
		t.Error("isRSAKeyType(RSA_3072) = false, want true")
	}
	if !isRSAKeyType(KeyType_KEY_TYPE_RSA_4096) {
		t.Error("isRSAKeyType(RSA_4096) = false, want true")
	}
	if isRSAKeyType(KeyType_KEY_TYPE_ECC_P256) {
		t.Error("isRSAKeyType(ECC_P256) = true, want false")
	}
}

// TestIsECCKeyType verifies ECC key type family detection.
func TestIsECCKeyType(t *testing.T) {
	if !isECCKeyType(KeyType_KEY_TYPE_ECC_P256) {
		t.Error("isECCKeyType(ECC_P256) = false, want true")
	}
	if !isECCKeyType(KeyType_KEY_TYPE_ECC_P384) {
		t.Error("isECCKeyType(ECC_P384) = false, want true")
	}
	if !isECCKeyType(KeyType_KEY_TYPE_ECC_P521) {
		t.Error("isECCKeyType(ECC_P521) = false, want true")
	}
	if isECCKeyType(KeyType_KEY_TYPE_RSA_2048) {
		t.Error("isECCKeyType(RSA_2048) = true, want false")
	}
}

// TestIsKyberKeyType verifies Kyber key type family detection.
func TestIsKyberKeyType(t *testing.T) {
	if !isKyberKeyType(KeyType_KEY_TYPE_KYBER_512) {
		t.Error("isKyberKeyType(KYBER_512) = false, want true")
	}
	if !isKyberKeyType(KeyType_KEY_TYPE_KYBER_768) {
		t.Error("isKyberKeyType(KYBER_768) = false, want true")
	}
	if !isKyberKeyType(KeyType_KEY_TYPE_KYBER_1024) {
		t.Error("isKyberKeyType(KYBER_1024) = false, want true")
	}
	if isKyberKeyType(KeyType_KEY_TYPE_RSA_2048) {
		t.Error("isKyberKeyType(RSA_2048) = true, want false")
	}
}
