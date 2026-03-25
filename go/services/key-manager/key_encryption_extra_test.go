package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// TestKeyEncryption_EncryptDecryptRSA3072 covers RSA-3072 serialize/deserialize paths.
func TestKeyEncryption_EncryptDecryptRSA3072(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(3072) error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_3072)
	if err != nil {
		t.Fatalf("EncryptPrivateKey(RSA_3072) error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_3072)
	if err != nil {
		t.Fatalf("DecryptPrivateKey(RSA_3072) error = %v", err)
	}

	rsaDec, ok := decrypted.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey(RSA_3072) returned %T, want *rsa.PrivateKey", decrypted)
	}
	if rsaDec.N.Cmp(rsaKey.N) != 0 {
		t.Error("DecryptPrivateKey(RSA_3072) returned different key")
	}
}

// TestKeyEncryption_EncryptDecryptRSA4096 covers RSA-4096 serialize/deserialize paths.
func TestKeyEncryption_EncryptDecryptRSA4096(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("rsa.GenerateKey(4096) error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_4096)
	if err != nil {
		t.Fatalf("EncryptPrivateKey(RSA_4096) error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_4096)
	if err != nil {
		t.Fatalf("DecryptPrivateKey(RSA_4096) error = %v", err)
	}

	rsaDec, ok := decrypted.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey(RSA_4096) returned %T, want *rsa.PrivateKey", decrypted)
	}
	if rsaDec.N.Cmp(rsaKey.N) != 0 {
		t.Error("DecryptPrivateKey(RSA_4096) returned different key")
	}
}

// TestKeyEncryption_EncryptDecryptECCP384 covers ECC P384 serialize/deserialize paths.
func TestKeyEncryption_EncryptDecryptECCP384(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384) error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_ECC_P384)
	if err != nil {
		t.Fatalf("EncryptPrivateKey(ECC_P384) error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_ECC_P384)
	if err != nil {
		t.Fatalf("DecryptPrivateKey(ECC_P384) error = %v", err)
	}

	eccDec, ok := decrypted.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey(ECC_P384) returned %T, want *ecdsa.PrivateKey", decrypted)
	}
	if eccDec.X.Cmp(eccKey.X) != 0 {
		t.Error("DecryptPrivateKey(ECC_P384) returned different key")
	}
}

// TestKeyEncryption_EncryptDecryptECCP521 covers ECC P521 serialize/deserialize paths.
func TestKeyEncryption_EncryptDecryptECCP521(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatalf("NewKeyEncryption() error = %v", err)
	}

	eccKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P521) error = %v", err)
	}

	encrypted, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_ECC_P521)
	if err != nil {
		t.Fatalf("EncryptPrivateKey(ECC_P521) error = %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_ECC_P521)
	if err != nil {
		t.Fatalf("DecryptPrivateKey(ECC_P521) error = %v", err)
	}

	eccDec, ok := decrypted.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("DecryptPrivateKey(ECC_P521) returned %T, want *ecdsa.PrivateKey", decrypted)
	}
	if eccDec.X.Cmp(eccKey.X) != 0 {
		t.Error("DecryptPrivateKey(ECC_P521) returned different key")
	}
}

// TestKeyEncryption_EncryptPrivateKey_UnsupportedType verifies error for unsupported key type.
func TestKeyEncryption_EncryptPrivateKey_UnsupportedType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Pass a valid key but with an unsupported type
	_, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("EncryptPrivateKey() should fail for unsupported key type")
	}
}

// TestKeyEncryption_DecryptPrivateKey_Tampered verifies authentication failure when ciphertext is modified.
func TestKeyEncryption_DecryptPrivateKey_Tampered(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypted, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}

	// Tamper with the ciphertext
	if len(encrypted.EncryptedData) > 0 {
		encrypted.EncryptedData[0] ^= 0xFF
	}

	_, err = ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey() should fail for tampered ciphertext")
	}
}

// TestKeyEncryption_DecryptPrivateKey_WrongKey verifies authentication failure when wrong key is used.
func TestKeyEncryption_DecryptPrivateKey_WrongKey(t *testing.T) {
	adminKey1 := make([]byte, 32)
	adminKey2 := make([]byte, 32)
	_, _ = rand.Read(adminKey1)
	_, _ = rand.Read(adminKey2)

	ke1, _ := NewKeyEncryption(adminKey1)
	ke2, _ := NewKeyEncryption(adminKey2)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypted, err := ke1.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}

	// Try to decrypt with a different key
	_, err = ke2.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey() should fail when using wrong decryption key")
	}
}

// TestKeyEncryption_DecryptPrivateKey_UnsupportedType verifies error for unsupported type after decryption.
func TestKeyEncryption_DecryptPrivateKey_UnsupportedType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	// Manually build a valid-looking EncryptedKeyData with garbage bytes
	// The decryption will succeed but deserialization will fail for unsupported type
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	encrypted, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}

	// Now try to deserialize as an unsupported type
	_, err = ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("DecryptPrivateKey() should fail for unsupported key type")
	}
}

// TestKeyEncryption_DecryptPrivateKey_ECC_WrongType verifies error when decrypting RSA as ECC.
func TestKeyEncryption_DecryptPrivateKey_ECC_WrongType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	// Encrypt an ECC key but try to deserialize as RSA
	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	encrypted, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("EncryptPrivateKey() error = %v", err)
	}

	// Decrypting ECC-serialized bytes as RSA should fail
	_, err = ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey() should fail when key type mismatch (ECC encrypted, RSA requested)")
	}
}

// TestKeyEncryption_DecryptPEM_Tampered verifies authentication failure for tampered PEM ciphertext.
func TestKeyEncryption_DecryptPEM_Tampered(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)

	ke, _ := NewKeyEncryption(adminKey)

	pemData := "-----BEGIN RSA PRIVATE KEY-----\nfakedata\n-----END RSA PRIVATE KEY-----"
	encrypted, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM() error = %v", err)
	}

	// Tamper with the ciphertext
	if len(encrypted.EncryptedData) > 0 {
		encrypted.EncryptedData[0] ^= 0xFF
	}

	_, err = ke.DecryptPrivateKeyPEM(encrypted)
	if err == nil {
		t.Fatal("DecryptPrivateKeyPEM() should fail for tampered ciphertext")
	}
}

// TestConvertPrivateKeyToPEM_ECCP384 covers ECC P384 PEM conversion.
func TestConvertPrivateKeyToPEM_ECCP384(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P384) error = %v", err)
	}

	pemStr, err := ConvertPrivateKeyToPEM(eccKey, KeyType_KEY_TYPE_ECC_P384)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM(ECC_P384) error = %v", err)
	}
	if pemStr == "" {
		t.Error("ConvertPrivateKeyToPEM(ECC_P384) returned empty string")
	}
}

// TestConvertPrivateKeyToPEM_ECCP521 covers ECC P521 PEM conversion.
func TestConvertPrivateKeyToPEM_ECCP521(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey(P521) error = %v", err)
	}

	pemStr, err := ConvertPrivateKeyToPEM(eccKey, KeyType_KEY_TYPE_ECC_P521)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM(ECC_P521) error = %v", err)
	}
	if pemStr == "" {
		t.Error("ConvertPrivateKeyToPEM(ECC_P521) returned empty string")
	}
}

// TestConvertPrivateKeyToPEM_WrongECCType verifies error when key type doesn't match for ECC.
func TestConvertPrivateKeyToPEM_WrongECCType(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Pass RSA key but claim it's ECC
	_, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("ConvertPrivateKeyToPEM() should fail when RSA key passed as ECC type")
	}
}

// TestSerializePrivateKey_UnsupportedType verifies error for unsupported key type via EncryptPrivateKey.
func TestSerializePrivateKey_UnsupportedType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// KEY_TYPE_UNSPECIFIED is not RSA, ECC, or Kyber so hits the unsupported branch
	_, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("EncryptPrivateKey() should fail for unspecified key type")
	}
}
