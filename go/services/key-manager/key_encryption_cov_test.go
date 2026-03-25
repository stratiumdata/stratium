//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCoverageFinal80_ConvertPrivateKeyToPEM_ECC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, err := ConvertPrivateKeyToPEM(ecKey, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM ECC: %v", err)
	}
	if pemStr == "" {
		t.Fatal("empty PEM")
	}
}

// NOTE: TestCoverageFinal80_ConvertPrivateKeyToPEM_ECCWrongType removed — duplicate of
// TestConvertPrivateKeyToPEM_ECCWrongType in coverage_final_push_test.go.

func TestCoverageFinal80_ConvertPrivateKeyToPEM_UnsupportedType(t *testing.T) {
	_, err := ConvertPrivateKeyToPEM("not-a-key", KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}

func TestCoverageFinal80_EncryptDecryptPrivateKeyPEM(t *testing.T) {
	adminKey := make([]byte, 32)
	if _, err := rand.Read(adminKey); err != nil {
		t.Fatal(err)
	}
	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a real RSA private key PEM instead of fake data
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))

	encrypted, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM: %v", err)
	}

	decrypted, err := ke.DecryptPrivateKeyPEM(encrypted)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM: %v", err)
	}
	if decrypted != pemData {
		t.Fatalf("round-trip mismatch")
	}
}

func TestCoverageFinal80_DecryptPrivateKeyPEM_WrongAlgorithm(t *testing.T) {
	adminKey := make([]byte, 32)
	if _, err := rand.Read(adminKey); err != nil {
		t.Fatal(err)
	}
	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ke.DecryptPrivateKeyPEM(&EncryptedKeyData{
		Algorithm: "UNSUPPORTED",
	})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
