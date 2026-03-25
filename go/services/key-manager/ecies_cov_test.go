//go:build !fips

package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestCoverageFinal80_ECIES_RoundTrip(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("hello-ecies-test-data-12345")

	ciphertext, err := encryptDEKWithECCPublicKey(&ecKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey: %v", err)
	}

	decrypted, err := decryptDEKWithECCPrivateKey(ecKey, ciphertext)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatal("round-trip mismatch")
	}
}

func TestCoverageFinal80_ECIES_InvalidInputs(t *testing.T) {
	_, err := encryptDEKWithECCPublicKey(nil, []byte("x"))
	if err == nil {
		t.Fatal("expected error for nil public key")
	}

	_, err = decryptDEKWithECCPrivateKey(nil, []byte("x"))
	if err == nil {
		t.Fatal("expected error for nil private key")
	}

	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err = decryptDEKWithECCPrivateKey(ecKey, []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestCoverageFinal80_EncryptDecryptECCPrivateKey(t *testing.T) {
	adminKey := make([]byte, 32)
	if _, err := rand.Read(adminKey); err != nil {
		t.Fatal(err)
	}
	ke, err := NewKeyEncryption(adminKey)
	if err != nil {
		t.Fatal(err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := ke.EncryptPrivateKey(ecKey, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("EncryptPrivateKey ECC: %v", err)
	}

	decrypted, err := ke.DecryptPrivateKey(encrypted, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("DecryptPrivateKey ECC: %v", err)
	}

	if _, ok := decrypted.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", decrypted)
	}
}

func TestCoverageFinal80_SerializeUnsupportedKeyType(t *testing.T) {
	_, err := serializePrivateKey("not-a-key", KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestCoverageFinal80_DeserializeUnsupportedKeyType(t *testing.T) {
	_, err := deserializePrivateKey([]byte{1, 2, 3}, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}
