package key_manager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestDecryptClientWrappedDEKWithKey_NilKey verifies error on nil key.
func TestDecryptClientWrappedDEKWithKey_NilKey(t *testing.T) {
	_, err := decryptClientWrappedDEKWithKey(nil, []byte("data"))
	if err == nil {
		t.Fatal("decryptClientWrappedDEKWithKey(nil, ...) should return error")
	}
}

// TestDecryptClientWrappedDEKWithKey_MissingPEM verifies error on empty public key PEM.
func TestDecryptClientWrappedDEKWithKey_MissingPEM(t *testing.T) {
	key := &Key{KeyId: "test", PublicKeyPem: ""}
	_, err := decryptClientWrappedDEKWithKey(key, []byte("data"))
	if err == nil {
		t.Fatal("decryptClientWrappedDEKWithKey() with empty PEM should return error")
	}
}

// TestDecryptClientWrappedDEKWithKey_InvalidPEM verifies error on malformed PEM.
func TestDecryptClientWrappedDEKWithKey_InvalidPEM(t *testing.T) {
	key := &Key{KeyId: "test", PublicKeyPem: "not-a-valid-pem"}
	_, err := decryptClientWrappedDEKWithKey(key, []byte("data"))
	if err == nil {
		t.Fatal("decryptClientWrappedDEKWithKey() with invalid PEM should return error")
	}
}

// TestDecryptClientWrappedDEKWithKey_WrongCiphertextLength verifies error when
// ciphertext length does not match the RSA key modulus size.
func TestDecryptClientWrappedDEKWithKey_WrongCiphertextLength(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	// Provide ciphertext with wrong length (not 256 bytes for RSA-2048)
	_, err = decryptClientWrappedDEKWithKey(key, []byte("short-wrong-length"))
	if err == nil {
		t.Fatal("decryptClientWrappedDEKWithKey() with wrong ciphertext length should return error")
	}
}
