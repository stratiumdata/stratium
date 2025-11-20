package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestECCECIESRoundTrip(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	plaintext := []byte("secret data for ecc")
	ciphertext, err := encryptDEKWithECCPublicKey(&privateKey.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey failed: %v", err)
	}

	decrypted, err := decryptDEKWithECCPrivateKey(privateKey, ciphertext)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %s want %s", decrypted, plaintext)
	}
}

func TestECCECIESTamper(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	ciphertext, err := encryptDEKWithECCPublicKey(&privateKey.PublicKey, []byte("data"))
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper with ciphertext payload
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0xFF

	if _, err := decryptDEKWithECCPrivateKey(privateKey, corrupted); err == nil {
		t.Fatalf("expected error when decrypting tampered payload")
	}
}
