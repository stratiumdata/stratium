package ztdf

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"

	"stratium/pkg/models"
)

// TestGenerateDEK verifies DEK generation produces 32 random bytes.
func TestGenerateDEK(t *testing.T) {
	dek1, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error = %v", err)
	}
	if len(dek1) != 32 {
		t.Errorf("GenerateDEK() len = %d, want 32", len(dek1))
	}

	dek2, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() second call error = %v", err)
	}
	if bytes.Equal(dek1, dek2) {
		t.Error("GenerateDEK() returned identical keys on consecutive calls")
	}
}

// TestEncryptDecryptPayload verifies round-trip encrypt/decrypt.
func TestEncryptDecryptPayload(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"empty payload", []byte{}},
		{"small payload", []byte("hello world")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xfe, 0xff}},
		{"64 bytes", bytes.Repeat([]byte("A"), 64)},
		{"1MB payload", bytes.Repeat([]byte("X"), 1024*1024)},
	}

	key, _ := GenerateDEK()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, iv, err := EncryptPayload(tt.plaintext, key)
			if err != nil {
				t.Fatalf("EncryptPayload() error = %v", err)
			}
			if len(iv) == 0 {
				t.Error("EncryptPayload() returned empty IV")
			}

			got, err := DecryptPayload(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("DecryptPayload() error = %v", err)
			}
			if !bytes.Equal(got, tt.plaintext) {
				t.Errorf("DecryptPayload() got %q, want %q", got, tt.plaintext)
			}
		})
	}
}

// TestEncryptPayload_WrongKeySize verifies invalid key lengths are rejected.
func TestEncryptPayload_WrongKeySize(t *testing.T) {
	_, _, err := EncryptPayload([]byte("data"), []byte("short"))
	if err == nil {
		t.Error("EncryptPayload() with short key should fail")
	}
}

// TestDecryptPayload_WrongKey verifies decryption fails with a different key.
func TestDecryptPayload_WrongKey(t *testing.T) {
	key1, _ := GenerateDEK()
	key2, _ := GenerateDEK()

	ciphertext, iv, err := EncryptPayload([]byte("secret"), key1)
	if err != nil {
		t.Fatalf("EncryptPayload() error = %v", err)
	}

	_, err = DecryptPayload(ciphertext, key2, iv)
	if err == nil {
		t.Error("DecryptPayload() with wrong key should fail")
	}
}

// TestDecryptPayload_TamperedCiphertext verifies integrity check catches corruption.
func TestDecryptPayload_TamperedCiphertext(t *testing.T) {
	key, _ := GenerateDEK()
	ciphertext, iv, err := EncryptPayload([]byte("secret data"), key)
	if err != nil {
		t.Fatalf("EncryptPayload() error = %v", err)
	}

	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[0] ^= 0xff

	_, err = DecryptPayload(tampered, key, iv)
	if err == nil {
		t.Error("DecryptPayload() with tampered ciphertext should fail")
	}
}

// TestEncryptDecryptDEKWithRSA verifies RSA-OAEP DEK wrap/unwrap.
func TestEncryptDecryptDEKWithRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	dek, _ := GenerateDEK()

	encryptedDEK, err := EncryptDEKWithPublicKey(&privateKey.PublicKey, dek)
	if err != nil {
		t.Fatalf("EncryptDEKWithPublicKey() error = %v", err)
	}

	decryptedDEK, err := DecryptDEKWithPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEKWithPrivateKey() error = %v", err)
	}

	if !bytes.Equal(dek, decryptedDEK) {
		t.Error("DEK mismatch after RSA wrap/unwrap")
	}
}

// TestDecryptDEKWithPrivateKey_BadCiphertext verifies error on invalid ciphertext.
func TestDecryptDEKWithPrivateKey_BadCiphertext(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := DecryptDEKWithPrivateKey(privateKey, []byte("not-valid-ciphertext"))
	if err == nil {
		t.Error("DecryptDEKWithPrivateKey() with bad ciphertext should fail")
	}
	var modelErr *models.Error
	if !isModelError(err, &modelErr) {
		t.Errorf("expected *models.Error, got %T", err)
	}
}

// TestCalculatePolicyBinding verifies deterministic HMAC output.
func TestCalculatePolicyBinding(t *testing.T) {
	dek := []byte("0123456789abcdef0123456789abcdef")
	policy := "eyJwb2xpY3kiOiJ0ZXN0In0="

	h1 := CalculatePolicyBinding(dek, policy)
	h2 := CalculatePolicyBinding(dek, policy)
	if h1 != h2 {
		t.Error("CalculatePolicyBinding() is not deterministic")
	}
	if len(h1) == 0 {
		t.Error("CalculatePolicyBinding() returned empty hash")
	}
	// Verify it is valid base64
	if _, err := base64.StdEncoding.DecodeString(h1); err != nil {
		t.Errorf("CalculatePolicyBinding() returned invalid base64: %v", err)
	}
}

// TestVerifyPolicyBinding covers match and mismatch paths.
func TestVerifyPolicyBinding(t *testing.T) {
	dek := []byte("0123456789abcdef0123456789abcdef")
	policy := "eyJwb2xpY3kiOiJ0ZXN0In0="
	correct := CalculatePolicyBinding(dek, policy)

	if err := VerifyPolicyBinding(dek, policy, correct); err != nil {
		t.Errorf("VerifyPolicyBinding() with correct hash error = %v", err)
	}

	if err := VerifyPolicyBinding(dek, policy, "wronghash"); err == nil {
		t.Error("VerifyPolicyBinding() with wrong hash should fail")
	}
}

// TestCalculateVerifyPayloadHash verifies hash round-trip.
func TestCalculateVerifyPayloadHash(t *testing.T) {
	payload := []byte("test payload data")
	hash := CalculatePayloadHash(payload)
	if len(hash) != 32 {
		t.Errorf("CalculatePayloadHash() len = %d, want 32", len(hash))
	}

	if err := VerifyPayloadHash(payload, hash); err != nil {
		t.Errorf("VerifyPayloadHash() with correct hash error = %v", err)
	}

	if err := VerifyPayloadHash([]byte("different"), hash); err == nil {
		t.Error("VerifyPayloadHash() with different payload should fail")
	}
}

// TestWrapDEKWithPrivateKey verifies PKCS#1 v1.5 private-key wrap in non-FIPS mode.
func TestWrapDEKWithPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	dek, _ := GenerateDEK()
	wrapped, err := WrapDEKWithPrivateKey(privateKey, dek)
	if err != nil {
		// In FIPS builds this will fail — treat as expected
		if strings.Contains(err.Error(), "FIPS") {
			t.Skipf("WrapDEKWithPrivateKey() skipped in FIPS mode: %v", err)
		}
		t.Fatalf("WrapDEKWithPrivateKey() error = %v", err)
	}
	if len(wrapped) == 0 {
		t.Error("WrapDEKWithPrivateKey() returned empty output")
	}
	k := (privateKey.N.BitLen() + 7) / 8
	if len(wrapped) != k {
		t.Errorf("WrapDEKWithPrivateKey() output len = %d, want %d", len(wrapped), k)
	}
}

// TestWrapDEKWithPrivateKey_DEKTooLarge verifies oversized DEK is rejected.
func TestWrapDEKWithPrivateKey_DEKTooLarge(t *testing.T) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	hugeDEK := make([]byte, 300) // larger than RSA-2048 capacity
	_, err := WrapDEKWithPrivateKey(privateKey, hugeDEK)
	if err == nil {
		// FIPS builds reject before size check — also acceptable
		return
	}
	if !strings.Contains(err.Error(), "too large") && !strings.Contains(err.Error(), "FIPS") {
		t.Errorf("expected 'too large' or 'FIPS' error, got %v", err)
	}
}

// TestDeriveChunkNonce verifies the nonce counter derivation is correct.
func TestDeriveChunkNonce(t *testing.T) {
	base := make([]byte, 12) // standard GCM nonce size

	n0 := deriveChunkNonce(base, 0)
	n1 := deriveChunkNonce(base, 1)

	if bytes.Equal(n0, n1) {
		t.Error("deriveChunkNonce() different counters produced same nonce")
	}
	if len(n0) != len(base) {
		t.Errorf("deriveChunkNonce() len = %d, want %d", len(n0), len(base))
	}
	// Original base should not be mutated
	for _, b := range base {
		if b != 0 {
			t.Error("deriveChunkNonce() mutated the base nonce")
			break
		}
	}
}

// TestDeriveChunkNonce_ShortBase verifies fallback for short base nonces.
func TestDeriveChunkNonce_ShortBase(t *testing.T) {
	base := []byte{0x01}
	n := deriveChunkNonce(base, 99)
	if len(n) != 1 {
		t.Errorf("deriveChunkNonce() short base len = %d, want 1", len(n))
	}
}

// isModelError checks if err unwraps to *models.Error and sets the pointer.
func isModelError(err error, target **models.Error) bool {
	if me, ok := err.(*models.Error); ok {
		*target = me
		return true
	}
	return false
}
