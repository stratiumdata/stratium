package ztdf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// ===== RSA Key Generation Tests =====

func TestGenerateRSAKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{
			name:    "2048-bit key",
			bits:    2048,
			wantErr: false,
		},
		{
			name:    "4096-bit key",
			bits:    4096,
			wantErr: false,
		},
		{
			name:    "invalid small key size",
			bits:    512,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := GenerateRSAKeyPair(tt.bits)

			if tt.wantErr {
				if err == nil {
					t.Error("GenerateRSAKeyPair() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("GenerateRSAKeyPair() unexpected error: %v", err)
			}

			if privateKey == nil {
				t.Fatal("GenerateRSAKeyPair() returned nil private key")
			}

			if privateKey.N.BitLen() != tt.bits {
				t.Errorf("GenerateRSAKeyPair() key size = %d, want %d", privateKey.N.BitLen(), tt.bits)
			}

			if privateKey.PublicKey.N == nil {
				t.Error("GenerateRSAKeyPair() public key is nil")
			}
		})
	}
}

// ===== RSA Key Storage Tests =====

func TestSaveAndLoadRSAPrivateKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate key
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Save key
	filename := "test_rsa.key"
	err = SaveRSAPrivateKey(privateKey, tmpDir, filename)
	if err != nil {
		t.Fatalf("SaveRSAPrivateKey() error: %v", err)
	}

	// Verify file exists
	keyPath := filepath.Join(tmpDir, filename)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("SaveRSAPrivateKey() did not create file")
	}

	// Verify file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("SaveRSAPrivateKey() file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Load key
	loadedKey, err := GetRSAPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("GetRSAPrivateKeyFromFile() error: %v", err)
	}

	// Compare keys
	if !privateKey.Equal(loadedKey) {
		t.Error("GetRSAPrivateKeyFromFile() loaded key doesn't match original")
	}
}

func TestGetRSAPrivateKeyFromFile_InvalidFile(t *testing.T) {
	_, err := GetRSAPrivateKeyFromFile("/nonexistent/path/key.pem")
	if err == nil {
		t.Error("GetRSAPrivateKeyFromFile() expected error for non-existent file, got nil")
	}
}

func TestGetRSAPrivateKeyFromFile_InvalidPEM(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.key")

	// Write invalid PEM data
	err := os.WriteFile(keyPath, []byte("invalid PEM data"), 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	_, err = GetRSAPrivateKeyFromFile(keyPath)
	if err == nil {
		t.Error("GetRSAPrivateKeyFromFile() expected error for invalid PEM, got nil")
	}
}

func TestRSAPublicKeyToPEM(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	pem, err := RSAPublicKeyToPEM(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("RSAPublicKeyToPEM() error: %v", err)
	}

	if len(pem) == 0 {
		t.Fatal("RSAPublicKeyToPEM() returned empty PEM")
	}

	// Verify PEM format
	if !bytes.Contains([]byte(pem), []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Error("RSAPublicKeyToPEM() missing PEM header")
	}

	if !bytes.Contains([]byte(pem), []byte("-----END PUBLIC KEY-----")) {
		t.Error("RSAPublicKeyToPEM() missing PEM footer")
	}
}

// ===== RSA DEK Encryption/Decryption Tests =====

func TestEncryptDecryptDEKWithRSA(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Generate DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt DEK
	encryptedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, dek)
	if err != nil {
		t.Fatalf("EncryptDEKWithRSAPublicKey() error: %v", err)
	}

	if len(encryptedDEK) == 0 {
		t.Fatal("EncryptDEKWithRSAPublicKey() returned empty ciphertext")
	}

	// Decrypt DEK
	decryptedDEK, err := DecryptDEKWithRSAPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("DecryptDEKWithRSAPrivateKey() error: %v", err)
	}

	// Verify DEK matches
	if !bytes.Equal(dek, decryptedDEK) {
		t.Error("DecryptDEKWithRSAPrivateKey() decrypted DEK doesn't match original")
	}
}

func TestDecryptDEKWithRSAPrivateKey_InvalidCiphertext(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Try to decrypt invalid data
	invalidData := []byte("invalid ciphertext")
	_, err = DecryptDEKWithRSAPrivateKey(privateKey, invalidData)
	if err == nil {
		t.Error("DecryptDEKWithRSAPrivateKey() expected error for invalid ciphertext, got nil")
	}
}

func TestEncryptDecryptDEKWithRSA_MultipleRounds(t *testing.T) {
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Test multiple encryption/decryption rounds
	for i := 0; i < 5; i++ {
		dek, err := GenerateDEK()
		if err != nil {
			t.Fatalf("Round %d: Failed to generate DEK: %v", i, err)
		}

		encryptedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, dek)
		if err != nil {
			t.Fatalf("Round %d: Failed to encrypt DEK: %v", i, err)
		}

		decryptedDEK, err := DecryptDEKWithRSAPrivateKey(privateKey, encryptedDEK)
		if err != nil {
			t.Fatalf("Round %d: Failed to decrypt DEK: %v", i, err)
		}

		if !bytes.Equal(dek, decryptedDEK) {
			t.Errorf("Round %d: Decrypted DEK doesn't match original", i)
		}
	}
}

// ===== DEK Generation Tests =====

func TestGenerateDEK(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() error: %v", err)
	}

	if len(dek) != AESKeySize {
		t.Errorf("GenerateDEK() key size = %d, want %d", len(dek), AESKeySize)
	}

	// Verify randomness - generate multiple DEKs and ensure they're different
	dek2, err := GenerateDEK()
	if err != nil {
		t.Fatalf("GenerateDEK() second call error: %v", err)
	}

	if bytes.Equal(dek, dek2) {
		t.Error("GenerateDEK() generated identical keys (should be random)")
	}
}

// ===== Payload Encryption/Decryption Tests =====

func TestEncryptDecryptPayload(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "small payload",
			plaintext: []byte("Hello, World!"),
		},
		{
			name:      "empty payload",
			plaintext: []byte(""),
		},
		{
			name:      "large payload",
			plaintext: bytes.Repeat([]byte("A"), 10000),
		},
		{
			name:      "binary payload",
			plaintext: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate DEK
			dek, err := GenerateDEK()
			if err != nil {
				t.Fatalf("Failed to generate DEK: %v", err)
			}

			// Encrypt payload
			ciphertext, iv, err := EncryptPayload(tt.plaintext, dek)
			if err != nil {
				t.Fatalf("EncryptPayload() error: %v", err)
			}

			if len(iv) == 0 {
				t.Fatal("EncryptPayload() returned empty IV")
			}

			// Decrypt payload
			decrypted, err := DecryptPayload(ciphertext, dek, iv)
			if err != nil {
				t.Fatalf("DecryptPayload() error: %v", err)
			}

			// Verify plaintext matches
			if !bytes.Equal(tt.plaintext, decrypted) {
				t.Errorf("DecryptPayload() decrypted text doesn't match original")
			}
		})
	}
}

func TestDecryptPayload_InvalidKey(t *testing.T) {
	plaintext := []byte("test data")
	dek, _ := GenerateDEK()
	ciphertext, iv, err := EncryptPayload(plaintext, dek)
	if err != nil {
		t.Fatalf("EncryptPayload() error: %v", err)
	}

	// Try to decrypt with wrong key
	wrongDEK, _ := GenerateDEK()
	_, err = DecryptPayload(ciphertext, wrongDEK, iv)
	if err == nil {
		t.Error("DecryptPayload() expected error for wrong key, got nil")
	}
}

func TestDecryptPayload_InvalidIV(t *testing.T) {
	plaintext := []byte("test data")
	dek, _ := GenerateDEK()
	ciphertext, _, err := EncryptPayload(plaintext, dek)
	if err != nil {
		t.Fatalf("EncryptPayload() error: %v", err)
	}

	// Try to decrypt with wrong IV
	wrongIV := make([]byte, 12)
	_, err = DecryptPayload(ciphertext, dek, wrongIV)
	if err == nil {
		t.Error("DecryptPayload() expected error for wrong IV, got nil")
	}
}

func TestEncryptPayload_InvalidDEK(t *testing.T) {
	plaintext := []byte("test data")
	invalidDEK := []byte("short")

	_, _, err := EncryptPayload(plaintext, invalidDEK)
	if err == nil {
		t.Error("EncryptPayload() expected error for invalid DEK, got nil")
	}
}

// ===== Policy Binding Tests =====

func TestCalculatePolicyBinding(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	policy := "eyJhY3Rpb24iOiJyZWFkIiwicmVzb3VyY2UiOiJ0ZXN0In0="

	binding := CalculatePolicyBinding(dek, policy)

	if len(binding) == 0 {
		t.Fatal("CalculatePolicyBinding() returned empty binding")
	}

	// Verify consistency - same inputs should produce same output
	binding2 := CalculatePolicyBinding(dek, policy)
	if binding != binding2 {
		t.Error("CalculatePolicyBinding() not deterministic")
	}

	// Verify different policy produces different binding
	differentPolicy := "eyJhY3Rpb24iOiJ3cml0ZSIsInJlc291cmNlIjoidGVzdCJ9"
	differentBinding := CalculatePolicyBinding(dek, differentPolicy)
	if binding == differentBinding {
		t.Error("CalculatePolicyBinding() same binding for different policies")
	}
}

func TestVerifyPolicyBinding(t *testing.T) {
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	policy := "eyJhY3Rpb24iOiJyZWFkIiwicmVzb3VyY2UiOiJ0ZXN0In0="
	binding := CalculatePolicyBinding(dek, policy)

	tests := []struct {
		name         string
		dek          []byte
		policy       string
		expectedHash string
		wantErr      bool
	}{
		{
			name:         "valid binding",
			dek:          dek,
			policy:       policy,
			expectedHash: binding,
			wantErr:      false,
		},
		{
			name:         "invalid hash",
			dek:          dek,
			policy:       policy,
			expectedHash: "invalid-hash",
			wantErr:      true,
		},
		{
			name:         "tampered policy",
			dek:          dek,
			policy:       "eyJhY3Rpb24iOiJ3cml0ZSIsInJlc291cmNlIjoidGVzdCJ9",
			expectedHash: binding,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPolicyBinding(tt.dek, tt.policy, tt.expectedHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPolicyBinding() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ===== Payload Hash Tests =====

func TestCalculatePayloadHash(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "simple text",
			payload: []byte("Hello, World!"),
		},
		{
			name:    "empty payload",
			payload: []byte(""),
		},
		{
			name:    "binary data",
			payload: []byte{0x00, 0xFF, 0x01, 0xFE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := CalculatePayloadHash(tt.payload)

			if len(hash) != 32 {
				t.Errorf("CalculatePayloadHash() hash length = %d, want 32 (SHA-256)", len(hash))
			}

			// Verify consistency
			hash2 := CalculatePayloadHash(tt.payload)
			if !bytes.Equal(hash, hash2) {
				t.Error("CalculatePayloadHash() not deterministic")
			}

			// Verify different payloads produce different hashes
			if len(tt.payload) > 0 {
				modifiedPayload := append([]byte{}, tt.payload...)
				modifiedPayload[0] ^= 0xFF
				differentHash := CalculatePayloadHash(modifiedPayload)
				if bytes.Equal(hash, differentHash) {
					t.Error("CalculatePayloadHash() same hash for different payloads")
				}
			}
		})
	}
}

func TestVerifyPayloadHash(t *testing.T) {
	payload := []byte("test payload data")
	correctHash := CalculatePayloadHash(payload)
	wrongHash := make([]byte, 32)

	tests := []struct {
		name         string
		payload      []byte
		expectedHash []byte
		wantErr      bool
	}{
		{
			name:         "valid hash",
			payload:      payload,
			expectedHash: correctHash,
			wantErr:      false,
		},
		{
			name:         "invalid hash",
			payload:      payload,
			expectedHash: wrongHash,
			wantErr:      true,
		},
		{
			name:         "tampered payload",
			payload:      []byte("tampered data"),
			expectedHash: correctHash,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPayloadHash(tt.payload, tt.expectedHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPayloadHash() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ===== Integration Tests =====

func TestRSAFullEncryptionFlow(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Original plaintext
	originalPlaintext := []byte("This is a secret message!")

	// Generate DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt payload with DEK
	ciphertext, iv, err := EncryptPayload(originalPlaintext, dek)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %v", err)
	}

	// Encrypt DEK with RSA public key
	encryptedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, dek)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK: %v", err)
	}

	// === Decryption process ===

	// Decrypt DEK with RSA private key
	decryptedDEK, err := DecryptDEKWithRSAPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("Failed to decrypt DEK: %v", err)
	}

	// Decrypt payload with decrypted DEK
	decryptedPlaintext, err := DecryptPayload(ciphertext, decryptedDEK, iv)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(originalPlaintext, decryptedPlaintext) {
		t.Error("Full encryption flow: decrypted plaintext doesn't match original")
	}
}

func TestECCFullEncryptionFlow(t *testing.T) {
	// Generate ECC key pair
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate ECC key pair: %v", err)
	}

	// Original plaintext
	originalPlaintext := []byte("This is a secret message encrypted with ECC!")

	// Generate DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt payload with DEK
	ciphertext, iv, err := EncryptPayload(originalPlaintext, dek)
	if err != nil {
		t.Fatalf("Failed to encrypt payload: %v", err)
	}

	// Encrypt DEK with ECC public key
	encryptedDEK, err := EncryptDEKWithECCPublicKey(privateKey.PublicKey(), dek)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK: %v", err)
	}

	// Calculate policy binding
	policy := "eyJhY3Rpb24iOiJyZWFkIn0="
	policyBinding := CalculatePolicyBinding(dek, policy)

	// Calculate payload hash
	payloadHash := CalculatePayloadHash(originalPlaintext)

	// === Decryption process ===

	// Decrypt DEK with ECC private key
	decryptedDEK, err := DecryptDEKWithECCPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("Failed to decrypt DEK: %v", err)
	}

	// Verify policy binding
	err = VerifyPolicyBinding(decryptedDEK, policy, policyBinding)
	if err != nil {
		t.Fatalf("Policy binding verification failed: %v", err)
	}

	// Decrypt payload with decrypted DEK
	decryptedPlaintext, err := DecryptPayload(ciphertext, decryptedDEK, iv)
	if err != nil {
		t.Fatalf("Failed to decrypt payload: %v", err)
	}

	// Verify payload hash
	err = VerifyPayloadHash(decryptedPlaintext, payloadHash)
	if err != nil {
		t.Fatalf("Payload hash verification failed: %v", err)
	}

	// Verify plaintext matches
	if !bytes.Equal(originalPlaintext, decryptedPlaintext) {
		t.Error("Full encryption flow: decrypted plaintext doesn't match original")
	}
}
