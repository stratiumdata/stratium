package ztdf

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateECCKeyPair_P256(t *testing.T) {
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate P-256 key pair: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Private key is nil")
	}

	publicKey := privateKey.PublicKey()
	if publicKey == nil {
		t.Fatal("Public key is nil")
	}
}

func TestGenerateECCKeyPair_P384(t *testing.T) {
	privateKey, err := GenerateECCKeyPair("P-384")
	if err != nil {
		t.Fatalf("Failed to generate P-384 key pair: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Private key is nil")
	}

	publicKey := privateKey.PublicKey()
	if publicKey == nil {
		t.Fatal("Public key is nil")
	}
}

func TestGenerateECCKeyPair_UnsupportedCurve(t *testing.T) {
	_, err := GenerateECCKeyPair("P-521")
	if err == nil {
		t.Fatal("Expected error for unsupported curve, got nil")
	}
}

func TestSaveAndLoadECCPrivateKey(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Generate key
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Save key
	filename := "test.key"
	err = SaveECCPrivateKey(privateKey, tmpDir, filename)
	if err != nil {
		t.Fatalf("Failed to save private key: %v", err)
	}

	// Verify file exists
	keyPath := filepath.Join(tmpDir, filename)
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatal("Private key file was not created")
	}

	// Load key
	loadedKey, err := GetECCPrivateKeyFromFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to load private key: %v", err)
	}

	// Compare public keys (private keys don't have a direct comparison method)
	origPubBytes := privateKey.PublicKey().Bytes()
	loadedPubBytes := loadedKey.PublicKey().Bytes()

	if !bytes.Equal(origPubBytes, loadedPubBytes) {
		t.Fatal("Loaded key public key doesn't match original")
	}
}

func TestECCPublicKeyToPEM(t *testing.T) {
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	pem, err := ECCPublicKeyToPEM(privateKey.PublicKey())
	if err != nil {
		t.Fatalf("Failed to convert public key to PEM: %v", err)
	}

	if len(pem) == 0 {
		t.Fatal("PEM string is empty")
	}

	// Verify PEM format
	if !bytes.Contains([]byte(pem), []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatal("PEM doesn't contain expected header")
	}

	if !bytes.Contains([]byte(pem), []byte("-----END PUBLIC KEY-----")) {
		t.Fatal("PEM doesn't contain expected footer")
	}
}

func TestEncryptDecryptDEKWithECC_P256(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Generate a DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt DEK
	encryptedDEK, err := EncryptDEKWithECCPublicKey(privateKey.PublicKey(), dek)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK: %v", err)
	}

	if len(encryptedDEK) == 0 {
		t.Fatal("Encrypted DEK is empty")
	}

	// Decrypt DEK
	decryptedDEK, err := DecryptDEKWithECCPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("Failed to decrypt DEK: %v", err)
	}

	// Verify DEK matches
	if !bytes.Equal(dek, decryptedDEK) {
		t.Fatal("Decrypted DEK doesn't match original")
	}
}

func TestEncryptDecryptDEKWithECC_P384(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateECCKeyPair("P-384")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Generate a DEK
	dek, err := GenerateDEK()
	if err != nil {
		t.Fatalf("Failed to generate DEK: %v", err)
	}

	// Encrypt DEK
	encryptedDEK, err := EncryptDEKWithECCPublicKey(privateKey.PublicKey(), dek)
	if err != nil {
		t.Fatalf("Failed to encrypt DEK: %v", err)
	}

	if len(encryptedDEK) == 0 {
		t.Fatal("Encrypted DEK is empty")
	}

	// Decrypt DEK
	decryptedDEK, err := DecryptDEKWithECCPrivateKey(privateKey, encryptedDEK)
	if err != nil {
		t.Fatalf("Failed to decrypt DEK: %v", err)
	}

	// Verify DEK matches
	if !bytes.Equal(dek, decryptedDEK) {
		t.Fatal("Decrypted DEK doesn't match original")
	}
}

func TestDecryptDEKWithECCPrivateKey_InvalidFormat(t *testing.T) {
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Try to decrypt invalid data
	invalidData := []byte{1, 2, 3}
	_, err = DecryptDEKWithECCPrivateKey(privateKey, invalidData)
	if err == nil {
		t.Fatal("Expected error for invalid encrypted DEK format, got nil")
	}
}

func TestEncryptDecryptDEKWithECC_MultipleRounds(t *testing.T) {
	// Generate key pair
	privateKey, err := GenerateECCKeyPair("P-256")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test multiple encryption/decryption rounds
	for i := 0; i < 10; i++ {
		dek, err := GenerateDEK()
		if err != nil {
			t.Fatalf("Round %d: Failed to generate DEK: %v", i, err)
		}

		encryptedDEK, err := EncryptDEKWithECCPublicKey(privateKey.PublicKey(), dek)
		if err != nil {
			t.Fatalf("Round %d: Failed to encrypt DEK: %v", i, err)
		}

		decryptedDEK, err := DecryptDEKWithECCPrivateKey(privateKey, encryptedDEK)
		if err != nil {
			t.Fatalf("Round %d: Failed to decrypt DEK: %v", i, err)
		}

		if !bytes.Equal(dek, decryptedDEK) {
			t.Fatalf("Round %d: Decrypted DEK doesn't match original", i)
		}
	}
}