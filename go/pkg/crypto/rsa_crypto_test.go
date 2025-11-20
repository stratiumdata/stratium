package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// Test helper to generate a test key pair
func generateTestKeyPair(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}
	return privateKey
}

// Benchmark helper to generate a test key pair
func generateBenchmarkKeyPair(b *testing.B, bits int) *rsa.PrivateKey {
	b.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		b.Fatalf("Failed to generate test key pair: %v", err)
	}
	return privateKey
}

func TestGenerateRSAKeyPair(t *testing.T) {
	t.Run("generate 2048-bit key", func(t *testing.T) {
		privateKey, err := GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if privateKey == nil {
			t.Fatal("Expected private key, got nil")
		}

		if privateKey.N.BitLen() != 2048 {
			t.Errorf("Expected 2048-bit key, got %d-bit", privateKey.N.BitLen())
		}

		// Verify public key is present
		if privateKey.PublicKey.N == nil {
			t.Error("Public key not generated")
		}
	})

	t.Run("generate 4096-bit key", func(t *testing.T) {
		privateKey, err := GenerateRSAKeyPair(4096)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if privateKey.N.BitLen() != 4096 {
			t.Errorf("Expected 4096-bit key, got %d-bit", privateKey.N.BitLen())
		}
	})

	t.Run("generate with invalid bit size", func(t *testing.T) {
		// RSA key sizes below 512 bits are typically rejected
		_, err := GenerateRSAKeyPair(128)
		if err == nil {
			t.Error("Expected error for too small key size, got nil")
		}
	})

	t.Run("generate multiple keys are unique", func(t *testing.T) {
		key1, err := GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate first key: %v", err)
		}

		key2, err := GenerateRSAKeyPair(2048)
		if err != nil {
			t.Fatalf("Failed to generate second key: %v", err)
		}

		// Keys should be different
		if key1.N.Cmp(key2.N) == 0 {
			t.Error("Generated keys are identical (should be unique)")
		}
	})
}

func TestEncryptWithPublicKey(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)
	publicKey := &privateKey.PublicKey

	t.Run("encrypt simple text", func(t *testing.T) {
		plaintext := []byte("Hello, World!")
		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)

		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if len(ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}

		// Ciphertext should be different from plaintext
		if string(ciphertext) == string(plaintext) {
			t.Error("Ciphertext should differ from plaintext")
		}
	})

	t.Run("encrypt empty data", func(t *testing.T) {
		plaintext := []byte("")
		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)

		if err != nil {
			t.Fatalf("Expected no error for empty data, got: %v", err)
		}

		if ciphertext == nil {
			t.Error("Expected non-nil ciphertext")
		}
	})

	t.Run("encrypt produces different ciphertext each time", func(t *testing.T) {
		plaintext := []byte("Same message")

		ciphertext1, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("First encryption failed: %v", err)
		}

		ciphertext2, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("Second encryption failed: %v", err)
		}

		// Due to random padding, ciphertexts should differ
		if string(ciphertext1) == string(ciphertext2) {
			t.Error("Expected different ciphertexts (OAEP uses random padding)")
		}
	})

	t.Run("encrypt large data within limits", func(t *testing.T) {
		// RSA-OAEP with 2048-bit key and SHA-256 can encrypt up to 190 bytes
		// (2048/8 - 2*32 - 2 = 256 - 64 - 2 = 190)
		plaintext := make([]byte, 190)
		for i := range plaintext {
			plaintext[i] = byte(i % 256)
		}

		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("Expected no error for max size data, got: %v", err)
		}

		if len(ciphertext) == 0 {
			t.Error("Expected non-empty ciphertext")
		}
	})

	t.Run("encrypt data too large", func(t *testing.T) {
		// Data larger than key size - padding should fail
		plaintext := make([]byte, 300)
		_, err := EncryptWithPublicKey(publicKey, plaintext)

		if err == nil {
			t.Error("Expected error for oversized data, got nil")
		}
	})

	t.Run("encrypt with non-RSA key", func(t *testing.T) {
		// Create an ECDSA key (non-RSA)
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		plaintext := []byte("test data")
		_, err = EncryptWithPublicKey(&ecdsaKey.PublicKey, plaintext)

		if err == nil {
			t.Error("Expected error for non-RSA key, got nil")
		}

		if err != nil && err.Error() != "public key is not RSA type" {
			t.Errorf("Expected 'public key is not RSA type' error, got: %v", err)
		}
	})

	t.Run("encrypt with nil key", func(t *testing.T) {
		plaintext := []byte("test data")
		_, err := EncryptWithPublicKey(nil, plaintext)

		if err == nil {
			t.Error("Expected error for nil key, got nil")
		}
	})
}

func TestDecryptWithPrivateKey(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)
	publicKey := &privateKey.PublicKey

	t.Run("decrypt valid ciphertext", func(t *testing.T) {
		plaintext := []byte("Hello, Decryption!")

		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		decrypted, err := DecryptWithPrivateKey(privateKey, ciphertext)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Expected %s, got %s", plaintext, decrypted)
		}
	})

	t.Run("decrypt empty ciphertext", func(t *testing.T) {
		_, err := DecryptWithPrivateKey(privateKey, []byte(""))

		if err == nil {
			t.Error("Expected error for empty ciphertext, got nil")
		}
	})

	t.Run("decrypt invalid ciphertext", func(t *testing.T) {
		invalidCiphertext := []byte("this is not valid ciphertext")

		_, err := DecryptWithPrivateKey(privateKey, invalidCiphertext)
		if err == nil {
			t.Error("Expected error for invalid ciphertext, got nil")
		}
	})

	t.Run("decrypt with wrong key", func(t *testing.T) {
		plaintext := []byte("Secret message")

		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Generate a different key
		wrongKey := generateTestKeyPair(t, 2048)

		_, err = DecryptWithPrivateKey(wrongKey, ciphertext)
		if err == nil {
			t.Error("Expected error when decrypting with wrong key, got nil")
		}
	})

	t.Run("decrypt with non-RSA key", func(t *testing.T) {
		// Create an ECDSA key (non-RSA)
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		ciphertext := []byte("dummy ciphertext")
		_, err = DecryptWithPrivateKey(ecdsaKey, ciphertext)

		if err == nil {
			t.Error("Expected error for non-RSA key, got nil")
		}

		if err != nil && err.Error() != "private key is not RSA type" {
			t.Errorf("Expected 'private key is not RSA type' error, got: %v", err)
		}
	})

	t.Run("decrypt with nil key", func(t *testing.T) {
		ciphertext := []byte("dummy ciphertext")
		_, err := DecryptWithPrivateKey(nil, ciphertext)

		if err == nil {
			t.Error("Expected error for nil key, got nil")
		}
	})

	t.Run("decrypt corrupted ciphertext", func(t *testing.T) {
		plaintext := []byte("Original message")

		ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}

		// Corrupt the ciphertext
		if len(ciphertext) > 0 {
			ciphertext[0] ^= 0xFF
		}

		_, err = DecryptWithPrivateKey(privateKey, ciphertext)
		if err == nil {
			t.Error("Expected error for corrupted ciphertext, got nil")
		}
	})
}

func TestSignWithPrivateKey(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)

	t.Run("sign data", func(t *testing.T) {
		data := []byte("Data to sign")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Expected non-empty signature")
		}

		// Signature length should match key size
		expectedLen := privateKey.Size()
		if len(signature) != expectedLen {
			t.Errorf("Expected signature length %d, got %d", expectedLen, len(signature))
		}
	})

	t.Run("sign empty data", func(t *testing.T) {
		data := []byte("")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Expected no error for empty data, got: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Expected non-empty signature even for empty data")
		}
	})

	t.Run("sign produces consistent signature", func(t *testing.T) {
		data := []byte("Consistent message")

		signature1, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("First signing failed: %v", err)
		}

		signature2, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Second signing failed: %v", err)
		}

		// PKCS1v15 signatures should be deterministic for same input
		if string(signature1) != string(signature2) {
			t.Error("Expected consistent signatures for same data")
		}
	})

	t.Run("sign large data", func(t *testing.T) {
		data := make([]byte, 1024*1024) // 1MB
		for i := range data {
			data[i] = byte(i % 256)
		}

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Expected no error for large data, got: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Expected non-empty signature")
		}
	})

	t.Run("sign with non-RSA key", func(t *testing.T) {
		// Create an ECDSA key (non-RSA)
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		data := []byte("test data")
		_, err = SignWithPrivateKey(ecdsaKey, data)

		if err == nil {
			t.Error("Expected error for non-RSA key, got nil")
		}

		if err != nil && err.Error() != "private key is not RSA type" {
			t.Errorf("Expected 'private key is not RSA type' error, got: %v", err)
		}
	})

	t.Run("sign with nil key", func(t *testing.T) {
		data := []byte("test data")
		_, err := SignWithPrivateKey(nil, data)

		if err == nil {
			t.Error("Expected error for nil key, got nil")
		}
	})

	t.Run("different data produces different signatures", func(t *testing.T) {
		data1 := []byte("Message one")
		data2 := []byte("Message two")

		signature1, err := SignWithPrivateKey(privateKey, data1)
		if err != nil {
			t.Fatalf("First signing failed: %v", err)
		}

		signature2, err := SignWithPrivateKey(privateKey, data2)
		if err != nil {
			t.Fatalf("Second signing failed: %v", err)
		}

		if string(signature1) == string(signature2) {
			t.Error("Different data should produce different signatures")
		}
	})
}

func TestVerifySignature(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)
	publicKey := &privateKey.PublicKey

	t.Run("verify valid signature", func(t *testing.T) {
		data := []byte("Data to verify")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		err = VerifySignature(publicKey, data, signature)
		if err != nil {
			t.Errorf("Expected valid signature, got error: %v", err)
		}
	})

	t.Run("verify signature for empty data", func(t *testing.T) {
		data := []byte("")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		err = VerifySignature(publicKey, data, signature)
		if err != nil {
			t.Errorf("Expected valid signature for empty data, got error: %v", err)
		}
	})

	t.Run("verify invalid signature", func(t *testing.T) {
		data := []byte("Original data")
		invalidSignature := []byte("this is not a valid signature")

		err := VerifySignature(publicKey, data, invalidSignature)
		if err == nil {
			t.Error("Expected error for invalid signature, got nil")
		}
	})

	t.Run("verify signature with modified data", func(t *testing.T) {
		originalData := []byte("Original data")

		signature, err := SignWithPrivateKey(privateKey, originalData)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		modifiedData := []byte("Modified data")
		err = VerifySignature(publicKey, modifiedData, signature)
		if err == nil {
			t.Error("Expected error when verifying with modified data, got nil")
		}
	})

	t.Run("verify with wrong public key", func(t *testing.T) {
		data := []byte("Secret data")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Generate a different key pair
		wrongKey := generateTestKeyPair(t, 2048)
		wrongPublicKey := &wrongKey.PublicKey

		err = VerifySignature(wrongPublicKey, data, signature)
		if err == nil {
			t.Error("Expected error when verifying with wrong key, got nil")
		}
	})

	t.Run("verify corrupted signature", func(t *testing.T) {
		data := []byte("Data to sign")

		signature, err := SignWithPrivateKey(privateKey, data)
		if err != nil {
			t.Fatalf("Signing failed: %v", err)
		}

		// Corrupt the signature
		if len(signature) > 0 {
			signature[0] ^= 0xFF
		}

		err = VerifySignature(publicKey, data, signature)
		if err == nil {
			t.Error("Expected error for corrupted signature, got nil")
		}
	})

	t.Run("verify with non-RSA key", func(t *testing.T) {
		// Create an ECDSA key (non-RSA)
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Failed to generate ECDSA key: %v", err)
		}

		data := []byte("test data")
		signature := []byte("dummy signature")
		err = VerifySignature(&ecdsaKey.PublicKey, data, signature)

		if err == nil {
			t.Error("Expected error for non-RSA key, got nil")
		}

		if err != nil && err.Error() != "public key is not RSA type" {
			t.Errorf("Expected 'public key is not RSA type' error, got: %v", err)
		}
	})

	t.Run("verify with nil key", func(t *testing.T) {
		data := []byte("test data")
		signature := []byte("dummy signature")
		err := VerifySignature(nil, data, signature)

		if err == nil {
			t.Error("Expected error for nil key, got nil")
		}
	})

	t.Run("verify empty signature", func(t *testing.T) {
		data := []byte("test data")
		emptySignature := []byte("")

		err := VerifySignature(publicKey, data, emptySignature)
		if err == nil {
			t.Error("Expected error for empty signature, got nil")
		}
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)
	publicKey := &privateKey.PublicKey

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("Hello, World!")},
		{"empty", []byte("")},
		{"single byte", []byte("A")},
		{"special characters", []byte("!@#$%^&*()_+-=[]{}|;:',.<>?/`~")},
		{"unicode", []byte("Hello 世界 🌍")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"max size", make([]byte, 190)}, // Max for 2048-bit RSA with OAEP and SHA-256
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill max size with test data
			if len(tc.plaintext) == 190 {
				for i := range tc.plaintext {
					tc.plaintext[i] = byte(i % 256)
				}
			}

			// Encrypt
			ciphertext, err := EncryptWithPublicKey(publicKey, tc.plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Decrypt
			decrypted, err := DecryptWithPrivateKey(privateKey, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Verify round-trip
			if string(decrypted) != string(tc.plaintext) {
				t.Errorf("Round-trip failed: expected %v, got %v", tc.plaintext, decrypted)
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	privateKey := generateTestKeyPair(t, 2048)
	publicKey := &privateKey.PublicKey

	testCases := []struct {
		name string
		data []byte
	}{
		{"simple text", []byte("Hello, World!")},
		{"empty", []byte("")},
		{"single byte", []byte("A")},
		{"special characters", []byte("!@#$%^&*()_+-=[]{}|;:',.<>?/`~")},
		{"unicode", []byte("Hello 世界 🌍")},
		{"binary data", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}},
		{"large data", make([]byte, 10000)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill large data with test pattern
			if len(tc.data) == 10000 {
				for i := range tc.data {
					tc.data[i] = byte(i % 256)
				}
			}

			// Sign
			signature, err := SignWithPrivateKey(privateKey, tc.data)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			// Verify
			err = VerifySignature(publicKey, tc.data, signature)
			if err != nil {
				t.Errorf("Verification failed: %v", err)
			}
		})
	}
}

func TestDifferentKeySizes(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}

	for _, size := range keySizes {
		t.Run(string(rune(size))+" bit key", func(t *testing.T) {
			privateKey, err := GenerateRSAKeyPair(size)
			if err != nil {
				t.Fatalf("Failed to generate %d-bit key: %v", size, err)
			}

			publicKey := &privateKey.PublicKey
			plaintext := []byte("Test message")

			// Test encryption/decryption
			ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := DecryptWithPrivateKey(privateKey, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(decrypted) != string(plaintext) {
				t.Errorf("Round-trip failed for %d-bit key", size)
			}

			// Test signing/verification
			signature, err := SignWithPrivateKey(privateKey, plaintext)
			if err != nil {
				t.Fatalf("Signing failed: %v", err)
			}

			err = VerifySignature(publicKey, plaintext, signature)
			if err != nil {
				t.Errorf("Verification failed for %d-bit key: %v", size, err)
			}
		})
	}
}

// Benchmark tests

func BenchmarkGenerateRSAKeyPair2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateRSAKeyPair(2048)
	}
}

func BenchmarkEncryptWithPublicKey(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	publicKey := &privateKey.PublicKey
	plaintext := []byte("Benchmark data for encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptWithPublicKey(publicKey, plaintext)
	}
}

func BenchmarkDecryptWithPrivateKey(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	publicKey := &privateKey.PublicKey
	plaintext := []byte("Benchmark data for decryption")

	ciphertext, err := EncryptWithPublicKey(publicKey, plaintext)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptWithPrivateKey(privateKey, ciphertext)
	}
}

func BenchmarkSignWithPrivateKey(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	data := []byte("Benchmark data for signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignWithPrivateKey(privateKey, data)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	publicKey := &privateKey.PublicKey
	data := []byte("Benchmark data for verification")

	signature, err := SignWithPrivateKey(privateKey, data)
	if err != nil {
		b.Fatalf("Setup failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(publicKey, data, signature)
	}
}

func BenchmarkEncryptDecryptRoundTrip(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	publicKey := &privateKey.PublicKey
	plaintext := []byte("Benchmark round-trip data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ciphertext, _ := EncryptWithPublicKey(publicKey, plaintext)
		_, _ = DecryptWithPrivateKey(privateKey, ciphertext)
	}
}

func BenchmarkSignVerifyRoundTrip(b *testing.B) {
	privateKey := generateBenchmarkKeyPair(b, 2048)
	publicKey := &privateKey.PublicKey
	data := []byte("Benchmark sign-verify data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		signature, _ := SignWithPrivateKey(privateKey, data)
		_ = VerifySignature(publicKey, data, signature)
	}
}