package kem

import (
	"testing"

	"stratium/pkg/security/encryption"
)

func TestNewKEMProvider(t *testing.T) {
	tests := []struct {
		name    string
		alg     encryption.Algorithm
		wantErr bool
	}{
		{
			name:    "KYBER512",
			alg:     encryption.KYBER512,
			wantErr: false,
		},
		{
			name:    "KYBER768",
			alg:     encryption.KYBER768,
			wantErr: false,
		},
		{
			name:    "KYBER1024",
			alg:     encryption.KYBER1024,
			wantErr: false,
		},
		{
			name:    "Invalid KEM algorithm",
			alg:     encryption.RSA2048,
			wantErr: true,
		},
		{
			name:    "Empty algorithm",
			alg:     encryption.Algorithm(""),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewKEMProvider(tt.alg)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewKEMProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if provider == nil {
					t.Error("Expected non-nil provider for valid algorithm")
				}
			}
		})
	}
}

func TestKEMProviders_BasicFunctionality(t *testing.T) {
	algorithms := []encryption.Algorithm{
		encryption.KYBER512,
		encryption.KYBER768,
		encryption.KYBER1024,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			provider, err := NewKEMProvider(alg)
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}

			// Test that provider implements required interface
			if provider == nil {
				t.Fatal("Provider is nil")
			}

			// Test EncapsulateTo
			seed := make([]byte, 32)
			for i := range seed {
				seed[i] = byte(i)
			}

			ciphertext, sharedSecret := provider.EncapsulateTo(seed)
			if len(ciphertext) == 0 {
				t.Error("Expected non-empty ciphertext")
			}
			if len(sharedSecret) == 0 {
				t.Error("Expected non-empty shared secret")
			}

			// Test DecapsulateTo
			decapsulatedSecret := provider.DecapsulateTo(ciphertext)
			if len(decapsulatedSecret) == 0 {
				t.Error("Expected non-empty decapsulated secret")
			}

			// Verify decapsulated secret matches original
			if len(decapsulatedSecret) != len(sharedSecret) {
				t.Errorf("Decapsulated secret length %d != original length %d",
					len(decapsulatedSecret), len(sharedSecret))
			}
		})
	}
}

func TestKEMProvider_EncryptDecrypt(t *testing.T) {
	algorithms := []encryption.Algorithm{
		encryption.KYBER512,
		encryption.KYBER768,
		encryption.KYBER1024,
	}

	plaintext := []byte("Hello, World! This is a test message.")

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			provider, err := NewKEMProvider(alg)
			if err != nil {
				t.Fatalf("Failed to create provider: %v", err)
			}

			// Generate key pair - EncapsulateTo returns ciphertext and shared secret
			seed := make([]byte, 32)
			_, sharedSecret := provider.EncapsulateTo(seed)

			// Encrypt using the shared secret as the key
			ciphertext, err := provider.Encrypt(sharedSecret, plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			if len(ciphertext) == 0 {
				t.Error("Expected non-empty ciphertext")
			}

			// Decrypt using the shared secret as the key
			decrypted, err := provider.Decrypt(sharedSecret, ciphertext)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			// Verify
			if string(decrypted) != string(plaintext) {
				t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s",
					plaintext, decrypted)
			}
		})
	}
}

// Benchmark tests
func BenchmarkKyber512_EncapsulateTo(b *testing.B) {
	provider, _ := NewKEMProvider(encryption.KYBER512)
	seed := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.EncapsulateTo(seed)
	}
}

func BenchmarkKyber768_EncapsulateTo(b *testing.B) {
	provider, _ := NewKEMProvider(encryption.KYBER768)
	seed := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.EncapsulateTo(seed)
	}
}

func BenchmarkKyber1024_EncapsulateTo(b *testing.B) {
	provider, _ := NewKEMProvider(encryption.KYBER1024)
	seed := make([]byte, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.EncapsulateTo(seed)
	}
}

func BenchmarkKyber768_Encrypt(b *testing.B) {
	provider, _ := NewKEMProvider(encryption.KYBER768)
	seed := make([]byte, 32)
	_, sharedSecret := provider.EncapsulateTo(seed)
	plaintext := []byte("Benchmark message for encryption testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Encrypt(sharedSecret, plaintext)
	}
}

func BenchmarkKyber768_Decrypt(b *testing.B) {
	provider, _ := NewKEMProvider(encryption.KYBER768)
	seed := make([]byte, 32)
	_, sharedSecret := provider.EncapsulateTo(seed)
	plaintext := []byte("Benchmark message for decryption testing")
	ciphertext, _ := provider.Encrypt(sharedSecret, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Decrypt(sharedSecret, ciphertext)
	}
}
