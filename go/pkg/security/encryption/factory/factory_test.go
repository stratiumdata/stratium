package factory

import (
	"testing"

	"stratium/pkg/security/encryption"
)

func TestNewEncryptionProvider(t *testing.T) {
	tests := []struct {
		name    string
		alg     encryption.Algorithm
		wantErr bool
	}{
		// KEM algorithms
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
		// RSA algorithms
		{
			name:    "RSA2048",
			alg:     encryption.RSA2048,
			wantErr: false,
		},
		{
			name:    "RSA3072",
			alg:     encryption.RSA3072,
			wantErr: false,
		},
		{
			name:    "RSA4096",
			alg:     encryption.RSA4096,
			wantErr: false,
		},
		// ECC algorithms
		{
			name:    "P256",
			alg:     encryption.ECC_P256,
			wantErr: false,
		},
		{
			name:    "P384",
			alg:     encryption.ECC_P384,
			wantErr: false,
		},
		{
			name:    "P521",
			alg:     encryption.ECC_P521,
			wantErr: false,
		},
		// Invalid
		{
			name:    "Invalid algorithm",
			alg:     encryption.Algorithm("INVALID"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewEncryptionProvider(tt.alg)

			if (err != nil) != tt.wantErr {
				t.Errorf("NewEncryptionProvider() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if provider == nil {
					t.Error("Expected non-nil provider")
				}

				// Test GetAlgorithm
				if provider.GetAlgorithm() != tt.alg {
					t.Errorf("GetAlgorithm() = %v, want %v", provider.GetAlgorithm(), tt.alg)
				}
			}
		})
	}
}

func TestGetAlgorithmType(t *testing.T) {
	tests := []struct {
		name string
		alg  encryption.Algorithm
		want string
	}{
		// KEM algorithms
		{
			name: "KYBER512 is KEM",
			alg:  encryption.KYBER512,
			want: "KEM",
		},
		{
			name: "KYBER768 is KEM",
			alg:  encryption.KYBER768,
			want: "KEM",
		},
		{
			name: "KYBER1024 is KEM",
			alg:  encryption.KYBER1024,
			want: "KEM",
		},
		// RSA algorithms
		{
			name: "RSA2048 is RSA",
			alg:  encryption.RSA2048,
			want: "RSA",
		},
		{
			name: "RSA3072 is RSA",
			alg:  encryption.RSA3072,
			want: "RSA",
		},
		{
			name: "RSA4096 is RSA",
			alg:  encryption.RSA4096,
			want: "RSA",
		},
		// ECC algorithms
		{
			name: "P256 is ECC",
			alg:  encryption.ECC_P256,
			want: "ECC",
		},
		{
			name: "P384 is ECC",
			alg:  encryption.ECC_P384,
			want: "ECC",
		},
		{
			name: "P521 is ECC",
			alg:  encryption.ECC_P521,
			want: "ECC",
		},
		// Invalid
		{
			name: "Invalid algorithm",
			alg:  encryption.Algorithm("INVALID"),
			want: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetAlgorithmType(tt.alg)
			if got != tt.want {
				t.Errorf("GetAlgorithmType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKEMProviderWrapper(t *testing.T) {
	provider, err := NewEncryptionProvider(encryption.KYBER768)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	kemProvider, ok := provider.(*KEMProvider)
	if !ok {
		t.Fatal("Expected KEMProvider type")
	}

	if kemProvider.GetAlgorithm() != encryption.KYBER768 {
		t.Errorf("GetAlgorithm() = %v, want KYBER768", kemProvider.GetAlgorithm())
	}

	// Test encryption/decryption
	plaintext := []byte("Test message")
	seed := make([]byte, 32)
	_, sharedSecret := kemProvider.EncapsulateTo(seed)

	ciphertext, err := kemProvider.Encrypt(sharedSecret, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := kemProvider.Decrypt(sharedSecret, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption mismatch: got %s, want %s", decrypted, plaintext)
	}
}

func TestRSAProviderWrapper(t *testing.T) {
	provider, err := NewEncryptionProvider(encryption.RSA2048)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	rsaProvider, ok := provider.(*RSAProviderWrapper)
	if !ok {
		t.Fatal("Expected RSAProviderWrapper type")
	}

	if rsaProvider.GetAlgorithm() != encryption.RSA2048 {
		t.Errorf("GetAlgorithm() = %v, want RSA2048", rsaProvider.GetAlgorithm())
	}

	// Test encryption/decryption with small message
	plaintext := []byte("Small test message")
	publicKey := make([]byte, 32)

	ciphertext, err := rsaProvider.Encrypt(publicKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := rsaProvider.Decrypt(publicKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption mismatch: got %s, want %s", decrypted, plaintext)
	}
}

func TestECCProviderWrapper(t *testing.T) {
	provider, err := NewEncryptionProvider(encryption.ECC_P256)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	eccProvider, ok := provider.(*ECCProviderWrapper)
	if !ok {
		t.Fatal("Expected ECCProviderWrapper type")
	}

	if eccProvider.GetAlgorithm() != encryption.ECC_P256 {
		t.Errorf("GetAlgorithm() = %v, want P256", eccProvider.GetAlgorithm())
	}

	// Test encryption/decryption
	plaintext := []byte("Test message for ECC")
	publicKey := make([]byte, 32)

	ciphertext, err := eccProvider.Encrypt(publicKey, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := eccProvider.Decrypt(publicKey, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decryption mismatch: got %s, want %s", decrypted, plaintext)
	}
}

// Benchmark tests
func BenchmarkNewEncryptionProvider_KEM(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewEncryptionProvider(encryption.KYBER768)
	}
}

func BenchmarkNewEncryptionProvider_RSA(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewEncryptionProvider(encryption.RSA2048)
	}
}

func BenchmarkNewEncryptionProvider_ECC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewEncryptionProvider(encryption.ECC_P256)
	}
}

func BenchmarkGetAlgorithmType(b *testing.B) {
	algorithms := []encryption.Algorithm{
		encryption.KYBER768,
		encryption.RSA2048,
		encryption.ECC_P256,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetAlgorithmType(algorithms[i%len(algorithms)])
	}
}
