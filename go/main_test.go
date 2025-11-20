package _go

import (
	"stratium/pkg/security/encryption"
	"strings"
	"testing"
)

func TestEncryptionProvider_AllSupportedAlgorithms(t *testing.T) {
	algorithms := []encryption.Algorithm{
		// Post-Quantum KEM algorithms
		encryption.KYBER512,
		encryption.KYBER768,
		encryption.KYBER1024,
		// RSA algorithms
		encryption.RSA2048,
		encryption.RSA3072,
		encryption.RSA4096,
		// ECC algorithms
		encryption.ECC_P256,
		encryption.ECC_P384,
		encryption.ECC_P521,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			err := EncryptionProvider(alg)
			if err != nil {
				t.Errorf("EncryptionProvider(%s) failed: %v", alg, err)
			}
		})
	}
}

func TestEncryptionProvider_UnsupportedAlgorithm(t *testing.T) {
	unsupportedAlg := encryption.Algorithm("UNSUPPORTED")
	err := EncryptionProvider(unsupportedAlg)

	if err == nil {
		t.Error("Expected error for unsupported algorithm, but got nil")
	}

	if !strings.Contains(err.Error(), "error initializing encryption provider") {
		t.Errorf("Expected error about encryption provider initialization, got: %v", err)
	}
}

// Test individual KEM algorithms
func TestEncryptionProvider_KYBER768_Success(t *testing.T) {
	err := EncryptionProvider(encryption.KYBER768)
	if err != nil {
		t.Errorf("EncryptionProvider(KYBER768) failed: %v", err)
	}
}

func TestEncryptionProvider_KYBER512_Success(t *testing.T) {
	err := EncryptionProvider(encryption.KYBER512)
	if err != nil {
		t.Errorf("EncryptionProvider(KYBER512) failed: %v", err)
	}
}

func TestEncryptionProvider_KYBER1024_Success(t *testing.T) {
	err := EncryptionProvider(encryption.KYBER1024)
	if err != nil {
		t.Errorf("EncryptionProvider(KYBER1024) failed: %v", err)
	}
}

// Test RSA algorithms
func TestEncryptionProvider_RSA2048_Success(t *testing.T) {
	err := EncryptionProvider(encryption.RSA2048)
	if err != nil {
		t.Errorf("EncryptionProvider(RSA2048) failed: %v", err)
	}
}

func TestEncryptionProvider_RSA3072_Success(t *testing.T) {
	err := EncryptionProvider(encryption.RSA3072)
	if err != nil {
		t.Errorf("EncryptionProvider(RSA3072) failed: %v", err)
	}
}

func TestEncryptionProvider_RSA4096_Success(t *testing.T) {
	err := EncryptionProvider(encryption.RSA4096)
	if err != nil {
		t.Errorf("EncryptionProvider(RSA4096) failed: %v", err)
	}
}

// Test ECC algorithms
func TestEncryptionProvider_ECC_P256_Success(t *testing.T) {
	err := EncryptionProvider(encryption.ECC_P256)
	if err != nil {
		t.Errorf("EncryptionProvider(ECC_P256) failed: %v", err)
	}
}

func TestEncryptionProvider_ECC_P384_Success(t *testing.T) {
	err := EncryptionProvider(encryption.ECC_P384)
	if err != nil {
		t.Errorf("EncryptionProvider(ECC_P384) failed: %v", err)
	}
}

func TestEncryptionProvider_ECC_P521_Success(t *testing.T) {
	err := EncryptionProvider(encryption.ECC_P521)
	if err != nil {
		t.Errorf("EncryptionProvider(ECC_P521) failed: %v", err)
	}
}

func TestEncryptionProvider_InvalidAlgorithmString(t *testing.T) {
	testCases := []struct {
		name string
		alg  encryption.Algorithm
	}{
		{"empty string", encryption.Algorithm("")},
		{"invalid algorithm", encryption.Algorithm("INVALID")},
		{"lowercase", encryption.Algorithm("kyber768")},
		{"mixed case", encryption.Algorithm("Kyber768")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := EncryptionProvider(tc.alg)
			if err == nil {
				t.Errorf("Expected error for algorithm %q, but got nil", tc.alg)
			}
		})
	}
}

// BenchmarkEncryptionProvider benchmarks the performance of the encryption provider

// KEM algorithm benchmarks
func BenchmarkEncryptionProvider_KYBER768(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.KYBER768)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_KYBER512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.KYBER512)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_KYBER1024(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.KYBER1024)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

// RSA algorithm benchmarks
func BenchmarkEncryptionProvider_RSA2048(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.RSA2048)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_RSA3072(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.RSA3072)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_RSA4096(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.RSA4096)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

// ECC algorithm benchmarks
func BenchmarkEncryptionProvider_ECC_P256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.ECC_P256)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_ECC_P384(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.ECC_P384)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}

func BenchmarkEncryptionProvider_ECC_P521(b *testing.B) {
	for i := 0; i < b.N; i++ {
		err := EncryptionProvider(encryption.ECC_P521)
		if err != nil {
			b.Fatalf("EncryptionProvider failed: %v", err)
		}
	}
}
