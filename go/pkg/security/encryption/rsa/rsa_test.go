package rsa

import (
	"bytes"
	"testing"

	"stratium/pkg/security/encryption"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name     string
		alg      encryption.Algorithm
		keySize  int
		wantErr  bool
	}{
		{
			name:     "RSA2048",
			alg:      encryption.RSA2048,
			keySize:  2048,
			wantErr:  false,
		},
		{
			name:     "RSA3072",
			alg:      encryption.RSA3072,
			keySize:  3072,
			wantErr:  false,
		},
		{
			name:     "RSA4096",
			alg:      encryption.RSA4096,
			keySize:  4096,
			wantErr:  false,
		},
		{
			name:     "Invalid algorithm - KYBER512",
			alg:      encryption.KYBER512,
			wantErr:  true,
		},
		{
			name:     "Invalid algorithm - ECC_P256",
			alg:      encryption.ECC_P256,
			wantErr:  true,
		},
		{
			name:     "Invalid algorithm - empty",
			alg:      encryption.Algorithm(""),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.alg)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
				assert.Contains(t, err.Error(), "unsupported RSA algorithm")
			} else {
				require.NoError(t, err)
				require.NotNil(t, provider)
				assert.Equal(t, tt.keySize, provider.GetKeySize())
				assert.NotNil(t, provider.privateKey)
				assert.NotNil(t, provider.publicKey)
			}
		})
	}
}

func TestRSAProvider_EncryptDecrypt(t *testing.T) {
	algorithms := []encryption.Algorithm{
		encryption.RSA2048,
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Small message",
			plaintext: []byte("Test message for RSA encryption"),
		},
		{
			name:      "Empty message",
			plaintext: []byte(""),
		},
		{
			name:      "Single byte",
			plaintext: []byte("a"),
		},
		{
			name:      "Large message near max size",
			plaintext: bytes.Repeat([]byte("A"), 100),
		},
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			provider, err := NewProvider(alg)
			require.NoError(t, err)

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					publicKey := make([]byte, 32)

					// Encrypt
					ciphertext, err := provider.Encrypt(publicKey, tc.plaintext)
					require.NoError(t, err)
					assert.NotEmpty(t, ciphertext)
					assert.NotEqual(t, tc.plaintext, ciphertext)

					// Decrypt
					decrypted, err := provider.Decrypt(publicKey, ciphertext)
					require.NoError(t, err)
					assert.Equal(t, tc.plaintext, decrypted)
				})
			}
		})
	}
}

func TestRSAProvider_DecryptInvalidCiphertext(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	testCases := []struct {
		name       string
		ciphertext []byte
	}{
		{
			name:       "Empty ciphertext",
			ciphertext: []byte{},
		},
		{
			name:       "Invalid ciphertext - random bytes",
			ciphertext: []byte("this is not a valid ciphertext"),
		},
		{
			name:       "Invalid ciphertext - too short",
			ciphertext: []byte{0x00, 0x01, 0x02},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.Decrypt(nil, tc.ciphertext)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "RSA decryption failed")
		})
	}
}

func TestRSAProvider_GetPublicKeyBytes(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	pubKeyBytes, err := provider.GetPublicKeyBytes()
	require.NoError(t, err)
	assert.NotEmpty(t, pubKeyBytes)

	// Public key should be in DER format (starts with SEQUENCE tag 0x30)
	assert.Equal(t, byte(0x30), pubKeyBytes[0])
}

func TestRSAProvider_GetPrivateKeyBytes(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	privKeyBytes, err := provider.GetPrivateKeyBytes()
	require.NoError(t, err)
	assert.NotEmpty(t, privKeyBytes)

	// Private key should be in PKCS#8 format (starts with SEQUENCE tag 0x30)
	assert.Equal(t, byte(0x30), privKeyBytes[0])
}

func TestRSAProvider_GetKeySize(t *testing.T) {
	tests := []struct {
		alg      encryption.Algorithm
		expected int
	}{
		{encryption.RSA2048, 2048},
		{encryption.RSA3072, 3072},
		{encryption.RSA4096, 4096},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			provider, err := NewProvider(tt.alg)
			require.NoError(t, err)

			keySize := provider.GetKeySize()
			assert.Equal(t, tt.expected, keySize)
		})
	}
}

func TestRSAProvider_GetMaxPlaintextSize(t *testing.T) {
	tests := []struct {
		alg      encryption.Algorithm
		expected int
	}{
		{encryption.RSA2048, (2048 / 8) - 66},
		{encryption.RSA3072, (3072 / 8) - 66},
		{encryption.RSA4096, (4096 / 8) - 66},
	}

	for _, tt := range tests {
		t.Run(string(tt.alg), func(t *testing.T) {
			provider, err := NewProvider(tt.alg)
			require.NoError(t, err)

			maxSize := provider.GetMaxPlaintextSize()
			assert.Equal(t, tt.expected, maxSize)
		})
	}
}

func TestRSAProvider_EncryptLarge(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	maxChunkSize := provider.GetMaxPlaintextSize()

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "Slightly larger than max size",
			plaintext: bytes.Repeat([]byte("B"), maxChunkSize+10),
		},
		{
			name:      "Multiple chunks",
			plaintext: bytes.Repeat([]byte("C"), maxChunkSize*2+50),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt
			ciphertext, err := provider.EncryptLarge(tc.plaintext)
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)

			// Decrypt
			decrypted, err := provider.DecryptLarge(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, tc.plaintext, decrypted)
		})
	}
}

func TestRSAProvider_DecryptLarge_InvalidFormat(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	testCases := []struct {
		name       string
		ciphertext []byte
		errorMsg   string
	}{
		{
			name:       "Too short for header",
			ciphertext: []byte{0x00, 0x01},
			errorMsg:   "invalid ciphertext format",
		},
		{
			name:       "Invalid chunk size - too large",
			ciphertext: []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02},
			errorMsg:   "invalid chunk size",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := provider.DecryptLarge(tc.ciphertext)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errorMsg)
		})
	}
}

func TestRSAProvider_DecryptLarge_EmptyCiphertext(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	// Empty ciphertext is treated as valid and returns empty result
	ciphertext := []byte{}
	result, err := provider.DecryptLarge(ciphertext)
	assert.NoError(t, err)
	assert.Empty(t, result)
}

func TestRSAProvider_EncryptLarge_VeryLargeMessage(t *testing.T) {
	provider, err := NewProvider(encryption.RSA2048)
	require.NoError(t, err)

	// Create a message that requires multiple chunks
	maxChunkSize := provider.GetMaxPlaintextSize()
	plaintext := bytes.Repeat([]byte("Large data chunk for testing"), maxChunkSize/10)
	ciphertext, err := provider.EncryptLarge(plaintext)
	require.NoError(t, err)

	decrypted, err := provider.DecryptLarge(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// Benchmark tests
func BenchmarkRSA2048_NewProvider(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = NewProvider(encryption.RSA2048)
	}
}

func BenchmarkRSA2048_Encrypt(b *testing.B) {
	provider, _ := NewProvider(encryption.RSA2048)
	publicKey := make([]byte, 32)
	plaintext := []byte("Benchmark plaintext for RSA encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Encrypt(publicKey, plaintext)
	}
}

func BenchmarkRSA2048_Decrypt(b *testing.B) {
	provider, _ := NewProvider(encryption.RSA2048)
	publicKey := make([]byte, 32)
	plaintext := []byte("Benchmark plaintext for RSA encryption")
	ciphertext, _ := provider.Encrypt(publicKey, plaintext)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Decrypt(publicKey, ciphertext)
	}
}

func BenchmarkRSA2048_EncryptLarge(b *testing.B) {
	provider, _ := NewProvider(encryption.RSA2048)
	maxSize := provider.GetMaxPlaintextSize()
	plaintext := bytes.Repeat([]byte("A"), maxSize*2)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.EncryptLarge(plaintext)
	}
}

func BenchmarkRSA4096_Encrypt(b *testing.B) {
	provider, _ := NewProvider(encryption.RSA4096)
	publicKey := make([]byte, 32)
	plaintext := []byte("Benchmark plaintext for RSA encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = provider.Encrypt(publicKey, plaintext)
	}
}