package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeyType_AllValues(t *testing.T) {
	tests := []struct {
		input string
		want  KeyType
	}{
		{"RSA2048", KeyType_KEY_TYPE_RSA_2048},
		{"RSA3072", KeyType_KEY_TYPE_RSA_3072},
		{"RSA4096", KeyType_KEY_TYPE_RSA_4096},
		{"ECC256", KeyType_KEY_TYPE_ECC_P256},
		{"ECC384", KeyType_KEY_TYPE_ECC_P384},
		{"ECC521", KeyType_KEY_TYPE_ECC_P521},
		{"Kyber512", KeyType_KEY_TYPE_KYBER_512},
		{"Kyber768", KeyType_KEY_TYPE_KYBER_768},
		{"Kyber1024", KeyType_KEY_TYPE_KYBER_1024},
		{"unknown", KeyType_KEY_TYPE_RSA_2048},  // default
		{"", KeyType_KEY_TYPE_RSA_2048},          // empty string default
		{"INVALID_KEY_TYPE", KeyType_KEY_TYPE_RSA_2048}, // another unknown default
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, parseKeyType(tc.input))
		})
	}
}

func TestKeyTypeToString_AllValues(t *testing.T) {
	tests := []struct {
		input KeyType
		want  string
	}{
		{KeyType_KEY_TYPE_RSA_2048, "RSA2048"},
		{KeyType_KEY_TYPE_RSA_3072, "RSA3072"},
		{KeyType_KEY_TYPE_RSA_4096, "RSA4096"},
		{KeyType_KEY_TYPE_ECC_P256, "ECC256"},
		{KeyType_KEY_TYPE_ECC_P384, "ECC384"},
		{KeyType_KEY_TYPE_ECC_P521, "ECC521"},
		{KeyType_KEY_TYPE_KYBER_512, "Kyber512"},
		{KeyType_KEY_TYPE_KYBER_768, "Kyber768"},
		{KeyType_KEY_TYPE_KYBER_1024, "Kyber1024"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, keyTypeToString(tc.input))
		})
	}
}

func TestKeyTypeToString_Default(t *testing.T) {
	// Unknown/unspecified value should default to RSA2048
	result := keyTypeToString(KeyType(9999))
	assert.Equal(t, "RSA2048", result)
}

func TestParseProviderType_AllValues(t *testing.T) {
	tests := []struct {
		input string
		want  KeyProviderType
	}{
		{"software", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE},
		{"hsm", KeyProviderType_KEY_PROVIDER_TYPE_HSM},
		{"smartcard", KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD},
		{"unknown", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE},  // default
		{"", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE},          // empty default
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, parseProviderType(tc.input))
		})
	}
}

func TestProviderTypeToString_AllValues(t *testing.T) {
	tests := []struct {
		input KeyProviderType
		want  string
	}{
		{KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, "software"},
		{KeyProviderType_KEY_PROVIDER_TYPE_HSM, "hsm"},
		{KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD, "smartcard"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			assert.Equal(t, tc.want, providerTypeToString(tc.input))
		})
	}
}

func TestProviderTypeToString_Default(t *testing.T) {
	result := providerTypeToString(KeyProviderType(9999))
	assert.Equal(t, "software", result)
}

func TestParseKeyStatus_AllValues(t *testing.T) {
	tests := []struct {
		input string
		want  KeyStatus
	}{
		{"active", KeyStatus_KEY_STATUS_ACTIVE},
		{"inactive", KeyStatus_KEY_STATUS_INACTIVE},
		{"deprecated", KeyStatus_KEY_STATUS_DEPRECATED},
		{"revoked", KeyStatus_KEY_STATUS_REVOKED},
		{"compromised", KeyStatus_KEY_STATUS_COMPROMISED},
		{"unknown", KeyStatus_KEY_STATUS_ACTIVE},  // default
		{"", KeyStatus_KEY_STATUS_ACTIVE},          // empty default
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, parseKeyStatus(tc.input))
		})
	}
}

func TestKeyStatusToDBString_AllValues(t *testing.T) {
	tests := []struct {
		input KeyStatus
		want  string
	}{
		{KeyStatus_KEY_STATUS_ACTIVE, "active"},
		{KeyStatus_KEY_STATUS_INACTIVE, "inactive"},
		{KeyStatus_KEY_STATUS_DEPRECATED, "inactive"}, // maps to inactive per implementation
		{KeyStatus_KEY_STATUS_COMPROMISED, "compromised"},
		{KeyStatus_KEY_STATUS_REVOKED, "revoked"},
		{KeyStatus_KEY_STATUS_PENDING_ROTATION, "active"}, // normalized to active
		{KeyStatus_KEY_STATUS_UNSPECIFIED, "active"},       // normalized to active
	}
	for _, tc := range tests {
		t.Run(tc.want+"_"+tc.input.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, keyStatusToDBString(tc.input))
		})
	}
}

func TestKeyStatusToDBString_Default(t *testing.T) {
	// Unknown status should default to active
	result := keyStatusToDBString(KeyStatus(9999))
	assert.Equal(t, "active", result)
}

func TestParsePublicKeyFromPEM_EmptyString(t *testing.T) {
	_, err := parsePublicKeyFromPEM("", KeyType_KEY_TYPE_RSA_2048)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParsePublicKeyFromPEM_InvalidPEM(t *testing.T) {
	_, err := parsePublicKeyFromPEM("not-valid-pem-data", KeyType_KEY_TYPE_RSA_2048)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode")
}

func TestParsePublicKeyFromPEM_RSA2048(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_RSA_2048)
	require.NoError(t, err)
	rsaPub, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, &privateKey.PublicKey, rsaPub)
}

func TestParsePublicKeyFromPEM_RSA3072(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_RSA_3072)
	require.NoError(t, err)
	_, ok := result.(*rsa.PublicKey)
	require.True(t, ok)
}

func TestParsePublicKeyFromPEM_ECCP256(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_ECC_P256)
	require.NoError(t, err)
	ecPub, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, &privateKey.PublicKey, ecPub)
}

func TestParsePublicKeyFromPEM_ECCP384(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_ECC_P384)
	require.NoError(t, err)
	_, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
}

func TestParsePublicKeyFromPEM_ECCP521(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_ECC_P521)
	require.NoError(t, err)
	_, ok := result.(*ecdsa.PublicKey)
	require.True(t, ok)
}

func TestParsePublicKeyFromPEM_WrongKeyType_RSAExpected(t *testing.T) {
	// Provide an ECC key but request RSA type
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	_, err = parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_RSA_2048)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected RSA public key")
}

func TestParsePublicKeyFromPEM_WrongKeyType_ECCExpected(t *testing.T) {
	// Provide an RSA key but request ECC type
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	_, err = parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_ECC_P256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ECDSA public key")
}

func TestParsePublicKeyFromPEM_DefaultKeyType(t *testing.T) {
	// For an unknown/Kyber key type, parsed key is returned as-is
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	// Using Kyber512 key type which falls to default return
	result, err := parsePublicKeyFromPEM(pemData, KeyType_KEY_TYPE_KYBER_512)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestParseAndRoundTripKeyType(t *testing.T) {
	// Test that parseKeyType and keyTypeToString are inverses
	keyTypes := []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521,
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	}
	for _, kt := range keyTypes {
		str := keyTypeToString(kt)
		parsed := parseKeyType(str)
		assert.Equal(t, kt, parsed, "roundtrip failed for %v", kt)
	}
}

func TestParseAndRoundTripProviderType(t *testing.T) {
	// Test that parseProviderType and providerTypeToString are inverses
	providerTypes := []KeyProviderType{
		KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD,
	}
	for _, pt := range providerTypes {
		str := providerTypeToString(pt)
		parsed := parseProviderType(str)
		assert.Equal(t, pt, parsed, "roundtrip failed for %v", pt)
	}
}
