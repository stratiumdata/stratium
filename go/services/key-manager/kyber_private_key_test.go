//go:build !fips

package key_manager

import (
	"crypto/rand"
	"strings"
	"testing"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestSerializeKyberPrivateKey_Kyber512 verifies serialization of a Kyber-512 private key.
func TestSerializeKyberPrivateKey_Kyber512(t *testing.T) {
	_, priv, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512 failed: %v", err)
	}

	keyBytes, handled, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("serializeKyberPrivateKey() handled = false, want true for kyber512.PrivateKey")
	}
	if len(keyBytes) == 0 {
		t.Error("serializeKyberPrivateKey() returned empty bytes")
	}
	if len(keyBytes) != kyber512.Scheme().PrivateKeySize() {
		t.Errorf("serializeKyberPrivateKey() keyBytes length = %d, want %d", len(keyBytes), kyber512.Scheme().PrivateKeySize())
	}
}

// TestSerializeKyberPrivateKey_Kyber768 verifies serialization of a Kyber-768 private key.
func TestSerializeKyberPrivateKey_Kyber768(t *testing.T) {
	_, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768 failed: %v", err)
	}

	keyBytes, handled, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("serializeKyberPrivateKey() handled = false, want true for kyber768.PrivateKey")
	}
	if len(keyBytes) != kyber768.Scheme().PrivateKeySize() {
		t.Errorf("serializeKyberPrivateKey() keyBytes length = %d, want %d", len(keyBytes), kyber768.Scheme().PrivateKeySize())
	}
}

// TestSerializeKyberPrivateKey_Kyber1024 verifies serialization of a Kyber-1024 private key.
func TestSerializeKyberPrivateKey_Kyber1024(t *testing.T) {
	_, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024 failed: %v", err)
	}

	keyBytes, handled, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("serializeKyberPrivateKey() handled = false, want true for kyber1024.PrivateKey")
	}
	if len(keyBytes) != kyber1024.Scheme().PrivateKeySize() {
		t.Errorf("serializeKyberPrivateKey() keyBytes length = %d, want %d", len(keyBytes), kyber1024.Scheme().PrivateKeySize())
	}
}

// TestSerializeKyberPrivateKey_NonKyberKey verifies that non-Kyber keys return handled=false.
func TestSerializeKyberPrivateKey_NonKyberKey(t *testing.T) {
	type notAKyberKey struct{}
	_, handled, err := serializeKyberPrivateKey(&notAKyberKey{}, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("serializeKyberPrivateKey() unexpected error for non-Kyber key: %v", err)
	}
	if handled {
		t.Error("serializeKyberPrivateKey() handled = true, want false for non-Kyber key")
	}
}

// TestDeserializeKyberPrivateKey_Kyber512 verifies round-trip deserialize for Kyber-512.
func TestDeserializeKyberPrivateKey_Kyber512(t *testing.T) {
	_, priv, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512 failed: %v", err)
	}

	keyBytes, _, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}

	result, handled, err := deserializeKyberPrivateKey(keyBytes, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("deserializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("deserializeKyberPrivateKey() handled = false, want true")
	}
	if result == nil {
		t.Error("deserializeKyberPrivateKey() returned nil key")
	}
	if _, ok := result.(*kyber512.PrivateKey); !ok {
		t.Errorf("deserializeKyberPrivateKey() returned %T, want *kyber512.PrivateKey", result)
	}
}

// TestDeserializeKyberPrivateKey_Kyber768 verifies round-trip deserialize for Kyber-768.
func TestDeserializeKyberPrivateKey_Kyber768(t *testing.T) {
	_, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768 failed: %v", err)
	}

	keyBytes, _, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}

	result, handled, err := deserializeKyberPrivateKey(keyBytes, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("deserializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("deserializeKyberPrivateKey() handled = false, want true")
	}
	if _, ok := result.(*kyber768.PrivateKey); !ok {
		t.Errorf("deserializeKyberPrivateKey() returned %T, want *kyber768.PrivateKey", result)
	}
}

// TestDeserializeKyberPrivateKey_Kyber1024 verifies round-trip deserialize for Kyber-1024.
func TestDeserializeKyberPrivateKey_Kyber1024(t *testing.T) {
	_, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024 failed: %v", err)
	}

	keyBytes, _, err := serializeKyberPrivateKey(priv, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("serializeKyberPrivateKey() error = %v", err)
	}

	result, handled, err := deserializeKyberPrivateKey(keyBytes, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("deserializeKyberPrivateKey() error = %v", err)
	}
	if !handled {
		t.Error("deserializeKyberPrivateKey() handled = false, want true")
	}
	if _, ok := result.(*kyber1024.PrivateKey); !ok {
		t.Errorf("deserializeKyberPrivateKey() returned %T, want *kyber1024.PrivateKey", result)
	}
}

// TestDeserializeKyberPrivateKey_InvalidSize verifies error on unsupported key size.
func TestDeserializeKyberPrivateKey_InvalidSize(t *testing.T) {
	_, _, err := deserializeKyberPrivateKey([]byte("not-a-valid-kyber-key"), KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("deserializeKyberPrivateKey() should fail for invalid key bytes")
	}
}

// TestDeserializeKyberPrivateKey_EmptyBytes verifies error on empty input.
func TestDeserializeKyberPrivateKey_EmptyBytes(t *testing.T) {
	_, _, err := deserializeKyberPrivateKey([]byte{}, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("deserializeKyberPrivateKey() should fail for empty bytes")
	}
}

// TestConvertKyberPrivateKeyToPEM_Kyber512 verifies PEM conversion for Kyber-512.
func TestConvertKyberPrivateKeyToPEM_Kyber512(t *testing.T) {
	_, priv, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512 failed: %v", err)
	}

	pemStr, handled, err := convertKyberPrivateKeyToPEM(priv, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("convertKyberPrivateKeyToPEM() error = %v", err)
	}
	if !handled {
		t.Error("convertKyberPrivateKeyToPEM() handled = false, want true")
	}
	if !strings.Contains(pemStr, "KYBER PRIVATE KEY") {
		t.Errorf("convertKyberPrivateKeyToPEM() PEM missing expected header, got: %s", pemStr)
	}
}

// TestConvertKyberPrivateKeyToPEM_Kyber768 verifies PEM conversion for Kyber-768.
func TestConvertKyberPrivateKeyToPEM_Kyber768(t *testing.T) {
	_, priv, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768 failed: %v", err)
	}

	pemStr, handled, err := convertKyberPrivateKeyToPEM(priv, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("convertKyberPrivateKeyToPEM() error = %v", err)
	}
	if !handled {
		t.Error("convertKyberPrivateKeyToPEM() handled = false, want true")
	}
	if !strings.Contains(pemStr, "KYBER PRIVATE KEY") {
		t.Errorf("convertKyberPrivateKeyToPEM() PEM missing expected header")
	}
}

// TestConvertKyberPrivateKeyToPEM_Kyber1024 verifies PEM conversion for Kyber-1024.
func TestConvertKyberPrivateKeyToPEM_Kyber1024(t *testing.T) {
	_, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024 failed: %v", err)
	}

	pemStr, handled, err := convertKyberPrivateKeyToPEM(priv, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("convertKyberPrivateKeyToPEM() error = %v", err)
	}
	if !handled {
		t.Error("convertKyberPrivateKeyToPEM() handled = false, want true")
	}
	if !strings.Contains(pemStr, "KYBER PRIVATE KEY") {
		t.Errorf("convertKyberPrivateKeyToPEM() PEM missing expected header")
	}
}

// TestConvertKyberPrivateKeyToPEM_NonKyberKey verifies non-Kyber keys are not handled.
func TestConvertKyberPrivateKeyToPEM_NonKyberKey(t *testing.T) {
	type notAKyberKey struct{}
	pemStr, handled, err := convertKyberPrivateKeyToPEM(&notAKyberKey{}, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("convertKyberPrivateKeyToPEM() unexpected error for non-Kyber key: %v", err)
	}
	if handled {
		t.Error("convertKyberPrivateKeyToPEM() handled = true, want false for non-Kyber key")
	}
	if pemStr != "" {
		t.Errorf("convertKyberPrivateKeyToPEM() returned non-empty PEM for non-Kyber key")
	}
}
