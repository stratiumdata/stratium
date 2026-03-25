//go:build !fips

package key_access

import (
	"testing"

	keyManager "stratium/services/key-manager"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// TestParseKyberPublicKey_Kyber512 verifies parsing a Kyber-512 public key.
func TestParseKyberPublicKey_Kyber512(t *testing.T) {
	pub, _, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	got, handled, err := parseKyberPublicKey(pubBytes, keyManager.KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("parseKyberPublicKey() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKey() handled = false for KYBER_512")
	}
	if got == nil {
		t.Error("parseKyberPublicKey() returned nil key")
	}
}

// TestParseKyberPublicKey_Kyber768 verifies parsing a Kyber-768 public key.
func TestParseKyberPublicKey_Kyber768(t *testing.T) {
	pub, _, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	got, handled, err := parseKyberPublicKey(pubBytes, keyManager.KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("parseKyberPublicKey() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKey() handled = false for KYBER_768")
	}
	if got == nil {
		t.Error("parseKyberPublicKey() returned nil key")
	}
}

// TestParseKyberPublicKey_Kyber1024 verifies parsing a Kyber-1024 public key.
func TestParseKyberPublicKey_Kyber1024(t *testing.T) {
	pub, _, err := kyber1024.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	got, handled, err := parseKyberPublicKey(pubBytes, keyManager.KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("parseKyberPublicKey() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKey() handled = false for KYBER_1024")
	}
	if got == nil {
		t.Error("parseKyberPublicKey() returned nil key")
	}
}

// TestParseKyberPublicKey_NonKyberType verifies non-Kyber types return not-handled.
func TestParseKyberPublicKey_NonKyberType(t *testing.T) {
	_, handled, err := parseKyberPublicKey([]byte("dummy"), keyManager.KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Errorf("parseKyberPublicKey() for RSA type should not error, got: %v", err)
	}
	if handled {
		t.Error("parseKyberPublicKey() handled = true for RSA type, want false")
	}
}

// TestParseKyberPublicKey_InvalidBytes verifies error on bad key bytes.
func TestParseKyberPublicKey_InvalidBytes(t *testing.T) {
	_, handled, err := parseKyberPublicKey([]byte("not-a-kyber-key"), keyManager.KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Error("parseKyberPublicKey() with invalid bytes should return error")
	}
	if !handled {
		t.Error("parseKyberPublicKey() handled = false for KYBER_512 even on error")
	}
}
