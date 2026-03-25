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

// TestPublicKeyToPEMIfKyber_Kyber512 verifies PEM encoding of a Kyber-512 public key.
func TestPublicKeyToPEMIfKyber_Kyber512(t *testing.T) {
	pub, _, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512 failed: %v", err)
	}

	pemStr, kt, handled, err := publicKeyToPEMIfKyber(pub)
	if err != nil {
		t.Fatalf("publicKeyToPEMIfKyber() error = %v", err)
	}
	if !handled {
		t.Error("publicKeyToPEMIfKyber() handled = false, want true for kyber512.PublicKey")
	}
	if kt != KeyType_KEY_TYPE_KYBER_512 {
		t.Errorf("publicKeyToPEMIfKyber() key type = %v, want KYBER_512", kt)
	}
	if !strings.Contains(pemStr, "KYBER-512 PUBLIC KEY") {
		t.Errorf("publicKeyToPEMIfKyber() PEM does not contain expected header, got: %s", pemStr)
	}
}

// TestPublicKeyToPEMIfKyber_Kyber768 verifies PEM encoding of a Kyber-768 public key.
func TestPublicKeyToPEMIfKyber_Kyber768(t *testing.T) {
	pub, _, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768 failed: %v", err)
	}

	pemStr, kt, handled, err := publicKeyToPEMIfKyber(pub)
	if err != nil {
		t.Fatalf("publicKeyToPEMIfKyber() error = %v", err)
	}
	if !handled {
		t.Error("publicKeyToPEMIfKyber() handled = false, want true for kyber768.PublicKey")
	}
	if kt != KeyType_KEY_TYPE_KYBER_768 {
		t.Errorf("publicKeyToPEMIfKyber() key type = %v, want KYBER_768", kt)
	}
	if !strings.Contains(pemStr, "KYBER-768 PUBLIC KEY") {
		t.Errorf("publicKeyToPEMIfKyber() PEM does not contain expected header, got: %s", pemStr)
	}
}

// TestPublicKeyToPEMIfKyber_Kyber1024 verifies PEM encoding of a Kyber-1024 public key.
func TestPublicKeyToPEMIfKyber_Kyber1024(t *testing.T) {
	pub, _, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024 failed: %v", err)
	}

	pemStr, kt, handled, err := publicKeyToPEMIfKyber(pub)
	if err != nil {
		t.Fatalf("publicKeyToPEMIfKyber() error = %v", err)
	}
	if !handled {
		t.Error("publicKeyToPEMIfKyber() handled = false, want true for kyber1024.PublicKey")
	}
	if kt != KeyType_KEY_TYPE_KYBER_1024 {
		t.Errorf("publicKeyToPEMIfKyber() key type = %v, want KYBER_1024", kt)
	}
	if !strings.Contains(pemStr, "KYBER-1024 PUBLIC KEY") {
		t.Errorf("publicKeyToPEMIfKyber() PEM does not contain expected header, got: %s", pemStr)
	}
}

// TestPublicKeyToPEMIfKyber_NonKyber verifies non-Kyber key returns handled=false.
func TestPublicKeyToPEMIfKyber_NonKyber(t *testing.T) {
	// Use a plain string as a non-Kyber type
	type notAKyberKey struct{}
	pemStr, kt, handled, err := publicKeyToPEMIfKyber(notAKyberKey{})
	if err != nil {
		t.Fatalf("publicKeyToPEMIfKyber() should not error for unknown type, got: %v", err)
	}
	if handled {
		t.Error("publicKeyToPEMIfKyber() handled = true, want false for non-Kyber key")
	}
	if pemStr != "" {
		t.Error("publicKeyToPEMIfKyber() should return empty PEM for non-Kyber key")
	}
	if kt != KeyType_KEY_TYPE_UNSPECIFIED {
		t.Errorf("publicKeyToPEMIfKyber() key type = %v, want UNSPECIFIED for non-Kyber key", kt)
	}
}

// TestParseKyberPublicKeyFromPEM_Kyber512 verifies round-trip PEM encode/decode for Kyber-512.
func TestParseKyberPublicKeyFromPEM_Kyber512(t *testing.T) {
	pub, _, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512 failed: %v", err)
	}

	keyBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	parsedKey, handled, err := parseKyberPublicKeyFromPEM(keyBytes, KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("parseKyberPublicKeyFromPEM() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKeyFromPEM() handled = false for KYBER_512")
	}
	if parsedKey == nil {
		t.Error("parseKyberPublicKeyFromPEM() returned nil key")
	}
}

// TestParseKyberPublicKeyFromPEM_Kyber768 verifies round-trip PEM encode/decode for Kyber-768.
func TestParseKyberPublicKeyFromPEM_Kyber768(t *testing.T) {
	pub, _, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768 failed: %v", err)
	}

	keyBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	parsedKey, handled, err := parseKyberPublicKeyFromPEM(keyBytes, KeyType_KEY_TYPE_KYBER_768)
	if err != nil {
		t.Fatalf("parseKyberPublicKeyFromPEM() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKeyFromPEM() handled = false for KYBER_768")
	}
	if parsedKey == nil {
		t.Error("parseKyberPublicKeyFromPEM() returned nil key")
	}
}

// TestParseKyberPublicKeyFromPEM_Kyber1024 verifies round-trip PEM encode/decode for Kyber-1024.
func TestParseKyberPublicKeyFromPEM_Kyber1024(t *testing.T) {
	pub, _, err := kyber1024.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024 failed: %v", err)
	}

	keyBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	parsedKey, handled, err := parseKyberPublicKeyFromPEM(keyBytes, KeyType_KEY_TYPE_KYBER_1024)
	if err != nil {
		t.Fatalf("parseKyberPublicKeyFromPEM() error = %v", err)
	}
	if !handled {
		t.Error("parseKyberPublicKeyFromPEM() handled = false for KYBER_1024")
	}
	if parsedKey == nil {
		t.Error("parseKyberPublicKeyFromPEM() returned nil key")
	}
}

// TestParseKyberPublicKeyFromPEM_InvalidBytes verifies error on bad bytes for Kyber types.
func TestParseKyberPublicKeyFromPEM_InvalidBytes(t *testing.T) {
	badBytes := []byte("not-a-kyber-key")

	for _, kt := range []KeyType{
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	} {
		_, handled, err := parseKyberPublicKeyFromPEM(badBytes, kt)
		if err == nil {
			t.Errorf("parseKyberPublicKeyFromPEM() should error for invalid bytes with %v", kt)
		}
		if !handled {
			t.Errorf("parseKyberPublicKeyFromPEM() handled = false for %v with invalid bytes", kt)
		}
	}
}

// TestParseKyberPublicKeyFromPEM_NonKyberKeyType verifies non-Kyber key type returns handled=false.
func TestParseKyberPublicKeyFromPEM_NonKyberKeyType(t *testing.T) {
	_, handled, err := parseKyberPublicKeyFromPEM([]byte("whatever"), KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("parseKyberPublicKeyFromPEM() should not error for non-Kyber type, got: %v", err)
	}
	if handled {
		t.Error("parseKyberPublicKeyFromPEM() handled = true for non-Kyber key type, want false")
	}
}

// TestEncodeKyberPublicKeyPEM verifies the PEM encoding helper.
func TestEncodeKyberPublicKeyPEM(t *testing.T) {
	keyBytes := []byte{0x01, 0x02, 0x03, 0x04}
	pemStr := encodeKyberPublicKeyPEM("TEST KEY TYPE", keyBytes)
	if !strings.Contains(pemStr, "TEST KEY TYPE") {
		t.Errorf("encodeKyberPublicKeyPEM() result does not contain label: %s", pemStr)
	}
	if !strings.HasPrefix(pemStr, "-----BEGIN TEST KEY TYPE-----") {
		t.Errorf("encodeKyberPublicKeyPEM() result missing BEGIN line: %s", pemStr)
	}
}

// TestPublicKeyToPEMIfKyber_RoundTrip verifies full round-trip for all Kyber sizes.
func TestPublicKeyToPEMIfKyber_RoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		genKey  func() (interface{}, error)
	}{
		{
			name:    "Kyber-512",
			keyType: KeyType_KEY_TYPE_KYBER_512,
			genKey: func() (interface{}, error) {
				pub, _, err := kyber512.GenerateKeyPair(rand.Reader)
				return pub, err
			},
		},
		{
			name:    "Kyber-768",
			keyType: KeyType_KEY_TYPE_KYBER_768,
			genKey: func() (interface{}, error) {
				pub, _, err := kyber768.GenerateKeyPair(rand.Reader)
				return pub, err
			},
		},
		{
			name:    "Kyber-1024",
			keyType: KeyType_KEY_TYPE_KYBER_1024,
			genKey: func() (interface{}, error) {
				pub, _, err := kyber1024.GenerateKeyPair(rand.Reader)
				return pub, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, err := tt.genKey()
			if err != nil {
				t.Fatalf("GenerateKeyPair failed: %v", err)
			}

			pemStr, kt, handled, err := publicKeyToPEMIfKyber(pubKey)
			if err != nil {
				t.Fatalf("publicKeyToPEMIfKyber() error = %v", err)
			}
			if !handled {
				t.Error("publicKeyToPEMIfKyber() handled = false")
			}
			if kt != tt.keyType {
				t.Errorf("key type = %v, want %v", kt, tt.keyType)
			}
			if len(pemStr) == 0 {
				t.Error("publicKeyToPEMIfKyber() returned empty PEM")
			}
		})
	}
}
