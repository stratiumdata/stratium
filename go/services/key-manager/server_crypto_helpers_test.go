package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestInferKeyTypeFromPEM_RSA2048 verifies RSA-2048 key type inference.
func TestInferKeyTypeFromPEM_RSA2048(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want RSA_2048", kt)
	}
}

// TestInferKeyTypeFromPEM_RSA3072 verifies RSA-3072 key type inference.
func TestInferKeyTypeFromPEM_RSA3072(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 3072)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_3072 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want RSA_3072", kt)
	}
}

// TestInferKeyTypeFromPEM_RSA4096 verifies RSA-4096 key type inference.
func TestInferKeyTypeFromPEM_RSA4096(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 4096)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want RSA_4096", kt)
	}
}

// TestInferKeyTypeFromPEM_P256 verifies P-256 key type inference.
func TestInferKeyTypeFromPEM_P256(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P256 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want ECC_P256", kt)
	}
}

// TestInferKeyTypeFromPEM_P384 verifies P-384 key type inference.
func TestInferKeyTypeFromPEM_P384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P384 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want ECC_P384", kt)
	}
}

// TestInferKeyTypeFromPEM_P521 verifies P-521 key type inference.
func TestInferKeyTypeFromPEM_P521(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	kt, err := inferKeyTypeFromPEM(pemStr)
	if err != nil {
		t.Fatalf("inferKeyTypeFromPEM() error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P521 {
		t.Errorf("inferKeyTypeFromPEM() = %v, want ECC_P521", kt)
	}
}

// TestInferKeyTypeFromPEM_InvalidPEM verifies error on invalid PEM.
func TestInferKeyTypeFromPEM_InvalidPEM(t *testing.T) {
	_, err := inferKeyTypeFromPEM("not-a-pem")
	if err == nil {
		t.Fatal("inferKeyTypeFromPEM() should fail for invalid PEM")
	}
}

// TestIsFIPSKeyTypeAllowed verifies FIPS allowed key types.
func TestIsFIPSKeyTypeAllowed(t *testing.T) {
	allowedTypes := []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
	}
	for _, kt := range allowedTypes {
		if !isFIPSKeyTypeAllowed(kt) {
			t.Errorf("isFIPSKeyTypeAllowed(%v) = false, want true", kt)
		}
	}

	notAllowedTypes := []KeyType{
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521,
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	}
	for _, kt := range notAllowedTypes {
		if isFIPSKeyTypeAllowed(kt) {
			t.Errorf("isFIPSKeyTypeAllowed(%v) = true, want false", kt)
		}
	}
}

// TestFilterFIPSKeyTypes verifies only FIPS-allowed key types are returned.
func TestFilterFIPSKeyTypes(t *testing.T) {
	input := []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_RSA_3072,
	}

	filtered := filterFIPSKeyTypes(input)
	if len(filtered) != 3 {
		t.Errorf("filterFIPSKeyTypes() returned %d types, want 3", len(filtered))
	}

	for _, kt := range filtered {
		if !isFIPSKeyTypeAllowed(kt) {
			t.Errorf("filterFIPSKeyTypes() returned non-FIPS type %v", kt)
		}
	}
}

// TestFilterFIPSKeyTypes_EmptyInput verifies empty input returns empty output.
func TestFilterFIPSKeyTypes_EmptyInput(t *testing.T) {
	filtered := filterFIPSKeyTypes(nil)
	if len(filtered) != 0 {
		t.Errorf("filterFIPSKeyTypes(nil) returned %d types, want 0", len(filtered))
	}
}

// TestParseClientPublicKey_Nil verifies error on nil key.
func TestParseClientPublicKey_Nil(t *testing.T) {
	_, err := parseClientPublicKey(nil)
	if err == nil {
		t.Fatal("parseClientPublicKey(nil) should return error")
	}
}

// TestParseClientPublicKey_EmptyPEM verifies error on empty PEM.
func TestParseClientPublicKey_EmptyPEM(t *testing.T) {
	key := &Key{
		KeyId:        "test",
		PublicKeyPem: "",
	}
	_, err := parseClientPublicKey(key)
	if err == nil {
		t.Fatal("parseClientPublicKey() with empty PEM should return error")
	}
}

// TestParseClientPublicKey_ValidRSA verifies valid RSA key parsing.
func TestParseClientPublicKey_ValidRSA(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	pub, err := parseClientPublicKey(key)
	if err != nil {
		t.Fatalf("parseClientPublicKey() error = %v", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Errorf("parseClientPublicKey() returned %T, want *rsa.PublicKey", pub)
	}
}

// TestIsYubiKeyClientKey verifies YubiKey metadata detection.
func TestIsYubiKeyClientKey(t *testing.T) {
	nilKey := isYubiKeyClientKey(nil)
	if nilKey {
		t.Error("isYubiKeyClientKey(nil) = true, want false")
	}

	noMetaKey := &Key{}
	if isYubiKeyClientKey(noMetaKey) {
		t.Error("isYubiKeyClientKey(key without metadata) = true, want false")
	}

	yubiKey := &Key{
		Metadata: map[string]string{
			"client_key_provider": "yubikey",
		},
	}
	if !isYubiKeyClientKey(yubiKey) {
		t.Error("isYubiKeyClientKey(yubikey) = false, want true")
	}

	// Case-insensitive check
	yubiKeyUpper := &Key{
		Metadata: map[string]string{
			"client_key_provider": "YubiKey",
		},
	}
	if !isYubiKeyClientKey(yubiKeyUpper) {
		t.Error("isYubiKeyClientKey(YubiKey) = false, want true (case insensitive)")
	}
}

// TestShouldAllowYubiKeyPlainClientEnvelope verifies touch-required detection.
func TestShouldAllowYubiKeyPlainClientEnvelope(t *testing.T) {
	// nil key
	if shouldAllowYubiKeyPlainClientEnvelope(nil) {
		t.Error("shouldAllowYubiKeyPlainClientEnvelope(nil) = true, want false")
	}

	// non-yubikey
	normalKey := &Key{
		Metadata: map[string]string{"client_key_provider": "software"},
	}
	if shouldAllowYubiKeyPlainClientEnvelope(normalKey) {
		t.Error("shouldAllowYubiKeyPlainClientEnvelope(non-yubikey) = true, want false")
	}

	// yubikey without touch-required
	yubiKey := &Key{
		Metadata: map[string]string{"client_key_provider": "yubikey"},
	}
	if shouldAllowYubiKeyPlainClientEnvelope(yubiKey) {
		t.Error("shouldAllowYubiKeyPlainClientEnvelope(yubikey without touch-required) = true, want false")
	}

	// yubikey with touch-required=true
	yubiKeyTouch := &Key{
		Metadata: map[string]string{
			"client_key_provider":           "yubikey",
			yubiKeyTouchRequiredMetadataKey: "true",
		},
	}
	if !shouldAllowYubiKeyPlainClientEnvelope(yubiKeyTouch) {
		t.Error("shouldAllowYubiKeyPlainClientEnvelope(yubikey with touch-required=true) = false, want true")
	}
}
