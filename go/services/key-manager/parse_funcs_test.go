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

// TestParseKeyTypeString covers all supported aliases and unknown values.
func TestParseKeyTypeString(t *testing.T) {
	tests := []struct {
		input   string
		want    KeyType
		wantErr bool
	}{
		{"RSA2048", KeyType_KEY_TYPE_RSA_2048, false},
		{"KEY_TYPE_RSA_2048", KeyType_KEY_TYPE_RSA_2048, false},
		{"RSA3072", KeyType_KEY_TYPE_RSA_3072, false},
		{"KEY_TYPE_RSA_3072", KeyType_KEY_TYPE_RSA_3072, false},
		{"RSA4096", KeyType_KEY_TYPE_RSA_4096, false},
		{"KEY_TYPE_RSA_4096", KeyType_KEY_TYPE_RSA_4096, false},
		{"ECC256", KeyType_KEY_TYPE_ECC_P256, false},
		{"P256", KeyType_KEY_TYPE_ECC_P256, false},
		{"KEY_TYPE_ECC_P256", KeyType_KEY_TYPE_ECC_P256, false},
		{"ECC384", KeyType_KEY_TYPE_ECC_P384, false},
		{"P384", KeyType_KEY_TYPE_ECC_P384, false},
		{"ECC521", KeyType_KEY_TYPE_ECC_P521, false},
		{"P521", KeyType_KEY_TYPE_ECC_P521, false},
		{"KYBER512", KeyType_KEY_TYPE_KYBER_512, false},
		{"KEY_TYPE_KYBER_512", KeyType_KEY_TYPE_KYBER_512, false},
		{"KYBER768", KeyType_KEY_TYPE_KYBER_768, false},
		{"KYBER1024", KeyType_KEY_TYPE_KYBER_1024, false},
		// Case insensitive with normalization
		{"rsa2048", KeyType_KEY_TYPE_RSA_2048, false},
		{"  RSA2048  ", KeyType_KEY_TYPE_RSA_2048, false},
		// Unknown
		{"unknown", KeyType_KEY_TYPE_UNSPECIFIED, true},
		{"", KeyType_KEY_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseKeyTypeString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyTypeString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseKeyTypeString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseProviderTypeString covers all supported values and unknown.
func TestParseProviderTypeString(t *testing.T) {
	tests := []struct {
		input   string
		want    KeyProviderType
		wantErr bool
	}{
		{"software", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, false},
		{"SOFTWARE", KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, false},
		{"hsm", KeyProviderType_KEY_PROVIDER_TYPE_HSM, false},
		{"smart_card", KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD, false},
		{"smartcard", KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD, false},
		{"usb_token", KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN, false},
		{"usb", KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN, false},
		{"unknown", KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED, true},
		{"", KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseProviderTypeString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseProviderTypeString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseProviderTypeString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseKeyStatusString covers all status values, empty default, and unknown.
func TestParseKeyStatusString(t *testing.T) {
	tests := []struct {
		input   string
		want    KeyStatus
		wantErr bool
	}{
		{"", KeyStatus_KEY_STATUS_ACTIVE, false},           // empty → active default
		{"active", KeyStatus_KEY_STATUS_ACTIVE, false},
		{"ACTIVE", KeyStatus_KEY_STATUS_ACTIVE, false},
		{"inactive", KeyStatus_KEY_STATUS_INACTIVE, false},
		{"pending_rotation", KeyStatus_KEY_STATUS_PENDING_ROTATION, false},
		{"deprecated", KeyStatus_KEY_STATUS_DEPRECATED, false},
		{"compromised", KeyStatus_KEY_STATUS_COMPROMISED, false},
		{"revoked", KeyStatus_KEY_STATUS_REVOKED, false},
		{"unknown_status", KeyStatus_KEY_STATUS_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.input+"_or_default", func(t *testing.T) {
			got, err := parseKeyStatusString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseKeyStatusString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseKeyStatusString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParseRotationPolicyString covers all policies, empty default, and unknown.
func TestParseRotationPolicyString(t *testing.T) {
	tests := []struct {
		input   string
		want    RotationPolicy
		wantErr bool
	}{
		{"", RotationPolicy_ROTATION_POLICY_MANUAL, false},          // empty → manual default
		{"manual", RotationPolicy_ROTATION_POLICY_MANUAL, false},
		{"MANUAL", RotationPolicy_ROTATION_POLICY_MANUAL, false},
		{"time_based", RotationPolicy_ROTATION_POLICY_TIME_BASED, false},
		{"time-based", RotationPolicy_ROTATION_POLICY_TIME_BASED, false},
		{"usage_based", RotationPolicy_ROTATION_POLICY_USAGE_BASED, false},
		{"usage-based", RotationPolicy_ROTATION_POLICY_USAGE_BASED, false},
		{"combined", RotationPolicy_ROTATION_POLICY_COMBINED, false},
		{"unknown", RotationPolicy_ROTATION_POLICY_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(tt.input+"_or_default", func(t *testing.T) {
			got, err := parseRotationPolicyString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRotationPolicyString(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseRotationPolicyString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestParsePrivateKeyPEM_RSA verifies RSA private key PEM parsing.
func TestParsePrivateKeyPEM_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	got, err := parsePrivateKeyPEM(pemData, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM() error = %v", err)
	}
	if _, ok := got.(*rsa.PrivateKey); !ok {
		t.Errorf("parsePrivateKeyPEM() returned %T, want *rsa.PrivateKey", got)
	}
}

// TestParsePrivateKeyPEM_ECC verifies EC private key PEM parsing.
func TestParsePrivateKeyPEM_ECC(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	got, err := parsePrivateKeyPEM(pemData, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("parsePrivateKeyPEM() error = %v", err)
	}
	if _, ok := got.(*ecdsa.PrivateKey); !ok {
		t.Errorf("parsePrivateKeyPEM() returned %T, want *ecdsa.PrivateKey", got)
	}
}

// TestParsePrivateKeyPEM_InvalidPEM verifies error on non-PEM input.
func TestParsePrivateKeyPEM_InvalidPEM(t *testing.T) {
	_, err := parsePrivateKeyPEM("not a pem block", KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Error("parsePrivateKeyPEM() with invalid PEM should fail")
	}
}

// TestParsePrivateKeyPEM_WrongKeyType verifies error for unsupported key types.
func TestParsePrivateKeyPEM_WrongKeyType(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	_, err := parsePrivateKeyPEM(pemData, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Error("parsePrivateKeyPEM() with Kyber type should fail (not supported)")
	}
}

// TestParsePrivateKeyPEM_WrongPEMForKeyType verifies error when PEM key type
// doesn't match the requested key type.
func TestParsePrivateKeyPEM_WrongPEMForKeyType(t *testing.T) {
	// Generate EC key but try to parse as RSA
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(priv)
	pemData := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))

	_, err := parsePrivateKeyPEM(pemData, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Error("parsePrivateKeyPEM() EC PEM for RSA type should fail")
	}
}
