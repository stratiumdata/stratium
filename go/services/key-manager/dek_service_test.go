package key_manager

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDEKUnwrappingService_EncryptDEKForSubject_YubiKeyWithoutTouchUsesRSAInNonFIPS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	service := &DEKUnwrappingService{fipsEnabled: false}
	dek := []byte("0123456789abcdef0123456789abcdef")
	subjectKey := &Key{
		KeyId: "client-key-yubikey",
		Metadata: map[string]string{
			"client_key_provider": "yubikey",
		},
	}

	wrapped, subjectKeyID, err := service.encryptDEKForSubject(subjectKey, &privateKey.PublicKey, dek, "user-1")
	if err != nil {
		t.Fatalf("encryptDEKForSubject() failed: %v", err)
	}
	if subjectKeyID == "" {
		t.Fatalf("expected subject key id")
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrapped, nil)
	if err != nil {
		t.Fatalf("expected RSA encrypted DEK in non-FIPS mode when touch is not required: %v", err)
	}
	if string(plaintext) != string(dek) {
		t.Fatalf("unexpected decrypted DEK payload")
	}
}

func TestDEKUnwrappingService_EncryptDEKForSubject_YubiKeyEnvelopeFIPS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	service := &DEKUnwrappingService{fipsEnabled: true}
	dek := []byte("0123456789abcdef0123456789abcdef")
	subjectKey := &Key{
		KeyId: "client-key-yubikey",
		Metadata: map[string]string{
			"client_key_provider": "yubikey",
		},
	}

	wrapped, subjectKeyID, err := service.encryptDEKForSubject(subjectKey, &privateKey.PublicKey, dek, "user-1")
	if err != nil {
		t.Fatalf("encryptDEKForSubject() failed: %v", err)
	}
	if subjectKeyID == "" {
		t.Fatalf("expected subject key id")
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrapped, nil)
	if err != nil {
		t.Fatalf("expected RSA encrypted DEK in FIPS mode: %v", err)
	}
	if string(plaintext) != string(dek) {
		t.Fatalf("unexpected decrypted DEK payload")
	}
}

func TestDEKUnwrappingService_EncryptDEKForSubject_YubiKeyEnvelopeFIPSWithTouchRequired(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	service := &DEKUnwrappingService{fipsEnabled: true}
	dek := []byte("0123456789abcdef0123456789abcdef")
	subjectKey := &Key{
		KeyId: "client-key-yubikey-touch",
		Metadata: map[string]string{
			"client_key_provider":           "yubikey",
			yubiKeyTouchRequiredMetadataKey: "true",
		},
	}

	wrapped, subjectKeyID, err := service.encryptDEKForSubject(subjectKey, &privateKey.PublicKey, dek, "user-1")
	if err != nil {
		t.Fatalf("encryptDEKForSubject() failed: %v", err)
	}
	if subjectKeyID == "" {
		t.Fatalf("expected subject key id")
	}

	var envelope yubiKeyPlainDEKEnvelope
	if err := json.Unmarshal(wrapped, &envelope); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}
	if envelope.Version != yubiKeyPlainDEKEnvelopeVersion {
		t.Fatalf("unexpected envelope version: %s", envelope.Version)
	}
	if envelope.DEK != base64.StdEncoding.EncodeToString(dek) {
		t.Fatalf("unexpected envelope DEK payload")
	}
}

func TestDEKUnwrappingService_EncryptDEKForSubject_YubiKeyTouchRequiredUsesPlainEnvelopeInNonFIPS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate rsa key: %v", err)
	}

	service := &DEKUnwrappingService{fipsEnabled: false}
	dek := []byte("0123456789abcdef0123456789abcdef")
	subjectKey := &Key{
		KeyId: "client-key-yubikey-touch",
		Metadata: map[string]string{
			"client_key_provider":           "yubikey",
			yubiKeyTouchRequiredMetadataKey: "true",
		},
	}

	wrapped, subjectKeyID, err := service.encryptDEKForSubject(subjectKey, &privateKey.PublicKey, dek, "user-1")
	if err != nil {
		t.Fatalf("encryptDEKForSubject() failed: %v", err)
	}
	if subjectKeyID == "" {
		t.Fatalf("expected subject key id")
	}

	var envelope yubiKeyPlainDEKEnvelope
	if err := json.Unmarshal(wrapped, &envelope); err != nil {
		t.Fatalf("failed to decode envelope: %v", err)
	}
	if envelope.Version != yubiKeyPlainDEKEnvelopeVersion {
		t.Fatalf("unexpected envelope version: %s", envelope.Version)
	}
	if envelope.DEK != base64.StdEncoding.EncodeToString(dek) {
		t.Fatalf("unexpected envelope DEK payload")
	}
}
