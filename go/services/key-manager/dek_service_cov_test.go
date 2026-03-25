//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCoverageFinal80_PublicKeyToPEM_RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, keyType, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM RSA: %v", err)
	}
	if keyType != KeyType_KEY_TYPE_RSA_2048 {
		t.Fatalf("expected RSA_2048, got %v", keyType)
	}
	if pemStr == "" {
		t.Fatal("empty PEM")
	}
}

func TestCoverageFinal80_PublicKeyToPEM_ECC(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemStr, keyType, err := publicKeyToPEM(&ecKey.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM ECC: %v", err)
	}
	if keyType != KeyType_KEY_TYPE_ECC_P256 {
		t.Fatalf("expected ECC_P256, got %v", keyType)
	}
	if pemStr == "" {
		t.Fatal("empty PEM")
	}
}

func TestCoverageFinal80_PublicKeyToPEM_Unsupported(t *testing.T) {
	_, _, err := publicKeyToPEM("not-a-key")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestCoverageFinal80_DEKService_CreateDeniedResponse(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)
	resp := svc.createDeniedResponse(&UnwrapDEKRequest{}, "test-denial")
	if resp.AccessGranted {
		t.Fatal("expected denied")
	}
	if resp.AccessReason != "test-denial" {
		t.Fatalf("expected reason test-denial, got %s", resp.AccessReason)
	}
}

func TestCoverageFinal80_ParseMetadataBool(t *testing.T) {
	if parseMetadataBool("true") != true {
		t.Fatal("expected true")
	}
	if parseMetadataBool("invalid") != false {
		t.Fatal("expected false for invalid")
	}
	if parseMetadataBool("") != false {
		t.Fatal("expected false for empty")
	}
}

func TestCoverageFinal80_IsYubiKeySubjectKey(t *testing.T) {
	if isYubiKeySubjectKey(nil) {
		t.Fatal("expected false for nil")
	}
	if isYubiKeySubjectKey(&Key{}) {
		t.Fatal("expected false for no metadata")
	}
	if !isYubiKeySubjectKey(&Key{Metadata: map[string]string{"client_key_provider": "yubikey"}}) {
		t.Fatal("expected true")
	}
}

func TestCoverageFinal80_ShouldUseYubiKeyPlainEnvelope(t *testing.T) {
	// Non-yubikey
	if shouldUseYubiKeyPlainEnvelope(&Key{Metadata: map[string]string{}}) {
		t.Fatal("expected false for non-yubikey")
	}
	// Yubikey without touch required
	if shouldUseYubiKeyPlainEnvelope(&Key{Metadata: map[string]string{"client_key_provider": "yubikey"}}) {
		t.Fatal("expected false without touch required")
	}
	// Yubikey with touch required
	if !shouldUseYubiKeyPlainEnvelope(&Key{Metadata: map[string]string{
		"client_key_provider":    "yubikey",
		"yubikey_touch_required": "true",
	}}) {
		t.Fatal("expected true with touch required")
	}
}

func TestCoverageFinal80_LogDEKAccess(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)

	ctx := context.Background()
	req := &UnwrapDEKRequest{
		Subject:  "test-user",
		Resource: "test-resource",
		Action:   "read",
		KeyId:    "key-1",
		Context:  map[string]string{"client_ip": "127.0.0.1"},
	}

	// Should not panic
	svc.logDEKAccess(ctx, req, true, "allowed", []string{"rule1"})
	svc.logDEKAccess(ctx, req, false, "denied", nil)
}

func TestCoverageFinal80_EncryptDEKForSubject_ECC(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	subjectKey := &Key{
		KeyId:    "ecc-subject-key",
		KeyType:  KeyType_KEY_TYPE_ECC_P256,
		Metadata: map[string]string{},
	}

	encrypted, keyID, err := svc.encryptDEKForSubject(subjectKey, &ecKey.PublicKey, dek, "ecc-user")
	if err != nil {
		t.Fatalf("encryptDEKForSubject ECC: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("empty encrypted DEK")
	}
	if keyID == "" {
		t.Fatal("empty key ID")
	}
}

// NOTE: TestCoverageFinal80_EncryptDEKForSubject_FIPS_RejectsECC removed — duplicate of
// TestEncryptDEKForSubject_FIPSRejectsNonRSA in coverage_final_push_test.go.

func TestCoverageFinal80_EncryptDEKForSubject_UnsupportedKeyType(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}

	subjectKey := &Key{
		KeyId:    "bad-key",
		Metadata: map[string]string{},
	}
	_, _, err := svc.encryptDEKForSubject(subjectKey, "not-a-key", dek, "bad-user")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestCoverageFinal80_DEKService_RegisterClientPublicKey(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)
	ctx := context.Background()

	pubPEM := generateRSAPEM(t)
	err := svc.RegisterClientPublicKey(ctx, "test-subject", pubPEM)
	if err != nil {
		t.Fatalf("RegisterClientPublicKey: %v", err)
	}

	// Invalid PEM
	err = svc.RegisterClientPublicKey(ctx, "test-subject", "not-pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestCoverageFinal80_PublicKeyToPEM_RSA3072(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	_, kt, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kt != KeyType_KEY_TYPE_RSA_3072 {
		t.Fatalf("expected RSA_3072, got %v", kt)
	}
}

func TestCoverageFinal80_PublicKeyToPEM_ECCP384(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, kt, err := publicKeyToPEM(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P384 {
		t.Fatalf("expected ECC_P384, got %v", kt)
	}
}

func TestCoverageFinal80_PublicKeyToPEM_ECCP521(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, kt, err := publicKeyToPEM(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P521 {
		t.Fatalf("expected ECC_P521, got %v", kt)
	}
}

func TestCoverageFinal80_ValidateUnwrapRequest(t *testing.T) {
	svc := NewDEKUnwrappingService(
		NewInMemoryKeyStore(),
		NewDefaultProviderFactory("RSA2048"),
		NewInMemoryClientKeyStore(),
		false,
	)

	// Missing subject
	err := svc.validateUnwrapRequest(&UnwrapDEKRequest{Resource: "r", KeyId: "k", EncryptedDek: []byte{1}})
	if err == nil {
		t.Fatal("expected error for missing subject")
	}

	// Missing resource
	err = svc.validateUnwrapRequest(&UnwrapDEKRequest{Subject: "s", KeyId: "k", EncryptedDek: []byte{1}})
	if err == nil {
		t.Fatal("expected error for missing resource")
	}

	// Missing key ID
	err = svc.validateUnwrapRequest(&UnwrapDEKRequest{Subject: "s", Resource: "r", EncryptedDek: []byte{1}})
	if err == nil {
		t.Fatal("expected error for missing key ID")
	}

	// Missing encrypted DEK
	err = svc.validateUnwrapRequest(&UnwrapDEKRequest{Subject: "s", Resource: "r", KeyId: "k"})
	if err == nil {
		t.Fatal("expected error for missing encrypted DEK")
	}

	// Valid with default action
	req := &UnwrapDEKRequest{Subject: "s", Resource: "r", KeyId: "k", EncryptedDek: []byte{1}}
	err = svc.validateUnwrapRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Action != "unwrap_dek" {
		t.Fatalf("expected default action, got %s", req.Action)
	}
}
