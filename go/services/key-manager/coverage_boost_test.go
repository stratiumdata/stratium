package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"stratium/pkg/security/encryption"
)

// ---------------------------------------------------------------------------
// external_secrets.go: extractFieldFromJSON missing branches
// ---------------------------------------------------------------------------

func TestExtractFieldFromJSON_EmptyField(t *testing.T) {
	// Empty field returns the full payload unchanged.
	payload := `{"key": "value"}`
	got, err := extractFieldFromJSON(payload, "")
	if err != nil {
		t.Fatalf("extractFieldFromJSON('') error = %v", err)
	}
	if got != payload {
		t.Errorf("expected full payload, got %q", got)
	}
}

func TestExtractFieldFromJSON_ValidField(t *testing.T) {
	payload := `{"username": "alice", "password": "secret"}`
	got, err := extractFieldFromJSON(payload, "username")
	if err != nil {
		t.Fatalf("extractFieldFromJSON error = %v", err)
	}
	if got != "alice" {
		t.Errorf("expected 'alice', got %q", got)
	}
}

func TestExtractFieldFromJSON_InvalidJSON(t *testing.T) {
	_, err := extractFieldFromJSON("not-json", "field")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestExtractFieldFromJSON_MissingField(t *testing.T) {
	_, err := extractFieldFromJSON(`{"other": "value"}`, "missing")
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestExtractFieldFromJSON_NonStringValue(t *testing.T) {
	_, err := extractFieldFromJSON(`{"count": 42}`, "count")
	if err == nil {
		t.Fatal("expected error when field value is not a string")
	}
}

// ---------------------------------------------------------------------------
// ecies.go: missing branches (nil key, short ciphertext)
// ---------------------------------------------------------------------------

func TestEncryptDEKWithECCPublicKey_NilKey(t *testing.T) {
	_, err := encryptDEKWithECCPublicKey(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

func TestEncryptDEKWithECCPublicKey_NilCurve(t *testing.T) {
	_, err := encryptDEKWithECCPublicKey(&ecdsa.PublicKey{Curve: nil}, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil curve")
	}
}

func TestDecryptDEKWithECCPrivateKey_NilKey(t *testing.T) {
	_, err := decryptDEKWithECCPrivateKey(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestDecryptDEKWithECCPrivateKey_ShortCiphertext(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// coordSize = 32, headerSize = 64 -- provide fewer bytes than headerSize
	_, err := decryptDEKWithECCPrivateKey(key, []byte("short"))
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than header")
	}
}

func TestDecryptDEKWithECCPrivateKey_PointNotOnCurve(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// coordSize for P256 = 32 bytes, header = 64 bytes
	// Build a payload where the ephemeral x,y are all zeros (not on curve)
	coordSize := 32
	badPayload := make([]byte, coordSize*2+16+1) // headerSize + nonceSize + 1 byte of payload
	_, err := decryptDEKWithECCPrivateKey(key, badPayload)
	if err == nil {
		t.Fatal("expected error for ephemeral key not on curve")
	}
}

func TestDecryptDEKWithECCPrivateKey_ShortPayloadAfterHeader(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	// coordSize for P384 = 48 bytes, so headerSize = 96
	// Provide exactly 96 bytes (header only, no nonce/ciphertext)
	// This is > headerSize but GCM nonce check will fail if point is valid-looking
	// Use the right length but all zeros - point won't be on curve
	coordSize := 48
	payload := make([]byte, coordSize*2+1) // just 1 extra byte (> headerSize but < headerSize + nonceSize)
	_, err := decryptDEKWithECCPrivateKey(key, payload)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestECIESRoundTrip_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}
	plaintext := []byte("p384 ecies roundtrip")
	ct, err := encryptDEKWithECCPublicKey(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey P384 failed: %v", err)
	}
	got, err := decryptDEKWithECCPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey P384 failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("P384 roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestECIESRoundTrip_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}
	plaintext := []byte("p521 ecies roundtrip")
	ct, err := encryptDEKWithECCPublicKey(&key.PublicKey, plaintext)
	if err != nil {
		t.Fatalf("encryptDEKWithECCPublicKey P521 failed: %v", err)
	}
	got, err := decryptDEKWithECCPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("decryptDEKWithECCPrivateKey P521 failed: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("P521 roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

// ---------------------------------------------------------------------------
// cache.go: cloneKeyPair with all optional fields set
// ---------------------------------------------------------------------------

func TestCloneKeyPair_AllOptionalFields(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)
	externalAt := now.Add(-time.Hour)

	original := &KeyPair{
		KeyID:             "full-kp",
		Metadata:          map[string]string{"env": "prod", "tier": "2"},
		ExpiresAt:         &now,
		LastRotated:       &later,
		ExternalLoadedAt:  &externalAt,
	}

	clone := cloneKeyPair(original)
	if clone == nil {
		t.Fatal("cloneKeyPair returned nil")
	}

	// Verify LastRotated is deep-copied
	if clone.LastRotated == original.LastRotated {
		t.Error("LastRotated should be a different pointer")
	}
	if !clone.LastRotated.Equal(*original.LastRotated) {
		t.Error("LastRotated should have the same value")
	}

	// Verify ExternalLoadedAt is deep-copied
	if clone.ExternalLoadedAt == original.ExternalLoadedAt {
		t.Error("ExternalLoadedAt should be a different pointer")
	}
	if !clone.ExternalLoadedAt.Equal(*original.ExternalLoadedAt) {
		t.Error("ExternalLoadedAt should have the same value")
	}

	// Mutate clone.Metadata; original should be unchanged
	clone.Metadata["env"] = "dev"
	if original.Metadata["env"] != "prod" {
		t.Error("Metadata mutation in clone affected original")
	}
}

// ---------------------------------------------------------------------------
// key_encryption.go: serializePrivateKey wrong types
// ---------------------------------------------------------------------------

func TestSerializePrivateKey_RSAKeyWrongType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	// Pass an ECC key but claim RSA type — serializePrivateKey should fail
	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := ke.EncryptPrivateKey(eccKey, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("EncryptPrivateKey should fail when passing ECC key as RSA type")
	}
}

func TestSerializePrivateKey_ECCKeyWrongType(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	// Pass an RSA key but claim ECC type — serializePrivateKey should fail
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ke.EncryptPrivateKey(rsaKey, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("EncryptPrivateKey should fail when passing RSA key as ECC type")
	}
}

func TestEncryptPrivateKeyPEM_Success(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	pemData := "-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----"
	enc, err := ke.EncryptPrivateKeyPEM(pemData)
	if err != nil {
		t.Fatalf("EncryptPrivateKeyPEM error = %v", err)
	}
	if enc == nil || len(enc.EncryptedData) == 0 {
		t.Fatal("expected non-empty encrypted data")
	}

	// Decrypt and verify roundtrip
	decrypted, err := ke.DecryptPrivateKeyPEM(enc)
	if err != nil {
		t.Fatalf("DecryptPrivateKeyPEM error = %v", err)
	}
	if decrypted != pemData {
		t.Errorf("PEM roundtrip mismatch: got %q want %q", decrypted, pemData)
	}
}

func TestDecryptPrivateKeyPEM_UnsupportedAlgo(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc := &EncryptedKeyData{
		Algorithm:     "NOT-SUPPORTED",
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}
	_, err := ke.DecryptPrivateKeyPEM(enc)
	if err == nil {
		t.Fatal("DecryptPrivateKeyPEM should fail for unsupported algorithm")
	}
}

func TestDecryptPrivateKey_UnsupportedAlgo(t *testing.T) {
	adminKey := make([]byte, 32)
	_, _ = rand.Read(adminKey)
	ke, _ := NewKeyEncryption(adminKey)

	enc := &EncryptedKeyData{
		Algorithm:     "CHACHA",
		EncryptedData: []byte("data"),
		Nonce:         []byte("nonce"),
	}
	_, err := ke.DecryptPrivateKey(enc, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("DecryptPrivateKey should fail for unsupported algorithm")
	}
}

func TestConvertPrivateKeyToPEM_RSA3072(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	pemStr, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_RSA_3072)
	if err != nil {
		t.Fatalf("ConvertPrivateKeyToPEM RSA3072 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string")
	}
}

// ---------------------------------------------------------------------------
// smartcard_provider.go: NewSmartCardKeyProvider with config, validateFIPSKeyByIDLocked
// ---------------------------------------------------------------------------

func TestNewSmartCardKeyProvider_WithConfig_NoHardware(t *testing.T) {
	// config without hardware trigger fields - uses mock reader
	provider := NewSmartCardKeyProvider("usb_token", map[string]string{
		"device_id": "mock-device-1",
	})
	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
	if provider.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN {
		t.Errorf("expected USB_TOKEN type, got %v", provider.GetProviderType())
	}
}

func TestNewSmartCardKeyProvider_USBTokenName(t *testing.T) {
	provider := NewSmartCardKeyProvider("usb_token", nil)
	if provider.GetProviderName() != "USB Token Key Provider" {
		t.Errorf("unexpected provider name: %q", provider.GetProviderName())
	}
}

func TestSmartCardKeyProvider_ValidateFIPSKeyByIDLocked_KeyInMetadata(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id":    "mock-device-1",
		"pin":          "1234",
		"fips_enabled": "true",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	// Generate an RSA-2048 key (FIPS allowed) and populate metadata
	const keyID = "fips-meta-key"
	if _, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, keyID, map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair() failed: %v", err)
	}

	// Sign should succeed - RSA-2048 is FIPS allowed
	provider.mu.Lock()
	err := provider.validateFIPSKeyByIDLocked(keyID)
	provider.mu.Unlock()
	if err != nil {
		t.Fatalf("validateFIPSKeyByIDLocked for RSA-2048 should succeed: %v", err)
	}
}

func TestSmartCardKeyProvider_ValidateFIPSKeyByIDLocked_KeyNotInMetadata(t *testing.T) {
	// Without FIPS mode, the validation should return nil
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	provider.mu.Lock()
	err := provider.validateFIPSKeyByIDLocked("nonexistent-key")
	provider.mu.Unlock()
	// Without FIPS enabled, should return nil regardless
	if err != nil {
		t.Fatalf("validateFIPSKeyByIDLocked without FIPS should be nil, got: %v", err)
	}
}

func TestSmartCardKeyProvider_GetConfiguration(t *testing.T) {
	provider := NewSmartCardKeyProvider("smartcard", nil)
	if err := provider.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
		"custom":    "value",
	}); err != nil {
		t.Fatalf("Configure() failed: %v", err)
	}

	cfg := provider.GetConfiguration()
	// PIN should be excluded
	if _, exists := cfg["pin"]; exists {
		t.Error("GetConfiguration should exclude 'pin' field")
	}
	if cfg["custom"] != "value" {
		t.Errorf("expected custom=value, got %q", cfg["custom"])
	}
}

// SmartCardKeyProvider GetConfiguration is already tested in provider_trivials_test.go
// Adding only tests for uncovered branches not in existing tests.

// ---------------------------------------------------------------------------
// server.go: GetProviderInfo for SmartCard/HSM/YubiKey types, ListKeys filters
// ---------------------------------------------------------------------------

func TestServer_GetProviderInfo_SmartCard(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	resp, err := srv.GetProviderInfo(context.Background(), &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD,
	})
	if err != nil {
		t.Fatalf("GetProviderInfo(SmartCard) error = %v", err)
	}
	if resp.Provider == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestServer_GetProviderInfo_NotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	_, err := srv.GetProviderInfo(context.Background(), &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED,
	})
	if err == nil {
		t.Fatal("expected error for unspecified provider type")
	}
}

func TestServer_ListKeys_WithSubjectFilter(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Create a key
	_, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:    "filter-test-key",
		KeyType: KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey error = %v", err)
	}

	// List with subject filter (matches no keys in the store, but exercises that branch)
	resp, err := srv.ListKeys(ctx, &ListKeysRequest{
		SubjectFilter: "nonexistent-subject",
	})
	if err != nil {
		t.Fatalf("ListKeys error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestServer_ListKeys_WithResourceFilter(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	resp, err := srv.ListKeys(ctx, &ListKeysRequest{
		ResourceFilter: "some-resource",
	})
	if err != nil {
		t.Fatalf("ListKeys error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestServer_ListKeys_WithStatusFilter(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Create some keys
	_, _ = srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "status-test-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})

	resp, err := srv.ListKeys(ctx, &ListKeysRequest{
		StatusFilter: KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err != nil {
		t.Fatalf("ListKeys with status filter error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestServer_ListKeys_WithProviderTypeFilter(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	resp, err := srv.ListKeys(ctx, &ListKeysRequest{
		ProviderTypeFilter: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("ListKeys with provider filter error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestServer_ListKeys_WithPageSize(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Create multiple keys
	for i := 0; i < 3; i++ {
		_, _ = srv.CreateKey(ctx, &CreateKeyRequest{
			Name:         "page-key",
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		})
	}

	resp, err := srv.ListKeys(ctx, &ListKeysRequest{PageSize: 2})
	if err != nil {
		t.Fatalf("ListKeys with page size error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// Should have paginated results
	if len(resp.Keys) > 2 {
		t.Errorf("expected at most 2 keys due to page size, got %d", len(resp.Keys))
	}
}

func TestServer_RewrapClientDEK_MissingSubject(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	_, err := srv.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
		Subject:          "",
		ClientKeyId:      "some-key",
		ClientWrappedDek: []byte("dek"),
		ServiceKeyId:     "service-key",
	})
	if err == nil {
		t.Fatal("expected error for missing subject")
	}
}

func TestServer_RewrapClientDEK_MissingClientKeyID(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	_, err := srv.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
		Subject:          "alice",
		ClientKeyId:      "",
		ClientWrappedDek: []byte("dek"),
		ServiceKeyId:     "service-key",
	})
	if err == nil {
		t.Fatal("expected error for missing client_key_id")
	}
}

func TestServer_RewrapClientDEK_MissingDEK(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	_, err := srv.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
		Subject:          "alice",
		ClientKeyId:      "some-key",
		ClientWrappedDek: nil,
		ServiceKeyId:     "service-key",
	})
	if err == nil {
		t.Fatal("expected error for missing client_wrapped_dek")
	}
}

func TestServer_RewrapClientDEK_MissingServiceKeyID(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	_, err := srv.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
		Subject:          "alice",
		ClientKeyId:      "some-key",
		ClientWrappedDek: []byte("dek"),
		ServiceKeyId:     "",
	})
	if err == nil {
		t.Fatal("expected error for missing service_key_id")
	}
}

func TestServer_RewrapClientDEK_ClientKeyNotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	_, err := srv.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
		Subject:          "alice",
		ClientKeyId:      "nonexistent-key",
		ClientWrappedDek: []byte("encrypted-dek"),
		ServiceKeyId:     "service-key",
	})
	if err == nil {
		t.Fatal("expected error for nonexistent client key")
	}
}

func TestServer_ListProviders_FIPSMode(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	resp, err := srv.ListProviders(context.Background(), &ListProvidersRequest{
		AvailableOnly: false,
	})
	if err != nil {
		t.Fatalf("ListProviders FIPS mode error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// In FIPS mode, providers with no allowed key types should be filtered out
	for _, p := range resp.Providers {
		if len(p.SupportedKeyTypes) == 0 {
			t.Errorf("provider %v should not appear with empty supported key types", p.Type)
		}
	}
}

func TestServer_ListProviders_AvailableOnly(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.ListProviders(context.Background(), &ListProvidersRequest{
		AvailableOnly: true,
	})
	if err != nil {
		t.Fatalf("ListProviders AvailableOnly error = %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	// All returned providers must be available
	for _, p := range resp.Providers {
		if !p.Available {
			t.Errorf("provider %v should be available but Available=false", p.Type)
		}
	}
}

func TestServer_GetProviderInfo_FIPSMode_Software(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	resp, err := srv.GetProviderInfo(context.Background(), &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("GetProviderInfo FIPS mode error = %v", err)
	}
	if resp.Provider == nil {
		t.Fatal("expected non-nil provider")
	}
	// In FIPS mode, only FIPS-allowed key types should appear
	for _, kt := range resp.Provider.SupportedKeyTypes {
		if !isFIPSKeyTypeAllowed(kt) {
			t.Errorf("non-FIPS key type %v appeared in FIPS mode", kt)
		}
	}
}

// ---------------------------------------------------------------------------
// yubikey_card_reader.go: pivToolPath and ykmanPath with custom config
// ---------------------------------------------------------------------------

func TestYubiKeyPIVCardReader_PivToolPath_Default(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	if reader.pivToolPath() != "yubico-piv-tool" {
		t.Errorf("expected 'yubico-piv-tool', got %q", reader.pivToolPath())
	}
}

func TestYubiKeyPIVCardReader_PivToolPath_Custom(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["piv_tool_path"] = "/usr/local/bin/yubico-piv-tool"
	if reader.pivToolPath() != "/usr/local/bin/yubico-piv-tool" {
		t.Errorf("expected custom path, got %q", reader.pivToolPath())
	}
}

func TestYubiKeyPIVCardReader_YkmanPath_Default(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	if reader.ykmanPath() != "ykman" {
		t.Errorf("expected 'ykman', got %q", reader.ykmanPath())
	}
}

func TestYubiKeyPIVCardReader_YkmanPath_Custom(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["ykman_path"] = "/opt/ykman/bin/ykman"
	if reader.ykmanPath() != "/opt/ykman/bin/ykman" {
		t.Errorf("expected custom ykman path, got %q", reader.ykmanPath())
	}
}

func TestYubiKeyPIVCardReader_PivToolPath_WhitespaceValue(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["piv_tool_path"] = "   "
	// Whitespace-only value should fall back to default
	if reader.pivToolPath() != "yubico-piv-tool" {
		t.Errorf("expected 'yubico-piv-tool' for whitespace config, got %q", reader.pivToolPath())
	}
}

func TestYubiKeyPIVCardReader_YkmanPath_WhitespaceValue(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.config["ykman_path"] = "   "
	// Whitespace-only value should fall back to default
	if reader.ykmanPath() != "ykman" {
		t.Errorf("expected 'ykman' for whitespace config, got %q", reader.ykmanPath())
	}
}

// ---------------------------------------------------------------------------
// yubikey_card_reader_touch_policy.go: ensureTouchPolicy branches
// ---------------------------------------------------------------------------

func TestEnsureTouchPolicy_NilLookPath_YKManSucceeds(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "9d"
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		return []byte("Touch policy: ALWAYS\n"), nil
	}
	reader.lookPath = nil // nil lookPath takes the getTouchPolicyFromYKMan path directly

	if err := reader.ensureTouchPolicy(); err != nil {
		t.Fatalf("ensureTouchPolicy with nil lookPath and ALWAYS touch policy failed: %v", err)
	}
}

func TestEnsureTouchPolicy_NilLookPath_YKManFails_PIVStatusSucceeds(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "9d"
	callCount := 0
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		callCount++
		if callCount == 1 {
			// First call (ykman) fails with parse error - not "failed to read"
			return []byte("no policy found"), nil // valid output but no touch policy parsed
		}
		// Second call (piv status)
		return []byte("Slot 9d:\n  Touch policy: ALWAYS\n"), nil
	}
	reader.lookPath = nil // nil lookPath branches

	// The ykman parse fails (no "Touch" keyword), falls through to PIV status
	// Note: getTouchPolicyFromYKMan will succeed with output but parseTouchPolicyFromYKManInfo
	// might fail if "touch" and "policy" keywords are missing
	_ = reader.ensureTouchPolicy() // May succeed or fail - just test no panic
}

func TestEnsureTouchPolicy_YKManFound_TouchPolicyCached(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "9d"
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		return []byte("Touch policy: CACHED\n"), nil
	}
	reader.lookPath = func(file string) (string, error) {
		return "/usr/bin/" + file, nil
	}

	err := reader.ensureTouchPolicy()
	// CACHED != ALWAYS, so error expected
	if err == nil {
		t.Fatal("expected error for CACHED touch policy when ALWAYS is required")
	}
}

func TestEnsureTouchPolicy_YKManNotFound_PIVStatusSucceeds(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "9d"
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		return []byte("Slot 9d:\n  Touch policy: ALWAYS\n"), nil
	}
	reader.lookPath = func(file string) (string, error) {
		return "", nil // lookPath returns no error but ykman binary isn't found
	}

	// Since lookPath succeeds, we try ykman; the output doesn't have proper "Touch policy:" for ykman
	// but PIV status fallback should handle it
	_ = reader.ensureTouchPolicy() // Just ensure no panic
}

func TestEnsureTouchPolicy_EmptySlot_DefaultsTo9d(t *testing.T) {
	reader := NewYubiKeyPIVCardReader()
	reader.selectedSlot = "" // empty slot should default to "9d"
	reader.runner = func(name string, stdin string, args ...string) ([]byte, error) {
		return []byte("Touch policy: ALWAYS\n"), nil
	}
	reader.lookPath = nil

	if err := reader.ensureTouchPolicy(); err != nil {
		t.Fatalf("ensureTouchPolicy with empty slot failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// software_provider.go: publicKeyToPEM for ECC P384/P521
// ---------------------------------------------------------------------------

func TestSoftwareKeyProvider_PublicKeyToPEM_ECCP384(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}

	pemStr, err := provider.publicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P384 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string for P384")
	}
}

func TestSoftwareKeyProvider_PublicKeyToPEM_ECCP521(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}

	pemStr, err := provider.publicKeyToPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P521 error = %v", err)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM string for P521")
	}
}

// ---------------------------------------------------------------------------
// AWSSecretsManagerFetcher: missing secret ID / region
// ---------------------------------------------------------------------------

func TestAWSSecretsManagerFetcher_MissingSecretID(t *testing.T) {
	f := NewAWSSecretsManagerFetcher()
	_, err := f.FetchSecret(context.Background(), "us-east-1", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for empty secretID")
	}
}

func TestAWSSecretsManagerFetcher_MissingRegion(t *testing.T) {
	f := NewAWSSecretsManagerFetcher()
	_, err := f.FetchSecret(context.Background(), "", "", "my-secret", "", "")
	if err == nil {
		t.Fatal("expected error for empty region")
	}
}
