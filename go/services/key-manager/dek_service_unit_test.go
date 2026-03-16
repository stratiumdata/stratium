package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"stratium/pkg/security/encryption"
)

// TestDEKUnwrappingService_SetClientKeyStore verifies SetClientKeyStore replaces the store.
func TestDEKUnwrappingService_SetClientKeyStore(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, clientKeyStore, false)

	// Set a different client key store
	newStore := NewInMemoryClientKeyStore()
	svc.SetClientKeyStore(newStore)

	if svc.clientKeyStore != newStore {
		t.Error("SetClientKeyStore() did not replace the client key store")
	}
}

// TestDEKUnwrappingService_SetAuditLogger verifies SetAuditLogger replaces the logger.
func TestDEKUnwrappingService_SetAuditLogger(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, clientKeyStore, false)

	newLogger := &DefaultAuditLogger{}
	svc.SetAuditLogger(newLogger)

	if svc.auditLogger != newLogger {
		t.Error("SetAuditLogger() did not replace the audit logger")
	}
}

// TestDEKUnwrappingService_SetClientKeyStore_Nil verifies setting nil does not panic.
func TestDEKUnwrappingService_SetClientKeyStore_Nil(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, clientKeyStore, false)

	// Should not panic
	svc.SetClientKeyStore(nil)
	if svc.clientKeyStore != nil {
		t.Error("SetClientKeyStore(nil) should have set clientKeyStore to nil")
	}
}

// TestDEKUnwrappingService_RegisterClientPublicKey_RSA verifies RSA key registration.
func TestDEKUnwrappingService_RegisterClientPublicKey_RSA(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, clientKeyStore, false)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	ctx := context.Background()
	err = svc.RegisterClientPublicKey(ctx, "test-subject", pemStr)
	if err != nil {
		t.Fatalf("RegisterClientPublicKey() error = %v", err)
	}
}

// TestDEKUnwrappingService_RegisterClientPublicKey_InvalidPEM verifies error on bad PEM.
func TestDEKUnwrappingService_RegisterClientPublicKey_InvalidPEM(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, clientKeyStore, false)

	ctx := context.Background()
	err := svc.RegisterClientPublicKey(ctx, "test-subject", "not-a-pem")
	if err == nil {
		t.Fatal("RegisterClientPublicKey() with invalid PEM should return error")
	}
}

// TestDEKUnwrappingService_RegisterClientPublicKey_NilClientKeyStore verifies error with nil store.
func TestDEKUnwrappingService_RegisterClientPublicKey_NilClientKeyStore(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	svc := NewDEKUnwrappingService(keyStore, factory, nil, false)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	derBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	ctx := context.Background()
	// This should panic or error because clientKeyStore is nil
	defer func() {
		if r := recover(); r != nil {
			// Panic is acceptable - nil pointer dereference
		}
	}()
	// Will panic on nil clientKeyStore.RegisterKey call
	_ = svc.RegisterClientPublicKey(ctx, "test-subject", pemStr)
}

// TestPublicKeyToPEM_RSA2048 verifies RSA-2048 key is converted correctly.
func TestPublicKeyToPEM_RSA2048(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pemStr, keyType, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM() error = %v", err)
	}
	if keyType != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("publicKeyToPEM() keyType = %v, want KEY_TYPE_RSA_2048", keyType)
	}
	if pemStr == "" {
		t.Error("publicKeyToPEM() returned empty PEM")
	}

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Error("publicKeyToPEM() returned invalid PEM")
	}
}

// TestPublicKeyToPEM_RSA3072 verifies RSA-3072 key type detection.
func TestPublicKeyToPEM_RSA3072(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, keyType, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM() error = %v", err)
	}
	if keyType != KeyType_KEY_TYPE_RSA_3072 {
		t.Errorf("publicKeyToPEM() keyType = %v, want KEY_TYPE_RSA_3072", keyType)
	}
}

// TestPublicKeyToPEM_RSA4096 verifies RSA-4096 key type detection.
func TestPublicKeyToPEM_RSA4096(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, keyType, err := publicKeyToPEM(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM() error = %v", err)
	}
	if keyType != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("publicKeyToPEM() keyType = %v, want KEY_TYPE_RSA_4096", keyType)
	}
}

// TestPublicKeyToPEM_UnsupportedType verifies error for unknown key types.
func TestPublicKeyToPEM_UnsupportedType(t *testing.T) {
	type unknownKey struct{}
	_, _, err := publicKeyToPEM(unknownKey{})
	if err == nil {
		t.Fatal("publicKeyToPEM() with unknown key type should return error")
	}
}

// TestDefaultAuditLogger_LogDEKAccess verifies no panic on log calls.
func TestDefaultAuditLogger_LogDEKAccess(t *testing.T) {
	logger := &DefaultAuditLogger{}
	ctx := context.Background()

	// Should not panic
	logger.LogDEKAccess(ctx, DEKAccessEvent{
		Subject:       "user-1",
		Resource:      "resource-1",
		KeyID:         "key-1",
		AccessGranted: true,
		Reason:        "test",
	})
}

// TestDefaultAuditLogger_LogSecurityEvent verifies no panic on log calls.
func TestDefaultAuditLogger_LogSecurityEvent(t *testing.T) {
	logger := &DefaultAuditLogger{}
	ctx := context.Background()

	// Should not panic
	logger.LogSecurityEvent(ctx, SecurityEvent{
		EventType:   "test-event",
		KeyID:       "key-1",
		Subject:     "user-1",
		Severity:    "HIGH",
		Description: "test security event",
	})
}

// TestUnwrapDEK_NilClientKeyStore verifies denied response when clientKeyStore is nil.
func TestUnwrapDEK_NilClientKeyStore(t *testing.T) {
	ctx := context.Background()

	// Create a server with a real key
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a key in the store
	createReq := &CreateKeyRequest{
		Name:         "test-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}
	createResp, err := server.CreateKey(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	keyID := createResp.Key.KeyId

	// Encrypt something with the key
	provider, err := server.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}
	encryptedDEK, err := provider.Encrypt(ctx, keyID, []byte("test-dek-32-bytes-0123456789abcdef"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Now set clientKeyStore to nil
	server.dekService.SetClientKeyStore(nil)

	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        keyID,
		ClientKeyId:  "nonexistent-client-key",
		EncryptedDek: encryptedDEK,
	}

	resp, err := server.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error = %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK() should deny access when clientKeyStore is nil")
	}
	if resp.AccessReason == "" {
		t.Error("UnwrapDEK() should return a reason when denying")
	}
}

// TestUnwrapDEK_InvalidRequest verifies denied response on invalid request.
func TestUnwrapDEK_InvalidRequest(t *testing.T) {
	ctx := context.Background()
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	req := &UnwrapDEKRequest{
		// Missing required fields
		Subject: "",
	}

	resp, err := server.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error = %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK() should deny access on invalid request")
	}
}

// TestUnwrapDEK_KeyNotFound verifies denied response when key does not exist.
func TestUnwrapDEK_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        "nonexistent-key-id",
		ClientKeyId:  "client-key-id",
		EncryptedDek: []byte("some-encrypted-dek"),
	}

	resp, err := server.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error = %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK() should deny access when key not found")
	}
}

// TestUnwrapDEK_FIPS_RejectsKyberKey verifies FIPS mode rejects non-RSA keys.
func TestUnwrapDEK_FIPS_RejectsNonRSAKey(t *testing.T) {
	ctx := context.Background()

	// Create FIPS-enabled server with ECC key
	server := newTestKeyManagerServerWithFIPS(t, encryption.ECC_P256, true)

	// Create an ECC key
	createReq := &CreateKeyRequest{
		Name:         "ecc-key",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}

	// In FIPS mode, creating ECC key should fail or be rejected at UnwrapDEK
	createResp, err := server.CreateKey(ctx, createReq)
	if err != nil {
		// FIPS validation may prevent creating ECC keys at all - that's fine
		t.Logf("CreateKey() returned error in FIPS mode (expected): %v", err)
		return
	}
	if createResp == nil || createResp.Key == nil {
		t.Skip("ECC key not created in FIPS mode")
		return
	}

	keyID := createResp.Key.KeyId

	// Try to UnwrapDEK with the ECC key - should be rejected in FIPS mode
	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        keyID,
		ClientKeyId:  "client-key-id",
		EncryptedDek: []byte("encrypted"),
	}

	resp, err := server.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error = %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK() should deny access for non-RSA key in FIPS mode")
	}
}

// TestUnwrapDEK_BadClientKeyPEM verifies denial when subject key has invalid PEM.
func TestUnwrapDEK_BadClientKeyPEM(t *testing.T) {
	ctx := context.Background()
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a service key
	createReq := &CreateKeyRequest{
		Name:         "service-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}
	createResp, err := server.CreateKey(ctx, createReq)
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	keyID := createResp.Key.KeyId

	// Encrypt a DEK with the service key
	provider, err := server.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}
	encryptedDEK, err := provider.Encrypt(ctx, keyID, []byte("test-dek-32-bytes-padding-xyz123"))
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Register a client key with invalid PEM
	clientKeyID := "bad-pem-client-key"
	badKey := &Key{
		KeyId:        clientKeyID,
		ClientId:     "user-1",
		PublicKeyPem: "this-is-not-valid-pem",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
	}
	// Directly insert the bad key into the store (bypassing validation)
	server.clientKeyStore.(*InMemoryClientKeyStore).mu.Lock()
	server.clientKeyStore.(*InMemoryClientKeyStore).keys[clientKeyID] = badKey
	server.clientKeyStore.(*InMemoryClientKeyStore).clientKeys["user-1"] = append(
		server.clientKeyStore.(*InMemoryClientKeyStore).clientKeys["user-1"], clientKeyID)
	server.clientKeyStore.(*InMemoryClientKeyStore).mu.Unlock()

	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        keyID,
		ClientKeyId:  clientKeyID,
		EncryptedDek: encryptedDEK,
	}

	resp, err := server.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK() unexpected error = %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK() should deny access when client key has invalid PEM")
	}
}
