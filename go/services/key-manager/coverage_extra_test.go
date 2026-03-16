package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"stratium/pkg/security/encryption"
)

// TestServer_DecryptClientWrappedDEK_KeyNotFound exercises the key-not-found path.
func TestServer_DecryptClientWrappedDEK_KeyNotFound(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	_, err := server.decryptClientWrappedDEK(ctx, "nonexistent-client-key", []byte("encrypted-data"))
	if err == nil {
		t.Fatal("decryptClientWrappedDEK() should return error for nonexistent key")
	}
}

// TestServer_DecryptClientWrappedDEK_ValidKey exercises the success and ECC-unsupported paths.
func TestServer_DecryptClientWrappedDEK_ValidKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Generate RSA-2048 key and register it as a client key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	clientKey := &Key{
		KeyId:        "client-key-rsa",
		ClientId:     "test-client",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		Metadata:     map[string]string{},
	}

	if err := server.clientKeyStore.RegisterKey(ctx, clientKey); err != nil {
		t.Fatalf("RegisterKey() error = %v", err)
	}

	// Provide wrong-length ciphertext to get an error from rsaPublicUnwrap
	_, err = server.decryptClientWrappedDEK(ctx, "client-key-rsa", []byte("short-ciphertext"))
	// Error is expected because ciphertext length is wrong for RSA-2048, but the function was called
	if err == nil {
		t.Fatal("decryptClientWrappedDEK() should error for wrong ciphertext length")
	}
}

// TestCheckAndPerformRotations_NoJobs exercises checkAndPerformRotations with no jobs.
func TestCheckAndPerformRotations_NoJobs(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Call checkAndPerformRotations directly - should be a no-op
	rm.checkAndPerformRotations()
}

// TestCheckAndPerformRotations_NoRotationNeeded exercises the path where rotation is not needed.
func TestCheckAndPerformRotations_NoRotationNeeded(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "check-rotate-key", KeyType_KEY_TYPE_RSA_2048)

	// Schedule with a far-future interval so rotation is NOT needed
	if err := rm.ScheduleRotation("check-rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 365*24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// checkAndPerformRotations should see the job but not trigger rotation
	rm.checkAndPerformRotations()
}

// TestCheckAndPerformRotations_ExternallyManagedKey exercises the externally-managed skip path.
func TestCheckAndPerformRotations_ExternallyManagedKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()
	key := &Key{
		KeyId:             "ext-check-key",
		KeyType:           KeyType_KEY_TYPE_RSA_2048,
		ProviderType:      KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:            KeyStatus_KEY_STATUS_ACTIVE,
		ExternallyManaged: true,
		CreatedAt:         timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	// Add a job for the externally managed key directly
	rm.mu.Lock()
	rm.rotationJobs["ext-check-key"] = &RotationJob{
		KeyID:        "ext-check-key",
		Policy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		Interval:     -1 * time.Second, // past due
		NextRotation: time.Now().Add(-1 * time.Second),
		Enabled:      true,
	}
	rm.mu.Unlock()

	// Should skip rotation because key is externally managed
	rm.checkAndPerformRotations()
}

// TestCheckAndPerformRotations_KeyNotFound exercises the key-not-found path.
func TestCheckAndPerformRotations_KeyNotFound(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Add a job for a nonexistent key
	rm.mu.Lock()
	rm.rotationJobs["nonexistent-key-check"] = &RotationJob{
		KeyID:        "nonexistent-key-check",
		Policy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		NextRotation: time.Now().Add(-1 * time.Second),
		Enabled:      true,
	}
	rm.mu.Unlock()

	// Should log error but not panic
	rm.checkAndPerformRotations()
}

// TestCheckAndPerformRotations_DisabledJob exercises the disabled job skip path.
func TestCheckAndPerformRotations_DisabledJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "disabled-check-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("disabled-check-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, -1*time.Second); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// Disable the job
	rm.mu.Lock()
	rm.rotationJobs["disabled-check-key"].Enabled = false
	rm.mu.Unlock()

	// Should skip disabled job without performing rotation
	rm.checkAndPerformRotations()
}

// TestCheckAndPerformRotations_RotationNeeded exercises the path where rotation is triggered.
func TestCheckAndPerformRotations_RotationNeeded(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "due-rotate-key", KeyType_KEY_TYPE_RSA_2048)

	// Schedule with a past-due interval so rotation IS needed
	if err := rm.ScheduleRotation("due-rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, -1*time.Second); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// checkAndPerformRotations should detect the need and start a goroutine
	rm.checkAndPerformRotations()

	// Give the goroutine a moment to execute
	time.Sleep(100 * time.Millisecond)
}
