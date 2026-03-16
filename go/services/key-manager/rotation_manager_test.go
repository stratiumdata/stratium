package key_manager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"stratium/pkg/security/encryption"
)

// storeTestKey generates and stores a key pair + key metadata record so that
// both GetKey and GetKeyPair work against the in-memory store.
func storeTestKey(t *testing.T, ctx context.Context, keyStore *InMemoryKeyStore, factory *DefaultProviderFactory, keyID string, keyType KeyType) {
	t.Helper()

	provider, err := factory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider() error = %v", err)
	}

	keyPair, err := provider.GenerateKeyPair(ctx, keyType, keyID, nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair(%s) error = %v", keyID, err)
	}

	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair(%s) error = %v", keyID, err)
	}

	// Also store the Key metadata record so GetKey works
	key := &Key{
		KeyId:        keyPair.KeyID,
		KeyType:      keyPair.KeyType,
		ProviderType: keyPair.ProviderType,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem: keyPair.PublicKeyPEM,
		CreatedAt:    timestamppb.New(keyPair.CreatedAt),
		Metadata:     keyPair.Metadata,
	}
	if err := keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("StoreKey(%s) error = %v", keyID, err)
	}
}

// wireFactory sets the key store on all software providers in the factory.
func wireFactory(factory *DefaultProviderFactory, keyStore *InMemoryKeyStore) {
	for _, pt := range factory.GetAvailableProviders() {
		p, _ := factory.GetProvider(pt)
		if sp, ok := p.(*SoftwareKeyProvider); ok {
			sp.SetKeyStore(keyStore)
		}
	}
}

func TestRotationManager_NewDefaultKeyRotationManager(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	if rm == nil {
		t.Fatal("NewDefaultKeyRotationManager() returned nil")
	}
	if rm.running {
		t.Error("NewDefaultKeyRotationManager() should not be running initially")
	}
}

func TestRotationManager_StartAndStop(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	err := rm.Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Start again should error
	err = rm.Start()
	if err == nil {
		t.Error("Start() second call should return error")
	}

	// Stop should succeed
	err = rm.Stop()
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
}

func TestRotationManager_StopNotRunning(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	err := rm.Stop()
	if err == nil {
		t.Error("Stop() on non-running manager should return error")
	}
}

func TestRotationManager_ScheduleRotation_KeyNotFound(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	err := rm.ScheduleRotation("nonexistent-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err == nil {
		t.Error("ScheduleRotation() for nonexistent key should return error")
	}
}

func TestRotationManager_ScheduleRotation_TimeBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "test-key-1", KeyType_KEY_TYPE_RSA_2048)

	// Schedule rotation
	err := rm.ScheduleRotation("test-key-1", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// Schedule again should error
	err = rm.ScheduleRotation("test-key-1", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err == nil {
		t.Error("ScheduleRotation() duplicate should return error")
	}
}

func TestRotationManager_ScheduleRotation_UsageBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "test-key-usage", KeyType_KEY_TYPE_RSA_2048)

	err := rm.ScheduleRotation("test-key-usage", RotationPolicy_ROTATION_POLICY_USAGE_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation() usage-based error = %v", err)
	}
}

func TestRotationManager_ScheduleRotation_Combined(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "test-key-combined", KeyType_KEY_TYPE_RSA_2048)

	err := rm.ScheduleRotation("test-key-combined", RotationPolicy_ROTATION_POLICY_COMBINED, 48*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation() combined error = %v", err)
	}
}

func TestRotationManager_ScheduleRotation_Manual(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "test-key-manual", KeyType_KEY_TYPE_RSA_2048)

	// Manual policy should error
	err := rm.ScheduleRotation("test-key-manual", RotationPolicy_ROTATION_POLICY_MANUAL, 24*time.Hour)
	if err == nil {
		t.Error("ScheduleRotation() with manual policy should return error")
	}
}

func TestRotationManager_ScheduleRotation_ExternallyManaged(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()
	key := &Key{
		KeyId:             "ext-key-1",
		KeyType:           KeyType_KEY_TYPE_RSA_2048,
		ProviderType:      KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:            KeyStatus_KEY_STATUS_ACTIVE,
		ExternallyManaged: true,
		CreatedAt:         timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	err := rm.ScheduleRotation("ext-key-1", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err == nil {
		t.Error("ScheduleRotation() for externally managed key should return error")
	}
}

func TestRotationManager_ScheduleRotation_UnsupportedPolicy(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "test-key-unsupported", KeyType_KEY_TYPE_RSA_2048)

	// Use an invalid policy value
	err := rm.ScheduleRotation("test-key-unsupported", RotationPolicy(999), 24*time.Hour)
	if err == nil {
		t.Error("ScheduleRotation() with unsupported policy should return error")
	}
}

func TestRotationManager_CancelRotation(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "cancel-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("cancel-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	err := rm.CancelRotation("cancel-key")
	if err != nil {
		t.Fatalf("CancelRotation() error = %v", err)
	}
}

func TestRotationManager_CancelRotation_NotScheduled(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	err := rm.CancelRotation("nonexistent-key")
	if err == nil {
		t.Error("CancelRotation() for non-scheduled key should return error")
	}
}

func TestRotationManager_CheckRotationNeeded_TimeBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "check-key-time", KeyType_KEY_TYPE_RSA_2048)

	// Schedule with a very short interval (already past)
	if err := rm.ScheduleRotation("check-key-time", RotationPolicy_ROTATION_POLICY_TIME_BASED, -1*time.Second); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	key, _ := keyStore.GetKey(ctx, "check-key-time")
	needed := rm.CheckRotationNeeded(key)
	if !needed {
		t.Error("CheckRotationNeeded() should return true for past-due key")
	}
}

func TestRotationManager_CheckRotationNeeded_NoJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	key := &Key{
		KeyId:     "no-job-key",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		Status:    KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt: timestamppb.Now(),
	}

	needed := rm.CheckRotationNeeded(key)
	if needed {
		t.Error("CheckRotationNeeded() should return false when no job scheduled")
	}
}

func TestRotationManager_CheckRotationNeeded_UsageBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "check-key-usage", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("check-key-usage", RotationPolicy_ROTATION_POLICY_USAGE_BASED, time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	key, _ := keyStore.GetKey(ctx, "check-key-usage")
	// No usage limit, should not trigger
	key.MaxUsageCount = 0
	needed := rm.CheckRotationNeeded(key)
	if needed {
		t.Error("CheckRotationNeeded() should return false when MaxUsageCount=0")
	}

	// Simulate exceeding usage
	key.MaxUsageCount = 5
	key.UsageCount = 5
	needed = rm.CheckRotationNeeded(key)
	if !needed {
		t.Error("CheckRotationNeeded() should return true when usage >= max")
	}
}

func TestRotationManager_CheckRotationNeeded_Combined(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "check-key-combined", KeyType_KEY_TYPE_RSA_2048)

	// Use past-due interval so time-based triggers
	if err := rm.ScheduleRotation("check-key-combined", RotationPolicy_ROTATION_POLICY_COMBINED, -1*time.Second); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	key, _ := keyStore.GetKey(ctx, "check-key-combined")
	needed := rm.CheckRotationNeeded(key)
	if !needed {
		t.Error("CheckRotationNeeded() combined should return true for past-due key")
	}
}

func TestRotationManager_CheckRotationNeeded_DisabledJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "disabled-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("disabled-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, -1*time.Second); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// Manually disable the job
	rm.mu.Lock()
	rm.rotationJobs["disabled-key"].Enabled = false
	rm.mu.Unlock()

	key, _ := keyStore.GetKey(ctx, "disabled-key")
	needed := rm.CheckRotationNeeded(key)
	if needed {
		t.Error("CheckRotationNeeded() should return false for disabled job")
	}
}

func TestRotationManager_CheckRotationNeeded_DefaultPolicy(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Inject a job with unknown policy to cover the default branch
	rm.mu.Lock()
	rm.rotationJobs["unknown-policy-key"] = &RotationJob{
		KeyID:   "unknown-policy-key",
		Policy:  RotationPolicy(999),
		Enabled: true,
	}
	rm.mu.Unlock()

	key := &Key{
		KeyId:     "unknown-policy-key",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		CreatedAt: timestamppb.Now(),
	}
	needed := rm.CheckRotationNeeded(key)
	if needed {
		t.Error("CheckRotationNeeded() default policy should return false")
	}
}

func TestRotationManager_PerformRotation_NoJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()
	_, err := rm.PerformRotation(ctx, "no-job-key")
	if err == nil {
		t.Error("PerformRotation() without job should return error")
	}
}

func TestRotationManager_PerformRotation_Success(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "rotate-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	resp, err := rm.PerformRotation(ctx, "rotate-key")
	if err != nil {
		t.Fatalf("PerformRotation() error = %v", err)
	}
	if resp == nil {
		t.Fatal("PerformRotation() returned nil response")
	}
	if resp.OldKey == nil || resp.NewKey == nil {
		t.Error("PerformRotation() response missing OldKey or NewKey")
	}
}

func TestRotationManager_PerformRotation_ExternallyManaged(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()
	key := &Key{
		KeyId:             "ext-key-rotate",
		KeyType:           KeyType_KEY_TYPE_RSA_2048,
		ProviderType:      KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:            KeyStatus_KEY_STATUS_ACTIVE,
		ExternallyManaged: true,
		CreatedAt:         timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	// Add the job manually to bypass ScheduleRotation check
	rm.mu.Lock()
	rm.rotationJobs["ext-key-rotate"] = &RotationJob{
		KeyID:    "ext-key-rotate",
		Policy:   RotationPolicy_ROTATION_POLICY_TIME_BASED,
		Interval: 24 * time.Hour,
		Enabled:  true,
	}
	rm.mu.Unlock()

	_, err := rm.PerformRotation(ctx, "ext-key-rotate")
	if err == nil {
		t.Error("PerformRotation() for externally managed key should return error")
	}
}

func TestRotationManager_AddNotificationChannel(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "notify-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("notify-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	ch := make(chan RotationEvent, 10)
	err := rm.AddNotificationChannel("notify-key", ch)
	if err != nil {
		t.Fatalf("AddNotificationChannel() error = %v", err)
	}
}

func TestRotationManager_AddNotificationChannel_NoJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ch := make(chan RotationEvent, 10)
	err := rm.AddNotificationChannel("no-job-key", ch)
	if err == nil {
		t.Error("AddNotificationChannel() for no-job key should return error")
	}
}

func TestRotationManager_GetRotationStatus(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Empty initially
	status := rm.GetRotationStatus()
	if len(status) != 0 {
		t.Errorf("GetRotationStatus() should return empty map, got %d entries", len(status))
	}

	ctx := context.Background()
	storeTestKey(t, ctx, keyStore, factory, "status-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("status-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	status = rm.GetRotationStatus()
	if len(status) != 1 {
		t.Errorf("GetRotationStatus() should return 1 entry, got %d", len(status))
	}
	if _, ok := status["status-key"]; !ok {
		t.Error("GetRotationStatus() should contain 'status-key'")
	}
}

func TestRotationManager_UpdateRotationJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "update-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("update-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	err := rm.UpdateRotationJob("update-key", RotationPolicy_ROTATION_POLICY_COMBINED, 48*time.Hour)
	if err != nil {
		t.Fatalf("UpdateRotationJob() error = %v", err)
	}

	status := rm.GetRotationStatus()
	job, ok := status["update-key"]
	if !ok {
		t.Fatal("UpdateRotationJob() job not found after update")
	}
	if job.Policy != RotationPolicy_ROTATION_POLICY_COMBINED {
		t.Errorf("UpdateRotationJob() policy = %v, want COMBINED", job.Policy)
	}
	if job.Interval != 48*time.Hour {
		t.Errorf("UpdateRotationJob() interval = %v, want 48h", job.Interval)
	}
}

func TestRotationManager_UpdateRotationJob_UsageBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "update-key-usage", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("update-key-usage", RotationPolicy_ROTATION_POLICY_USAGE_BASED, time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	// Update to usage-based (exercises that branch in UpdateRotationJob)
	err := rm.UpdateRotationJob("update-key-usage", RotationPolicy_ROTATION_POLICY_USAGE_BASED, time.Hour)
	if err != nil {
		t.Fatalf("UpdateRotationJob() usage-based error = %v", err)
	}
}

func TestRotationManager_UpdateRotationJob_NotFound(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	err := rm.UpdateRotationJob("nonexistent-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err == nil {
		t.Error("UpdateRotationJob() for nonexistent key should return error")
	}
}

func TestRotationManager_KeyPairToKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	lastRotated := now.Add(-time.Hour)
	externalLoadedAt := now

	kp := &KeyPair{
		KeyID:                "kp-key",
		KeyType:              KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKeyPEM:         "public-pem",
		CreatedAt:            now,
		UsageCount:           5,
		MaxUsageCount:        100,
		Metadata:             map[string]string{"k": "v"},
		ExpiresAt:            &expiresAt,
		LastRotated:          &lastRotated,
		ExternallyManaged:    true,
		ExternalSource:       "vault",
		ExternalManifestPath: "/path/manifest",
		PrivateKeySource:     "encrypted",
		ExternalLoadedAt:     &externalLoadedAt,
	}

	key := rm.keyPairToKey(kp)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if key.KeyId != "kp-key" {
		t.Errorf("keyPairToKey() KeyId = %q, want %q", key.KeyId, "kp-key")
	}
	if key.ExpiresAt == nil {
		t.Error("keyPairToKey() ExpiresAt should not be nil")
	}
	if key.LastRotated == nil {
		t.Error("keyPairToKey() LastRotated should not be nil")
	}
	if !key.ExternallyManaged {
		t.Error("keyPairToKey() ExternallyManaged should be true")
	}
	if key.ExternalLoadedAt == nil {
		t.Error("keyPairToKey() ExternalLoadedAt should not be nil")
	}
}

func TestRotationManager_KeyPairToKey_NoOptionalFields(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// KeyPair with no optional time fields
	kp := &KeyPair{
		KeyID:        "kp-minimal",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		CreatedAt:    time.Now(),
		Metadata:     map[string]string{},
	}

	key := rm.keyPairToKey(kp)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if key.ExpiresAt != nil {
		t.Error("keyPairToKey() ExpiresAt should be nil when not set")
	}
	if key.LastRotated != nil {
		t.Error("keyPairToKey() LastRotated should be nil when not set")
	}
}

func TestRotationManager_SendRotationEvent_NoJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// sendRotationEvent for a key with no job should not panic
	rm.sendRotationEvent(RotationEvent{
		Type:      RotationEventTypeCompleted,
		KeyID:     "nonexistent",
		Timestamp: time.Now(),
		Message:   "test",
	})
}

func TestRotationManager_HandleRotationError_DisablesAfterMaxRetries(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "error-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("error-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	testErr := fmt.Errorf("simulated rotation error")

	// Call enough times to exceed MaxRetries (3)
	rm.handleRotationError("error-key", testErr)
	rm.handleRotationError("error-key", testErr)
	rm.handleRotationError("error-key", testErr)

	status := rm.GetRotationStatus()
	job, ok := status["error-key"]
	if !ok {
		t.Fatal("error-key should still be in status after errors")
	}
	if job.Enabled {
		t.Error("Job should be disabled after exceeding MaxRetries")
	}
}

func TestRotationManager_HandleRotationError_Retries(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	storeTestKey(t, ctx, keyStore, factory, "retry-key", KeyType_KEY_TYPE_RSA_2048)

	if err := rm.ScheduleRotation("retry-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour); err != nil {
		t.Fatalf("ScheduleRotation() error = %v", err)
	}

	testErr := fmt.Errorf("simulated rotation error")

	// First error - should increment retry count but keep enabled
	rm.handleRotationError("retry-key", testErr)

	status := rm.GetRotationStatus()
	job, ok := status["retry-key"]
	if !ok {
		t.Fatal("retry-key should be in status after first error")
	}
	if !job.Enabled {
		t.Error("Job should still be enabled after first error (below MaxRetries)")
	}
	if job.RetryCount != 1 {
		t.Errorf("RetryCount = %d, want 1", job.RetryCount)
	}
}

func TestRotationManager_HandleRotationError_NoJob(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Should not panic when called for non-existent job
	rm.handleRotationError("nonexistent-key", fmt.Errorf("test error"))
}

func TestRotationEventTypes(t *testing.T) {
	// Verify event type constants are accessible
	types := []RotationEventType{
		RotationEventTypeScheduled,
		RotationEventTypeStarted,
		RotationEventTypeCompleted,
		RotationEventTypeFailed,
		RotationEventTypeCancelled,
	}
	if len(types) != 5 {
		t.Errorf("expected 5 event types, got %d", len(types))
	}
}

func TestRotationManager_ScheduleRotation_WithLastRotated(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	wireFactory(factory, keyStore)

	rm := NewDefaultKeyRotationManager(keyStore, factory)
	ctx := context.Background()

	// Store a key that has already been rotated (LastRotated is set)
	storeTestKey(t, ctx, keyStore, factory, "already-rotated-key", KeyType_KEY_TYPE_RSA_2048)

	// Update the key to have a LastRotated time
	key, _ := keyStore.GetKey(ctx, "already-rotated-key")
	lastRotated := timestamppb.New(time.Now().Add(-48 * time.Hour))
	key.LastRotated = lastRotated
	_ = keyStore.UpdateKey(ctx, key)

	err := rm.ScheduleRotation("already-rotated-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation() for previously rotated key error = %v", err)
	}

	// Since last rotation was 48h ago and interval is 24h, next rotation should be in the past
	status := rm.GetRotationStatus()
	job, ok := status["already-rotated-key"]
	if !ok {
		t.Fatal("job not found after scheduling")
	}
	if job.NextRotation.After(time.Now()) {
		t.Error("NextRotation should be in the past for overdue key")
	}
}
