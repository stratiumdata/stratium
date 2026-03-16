//go:build !fips

package key_manager

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCoverageFinal80_DefaultRotationManager_ScheduleAndCheck(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	providerFactory := NewDefaultProviderFactory("RSA2048")

	// Set up the key store with a provider
	provider, _ := providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if sp, ok := provider.(*SoftwareKeyProvider); ok {
		sp.SetKeyStore(keyStore)
	}

	ctx := context.Background()

	// Generate a key
	kp, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "rot-mgr-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Store key and key pair
	key := &Key{
		KeyId:      "rot-mgr-key",
		KeyType:    KeyType_KEY_TYPE_RSA_2048,
		Status:     KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:  timestamppb.Now(),
		UsageCount: 0,
	}
	if err := keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("setup: store key: %v", err)
	}
	if err := keyStore.StoreKeyPair(ctx, kp); err != nil {
		t.Fatalf("setup: store key pair: %v", err)
	}

	rm := NewDefaultKeyRotationManager(keyStore, providerFactory)

	// Schedule time-based rotation
	err = rm.ScheduleRotation("rot-mgr-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// Duplicate schedule
	err = rm.ScheduleRotation("rot-mgr-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for duplicate schedule")
	}

	// CheckRotationNeeded - should be false (next rotation is 24h from now)
	needsRotation := rm.CheckRotationNeeded(key)
	if needsRotation {
		t.Fatal("should not need rotation yet")
	}

	// Cancel
	err = rm.CancelRotation("rot-mgr-key")
	if err != nil {
		t.Fatalf("CancelRotation: %v", err)
	}

	// Cancel non-existent
	err = rm.CancelRotation("nonexistent")
	if err == nil {
		t.Fatal("expected error for canceling non-existent rotation")
	}

	// Manual policy
	err = rm.ScheduleRotation("rot-mgr-key", RotationPolicy_ROTATION_POLICY_MANUAL, 0)
	if err == nil {
		t.Fatal("expected error for manual policy scheduling")
	}

	// PerformRotation for a key with no key pair stored (triggers provider.RotateKey error at line 276)
	key2 := &Key{
		KeyId:        "rot-no-kp",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, key2); err != nil {
		t.Fatalf("setup: store key2: %v", err)
	}
	rm2 := NewDefaultKeyRotationManager(keyStore, providerFactory)
	if err := rm2.ScheduleRotation("rot-no-kp", RotationPolicy_ROTATION_POLICY_TIME_BASED, time.Hour); err != nil {
		t.Fatalf("setup: schedule rotation: %v", err)
	}
	_, err = rm2.PerformRotation(ctx, "rot-no-kp")
	if err == nil {
		t.Fatal("expected error for rotation with missing key pair")
	}
}
