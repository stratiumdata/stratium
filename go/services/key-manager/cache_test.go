package key_manager

import (
	"testing"
	"time"
)

// TestNewTTLCache verifies cache is created with the given TTL.
func TestNewTTLCache(t *testing.T) {
	c := newTTLCache[string]("test", 10*time.Second)
	if c == nil {
		t.Fatal("newTTLCache() returned nil")
	}
	if c.ttl != 10*time.Second {
		t.Errorf("ttl = %v, want 10s", c.ttl)
	}
	if c.name != "test" {
		t.Errorf("name = %q, want 'test'", c.name)
	}
}

// TestNewTTLCache_ZeroTTLDefaults verifies zero TTL gets the default 5 minutes.
func TestNewTTLCache_ZeroTTLDefaults(t *testing.T) {
	c := newTTLCache[string]("test", 0)
	if c.ttl != 5*time.Minute {
		t.Errorf("ttl = %v, want 5m (default)", c.ttl)
	}
}

// TestTTLCache_SetGet verifies a stored value can be retrieved.
func TestTTLCache_SetGet(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("key1", "value1")

	got, ok := c.Get("key1")
	if !ok {
		t.Fatal("Get() ok = false, want true")
	}
	if got != "value1" {
		t.Errorf("Get() = %q, want %q", got, "value1")
	}
}

// TestTTLCache_Get_MissingKey verifies Get returns false for unknown keys.
func TestTTLCache_Get_MissingKey(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	_, ok := c.Get("nonexistent")
	if ok {
		t.Error("Get() ok = true for missing key, want false")
	}
}

// TestTTLCache_Get_EmptyKey verifies empty keys are always a miss.
func TestTTLCache_Get_EmptyKey(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("", "val")
	_, ok := c.Get("")
	if ok {
		t.Error("Get('') ok = true, want false (empty keys ignored)")
	}
}

// TestTTLCache_Set_EmptyKey verifies setting an empty key is a no-op.
func TestTTLCache_Set_EmptyKey(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("", "val") // should not panic
	if len(c.data) != 0 {
		t.Error("Set with empty key should not store anything")
	}
}

// TestTTLCache_Expired verifies an expired entry is treated as a miss.
func TestTTLCache_Expired(t *testing.T) {
	c := newTTLCache[string]("test", time.Millisecond)
	c.Set("key", "value")
	time.Sleep(5 * time.Millisecond) // wait for TTL to pass

	_, ok := c.Get("key")
	if ok {
		t.Error("Get() ok = true for expired entry, want false")
	}
	// The entry should be evicted
	if len(c.data) != 0 {
		t.Errorf("expired entry should be evicted, got %d entries", len(c.data))
	}
}

// TestTTLCache_Delete verifies Delete removes an existing entry.
func TestTTLCache_Delete(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("key", "value")
	c.Delete("key")

	_, ok := c.Get("key")
	if ok {
		t.Error("Get() ok = true after Delete, want false")
	}
}

// TestTTLCache_Delete_EmptyKey verifies Delete with empty key does nothing.
func TestTTLCache_Delete_EmptyKey(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("key", "value")
	c.Delete("") // should not panic or remove valid entries
	_, ok := c.Get("key")
	if !ok {
		t.Error("Delete('') should not remove valid entries")
	}
}

// TestTTLCache_NilCache verifies nil cache operations don't panic.
func TestTTLCache_NilCache(t *testing.T) {
	var c *ttlCache[string]
	c.Set("key", "val")     // should not panic
	c.Delete("key")         // should not panic
	_, ok := c.Get("key")  // should not panic
	if ok {
		t.Error("Get on nil cache should return false")
	}
}

// TestTTLCache_Overwrite verifies Set overwrites an existing value.
func TestTTLCache_Overwrite(t *testing.T) {
	c := newTTLCache[string]("test", time.Minute)
	c.Set("key", "first")
	c.Set("key", "second")

	got, ok := c.Get("key")
	if !ok {
		t.Fatal("Get() ok = false after overwrite")
	}
	if got != "second" {
		t.Errorf("Get() = %q, want %q", got, "second")
	}
}

// TestCloneKeyPair_Nil verifies cloneKeyPair returns nil for nil input.
func TestCloneKeyPair_Nil(t *testing.T) {
	if cloneKeyPair(nil) != nil {
		t.Error("cloneKeyPair(nil) should return nil")
	}
}

// TestCloneKeyPair_DeepCopy verifies metadata is deep-copied.
func TestCloneKeyPair_DeepCopy(t *testing.T) {
	now := time.Now()
	original := &KeyPair{
		KeyID:    "test-id",
		Metadata: map[string]string{"env": "prod"},
		ExpiresAt: &now,
	}

	clone := cloneKeyPair(original)
	if clone == nil {
		t.Fatal("cloneKeyPair() returned nil")
	}
	if clone.KeyID != original.KeyID {
		t.Errorf("KeyID = %q, want %q", clone.KeyID, original.KeyID)
	}

	// Mutate clone metadata — original should be unaffected
	clone.Metadata["env"] = "dev"
	if original.Metadata["env"] != "prod" {
		t.Error("cloneKeyPair() did not deep-copy Metadata")
	}

	// Mutate clone ExpiresAt — original should be unaffected
	later := now.Add(time.Hour)
	clone.ExpiresAt = &later
	if original.ExpiresAt.Equal(later) {
		t.Error("cloneKeyPair() did not deep-copy ExpiresAt")
	}
}

// TestCloneKeyPair_NilMetadataAndTimes verifies nil optional fields are safe.
func TestCloneKeyPair_NilMetadataAndTimes(t *testing.T) {
	original := &KeyPair{KeyID: "kp"}
	clone := cloneKeyPair(original)
	if clone == nil {
		t.Fatal("cloneKeyPair() returned nil for minimal KeyPair")
	}
	if clone.ExpiresAt != nil {
		t.Error("ExpiresAt should be nil in clone")
	}
	if clone.LastRotated != nil {
		t.Error("LastRotated should be nil in clone")
	}
}
