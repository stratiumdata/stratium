package cache

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestNoOpCacheInvalidator(t *testing.T) {
	cache := NewNoOpCacheInvalidator()

	ctx := context.Background()

	t.Run("InvalidatePolicy should not error", func(t *testing.T) {
		err := cache.InvalidatePolicy(ctx, "test-policy-id")
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("InvalidateAllPolicies should not error", func(t *testing.T) {
		err := cache.InvalidateAllPolicies(ctx)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	t.Run("Close should not error", func(t *testing.T) {
		err := cache.Close()
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})
}

func TestNoOpCacheInvalidator_Multiple(t *testing.T) {
	cache := NewNoOpCacheInvalidator()
	ctx := context.Background()

	// Test multiple operations
	for i := 0; i < 10; i++ {
		if err := cache.InvalidatePolicy(ctx, "policy-"+string(rune(i))); err != nil {
			t.Errorf("InvalidatePolicy iteration %d failed: %v", i, err)
		}
	}

	if err := cache.InvalidateAllPolicies(ctx); err != nil {
		t.Errorf("InvalidateAllPolicies failed: %v", err)
	}

	if err := cache.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestNoOpCacheInvalidator_Concurrent(t *testing.T) {
	cache := NewNoOpCacheInvalidator()
	ctx := context.Background()

	// Test concurrent operations
	done := make(chan bool)
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				_ = cache.InvalidatePolicy(ctx, "concurrent-policy")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestNoOpCacheInvalidator_ContextCancellation(t *testing.T) {
	cache := NewNoOpCacheInvalidator()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	time.Sleep(2 * time.Millisecond)

	// Should not fail even with cancelled context
	err := cache.InvalidatePolicy(ctx, "test-policy")
	if err != nil {
		t.Errorf("Expected no error with cancelled context, got: %v", err)
	}
}

// Benchmark tests
func BenchmarkNoOpCacheInvalidator_InvalidatePolicy(b *testing.B) {
	cache := NewNoOpCacheInvalidator()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.InvalidatePolicy(ctx, "benchmark-policy")
	}
}

func BenchmarkNoOpCacheInvalidator_InvalidateAllPolicies(b *testing.B) {
	cache := NewNoOpCacheInvalidator()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cache.InvalidateAllPolicies(ctx)
	}
}

func BenchmarkNoOpCacheInvalidator_Concurrent(b *testing.B) {
	cache := NewNoOpCacheInvalidator()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.InvalidatePolicy(ctx, "concurrent-policy")
		}
	})
}

// Redis Cache Invalidator Tests

func TestNewRedisCacheInvalidator(t *testing.T) {
	t.Run("successful connection with default prefix", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:     mr.Addr(),
			Password: "",
			DB:       0,
			Prefix:   "",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer invalidator.Close()

		if invalidator.prefix != "stratium:policy:" {
			t.Errorf("Expected default prefix 'stratium:policy:', got: %s", invalidator.prefix)
		}
	})

	t.Run("successful connection with custom prefix", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		customPrefix := "custom:prefix:"
		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: customPrefix,
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer invalidator.Close()

		if invalidator.prefix != customPrefix {
			t.Errorf("Expected custom prefix '%s', got: %s", customPrefix, invalidator.prefix)
		}
	})

	t.Run("connection failure", func(t *testing.T) {
		config := RedisCacheConfig{
			Addr:     "invalid:9999",
			Password: "",
			DB:       0,
			Prefix:   "",
		}

		_, err := NewRedisCacheInvalidator(config)
		if err == nil {
			t.Fatal("Expected error for invalid connection, got nil")
		}
	})

	t.Run("with password and custom DB", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:     mr.Addr(),
			Password: "test-password",
			DB:       5,
			Prefix:   "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		defer invalidator.Close()
	})
}

func TestRedisCacheInvalidator_InvalidatePolicy(t *testing.T) {
	t.Run("invalidate existing policy", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		// Set a key first
		policyID := "policy-123"
		mr.Set("test:"+policyID, "some-data")

		ctx := context.Background()
		err = invalidator.InvalidatePolicy(ctx, policyID)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Verify key was deleted
		exists := mr.Exists("test:" + policyID)
		if exists {
			t.Error("Expected key to be deleted")
		}
	})

	t.Run("invalidate non-existing policy", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		ctx := context.Background()
		err = invalidator.InvalidatePolicy(ctx, "non-existing")
		if err != nil {
			t.Errorf("Expected no error for non-existing key, got: %v", err)
		}
	})

	t.Run("with cancelled context", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = invalidator.InvalidatePolicy(ctx, "policy-123")
		if err == nil {
			t.Error("Expected error with cancelled context")
		}
	})

	t.Run("with empty policy ID", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		ctx := context.Background()
		err = invalidator.InvalidatePolicy(ctx, "")
		if err != nil {
			t.Errorf("Expected no error for empty policy ID, got: %v", err)
		}
	})
}

func TestRedisCacheInvalidator_InvalidateAllPolicies(t *testing.T) {
	t.Run("invalidate multiple policies", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		// Set multiple keys
		mr.Set("test:policy-1", "data1")
		mr.Set("test:policy-2", "data2")
		mr.Set("test:policy-3", "data3")
		mr.Set("other:key", "should-remain")

		ctx := context.Background()
		err = invalidator.InvalidateAllPolicies(ctx)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Verify all test: keys were deleted
		if mr.Exists("test:policy-1") {
			t.Error("Expected test:policy-1 to be deleted")
		}
		if mr.Exists("test:policy-2") {
			t.Error("Expected test:policy-2 to be deleted")
		}
		if mr.Exists("test:policy-3") {
			t.Error("Expected test:policy-3 to be deleted")
		}

		// Verify other key remains
		if !mr.Exists("other:key") {
			t.Error("Expected other:key to remain")
		}
	})

	t.Run("invalidate with no policies", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		ctx := context.Background()
		err = invalidator.InvalidateAllPolicies(ctx)
		if err != nil {
			t.Errorf("Expected no error with no keys, got: %v", err)
		}
	})

	t.Run("with cancelled context", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		err = invalidator.InvalidateAllPolicies(ctx)
		if err == nil {
			t.Error("Expected error with cancelled context")
		}
	})

	t.Run("invalidate large number of policies", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}
		defer invalidator.Close()

		// Set many keys
		for i := 0; i < 100; i++ {
			mr.Set("test:policy-"+string(rune(i)), "data")
		}

		ctx := context.Background()
		err = invalidator.InvalidateAllPolicies(ctx)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Verify all were deleted
		keys := mr.Keys()
		for _, key := range keys {
			if len(key) >= 5 && key[:5] == "test:" {
				t.Errorf("Expected all test: keys to be deleted, but found: %s", key)
			}
		}
	})
}

func TestRedisCacheInvalidator_Close(t *testing.T) {
	t.Run("close connection", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}

		err = invalidator.Close()
		if err != nil {
			t.Errorf("Expected no error on close, got: %v", err)
		}
	})

	t.Run("operations after close should fail", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "test:",
		}

		invalidator, err := NewRedisCacheInvalidator(config)
		if err != nil {
			t.Fatalf("Failed to create invalidator: %v", err)
		}

		invalidator.Close()

		ctx := context.Background()
		err = invalidator.InvalidatePolicy(ctx, "policy-123")
		if err == nil {
			t.Error("Expected error after close")
		}
	})
}

func TestRedisCacheInvalidator_PrefixHandling(t *testing.T) {
	t.Run("verify prefix isolation", func(t *testing.T) {
		mr := miniredis.RunT(t)
		defer mr.Close()

		config1 := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "app1:",
		}

		config2 := RedisCacheConfig{
			Addr:   mr.Addr(),
			Prefix: "app2:",
		}

		inv1, err := NewRedisCacheInvalidator(config1)
		if err != nil {
			t.Fatalf("Failed to create invalidator 1: %v", err)
		}
		defer inv1.Close()

		inv2, err := NewRedisCacheInvalidator(config2)
		if err != nil {
			t.Fatalf("Failed to create invalidator 2: %v", err)
		}
		defer inv2.Close()

		// Set keys in both prefixes
		mr.Set("app1:policy-1", "data1")
		mr.Set("app2:policy-1", "data2")

		ctx := context.Background()

		// Invalidate all for app1
		err = inv1.InvalidateAllPolicies(ctx)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}

		// Verify app1 key is deleted but app2 key remains
		if mr.Exists("app1:policy-1") {
			t.Error("Expected app1:policy-1 to be deleted")
		}
		if !mr.Exists("app2:policy-1") {
			t.Error("Expected app2:policy-1 to remain")
		}
	})
}

func TestRedisCacheInvalidator_Concurrent(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	config := RedisCacheConfig{
		Addr:   mr.Addr(),
		Prefix: "test:",
	}

	invalidator, err := NewRedisCacheInvalidator(config)
	if err != nil {
		t.Fatalf("Failed to create invalidator: %v", err)
	}
	defer invalidator.Close()

	// Set some initial keys
	for i := 0; i < 50; i++ {
		mr.Set("test:policy-"+string(rune(i)), "data")
	}

	ctx := context.Background()
	done := make(chan bool)
	errors := make(chan error, 10)

	// Concurrent invalidate operations
	for i := 0; i < 5; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				err := invalidator.InvalidatePolicy(ctx, "policy-"+string(rune(id*10+j)))
				if err != nil {
					errors <- err
				}
			}
			done <- true
		}(i)
	}

	// Concurrent invalidate all operations
	for i := 0; i < 5; i++ {
		go func() {
			err := invalidator.InvalidateAllPolicies(ctx)
			if err != nil {
				errors <- err
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
}

func TestRedisCacheInvalidator_Interface(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	config := RedisCacheConfig{
		Addr:   mr.Addr(),
		Prefix: "test:",
	}

	invalidator, err := NewRedisCacheInvalidator(config)
	if err != nil {
		t.Fatalf("Failed to create invalidator: %v", err)
	}
	defer invalidator.Close()

	// Verify it implements CacheInvalidator interface
	var _ CacheInvalidator = invalidator
}

func TestCacheInvalidator_InterfaceCompliance(t *testing.T) {
	// Test that both implementations satisfy the interface
	var _ CacheInvalidator = &RedisCacheInvalidator{}
	var _ CacheInvalidator = &NoOpCacheInvalidator{}
}

// Benchmark tests for Redis

func BenchmarkRedisCacheInvalidator_InvalidatePolicy(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	config := RedisCacheConfig{
		Addr:   mr.Addr(),
		Prefix: "bench:",
	}

	invalidator, err := NewRedisCacheInvalidator(config)
	if err != nil {
		b.Fatalf("Failed to create invalidator: %v", err)
	}
	defer invalidator.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invalidator.InvalidatePolicy(ctx, "policy-123")
	}
}

func BenchmarkRedisCacheInvalidator_InvalidateAllPolicies(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	config := RedisCacheConfig{
		Addr:   mr.Addr(),
		Prefix: "bench:",
	}

	invalidator, err := NewRedisCacheInvalidator(config)
	if err != nil {
		b.Fatalf("Failed to create invalidator: %v", err)
	}
	defer invalidator.Close()

	ctx := context.Background()

	// Set some keys for each iteration
	for i := 0; i < 10; i++ {
		mr.Set("bench:policy-"+string(rune(i)), "data")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invalidator.InvalidateAllPolicies(ctx)
		// Repopulate for next iteration
		for j := 0; j < 10; j++ {
			mr.Set("bench:policy-"+string(rune(j)), "data")
		}
	}
}

func BenchmarkRedisCacheInvalidator_Concurrent(b *testing.B) {
	mr := miniredis.RunT(b)
	defer mr.Close()

	config := RedisCacheConfig{
		Addr:   mr.Addr(),
		Prefix: "bench:",
	}

	invalidator, err := NewRedisCacheInvalidator(config)
	if err != nil {
		b.Fatalf("Failed to create invalidator: %v", err)
	}
	defer invalidator.Close()

	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = invalidator.InvalidatePolicy(ctx, "concurrent-policy")
		}
	})
}
