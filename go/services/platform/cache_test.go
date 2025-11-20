package platform

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"stratium/pkg/models"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
)

// Test NewInMemoryPolicyCache constructor
func TestCache_NewInMemoryPolicyCache(t *testing.T) {
	cache := NewInMemoryPolicyCache()

	if cache == nil {
		t.Fatal("Expected cache to not be nil")
	}

	if cache.cache == nil {
		t.Error("Expected cache.cache map to be initialized")
	}

	if len(cache.cache) != 0 {
		t.Errorf("Expected cache to be empty, got %d items", len(cache.cache))
	}
}

// Test InMemoryPolicyCache Get method
func TestCache_InMemoryPolicyCache_Get(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	tests := []struct {
		name           string
		setupCache     func()
		key            string
		expectFound    bool
		expectPolicyID uuid.UUID
	}{
		{
			name: "Get existing policy - should return policy and true",
			setupCache: func() {
				cache.cache["test-key"] = testPolicy
			},
			key:            "test-key",
			expectFound:    true,
			expectPolicyID: policyID,
		},
		{
			name:        "Get non-existent policy - should return nil and false",
			setupCache:  func() {},
			key:         "non-existent-key",
			expectFound: false,
		},
		{
			name: "Get with empty key - should return nil and false",
			setupCache: func() {
				cache.cache["test-key"] = testPolicy
			},
			key:         "",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache = NewInMemoryPolicyCache()
			tt.setupCache()

			policy, found := cache.Get(ctx, tt.key)

			if found != tt.expectFound {
				t.Errorf("Expected found=%v, got %v", tt.expectFound, found)
			}

			if tt.expectFound {
				if policy == nil {
					t.Fatal("Expected policy to not be nil")
				}
				if policy.ID != tt.expectPolicyID {
					t.Errorf("Expected policy ID %s, got %s", tt.expectPolicyID, policy.ID)
				}
			} else {
				if policy != nil {
					t.Errorf("Expected policy to be nil, got %+v", policy)
				}
			}
		})
	}
}

// Test InMemoryPolicyCache Set method
func TestCache_InMemoryPolicyCache_Set(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	tests := []struct {
		name      string
		key       string
		policy    *models.Policy
		ttl       time.Duration
		expectErr bool
	}{
		{
			name:      "Set new policy - should succeed",
			key:       "new-key",
			policy:    testPolicy,
			ttl:       1 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Set with TTL zero - should succeed (TTL ignored for in-memory)",
			key:       "key-no-ttl",
			policy:    testPolicy,
			ttl:       0,
			expectErr: false,
		},
		{
			name:      "Set with empty key - should succeed",
			key:       "",
			policy:    testPolicy,
			ttl:       1 * time.Hour,
			expectErr: false,
		},
		{
			name:      "Overwrite existing policy - should succeed",
			key:       "existing-key",
			policy:    testPolicy,
			ttl:       1 * time.Hour,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Overwrite existing policy - should succeed" {
				// Pre-populate with a different policy
				oldPolicy := &models.Policy{
					ID:   uuid.New(),
					Name: "old-policy",
				}
				cache.cache[tt.key] = oldPolicy
			}

			err := cache.Set(ctx, tt.key, tt.policy, tt.ttl)

			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error=%v, got error=%v", tt.expectErr, err)
			}

			if !tt.expectErr {
				// Verify the policy was stored
				stored, found := cache.cache[tt.key]
				if !found {
					t.Error("Expected policy to be stored in cache")
				}
				if stored != tt.policy {
					t.Error("Expected stored policy to be the same instance")
				}
			}
		})
	}
}

// Test InMemoryPolicyCache Invalidate method
func TestCache_InMemoryPolicyCache_Invalidate(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	tests := []struct {
		name       string
		setupCache func()
		key        string
		expectErr  bool
	}{
		{
			name: "Invalidate existing policy - should succeed",
			setupCache: func() {
				cache.cache["test-key"] = testPolicy
			},
			key:       "test-key",
			expectErr: false,
		},
		{
			name:       "Invalidate non-existent policy - should succeed (no error)",
			setupCache: func() {},
			key:        "non-existent-key",
			expectErr:  false,
		},
		{
			name: "Invalidate with empty key - should succeed",
			setupCache: func() {
				cache.cache[""] = testPolicy
			},
			key:       "",
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache = NewInMemoryPolicyCache()
			tt.setupCache()

			initialCount := len(cache.cache)

			err := cache.Invalidate(ctx, tt.key)

			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error=%v, got error=%v", tt.expectErr, err)
			}

			if !tt.expectErr {
				// Verify the policy was removed
				_, found := cache.cache[tt.key]
				if found {
					t.Error("Expected policy to be removed from cache")
				}

				// Verify count decreased if key existed
				if initialCount > 0 && len(cache.cache) >= initialCount {
					t.Error("Expected cache size to decrease after invalidation")
				}
			}
		})
	}
}

// Test InMemoryPolicyCache Clear method
func TestCache_InMemoryPolicyCache_Clear(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		setupCache func(*InMemoryPolicyCache)
		expectErr  bool
	}{
		{
			name: "Clear cache with multiple policies - should succeed",
			setupCache: func(cache *InMemoryPolicyCache) {
				for i := 0; i < 5; i++ {
					policy := &models.Policy{
						ID:   uuid.New(),
						Name: "policy-" + string(rune(i)),
					}
					cache.cache[string(rune(i))] = policy
				}
			},
			expectErr: false,
		},
		{
			name:       "Clear empty cache - should succeed",
			setupCache: func(cache *InMemoryPolicyCache) {},
			expectErr:  false,
		},
		{
			name: "Clear cache with single policy - should succeed",
			setupCache: func(cache *InMemoryPolicyCache) {
				cache.cache["single-key"] = &models.Policy{
					ID:   uuid.New(),
					Name: "single-policy",
				}
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := NewInMemoryPolicyCache()
			tt.setupCache(cache)

			initialCount := len(cache.cache)

			err := cache.Clear(ctx)

			if (err != nil) != tt.expectErr {
				t.Errorf("Expected error=%v, got error=%v", tt.expectErr, err)
			}

			if !tt.expectErr {
				if len(cache.cache) != 0 {
					t.Errorf("Expected cache to be empty after Clear, got %d items", len(cache.cache))
				}

				if initialCount > 0 && len(cache.cache) > 0 {
					t.Error("Expected all items to be removed from cache")
				}
			}
		})
	}
}

// Test concurrent access to InMemoryPolicyCache
func TestCache_InMemoryPolicyCache_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Test concurrent Set operations
	t.Run("Concurrent Set operations", func(t *testing.T) {
		var wg sync.WaitGroup
		numGoroutines := 10
		numOpsPerGoroutine := 100

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < numOpsPerGoroutine; j++ {
					key := string(rune('A' + (id*numOpsPerGoroutine+j)%26))
					err := cache.Set(ctx, key, testPolicy, 1*time.Hour)
					if err != nil {
						t.Errorf("Unexpected error during concurrent Set: %v", err)
					}
				}
			}(i)
		}
		wg.Wait()

		// Verify cache contains entries
		if len(cache.cache) == 0 {
			t.Error("Expected cache to contain entries after concurrent Set")
		}
	})

	// Test concurrent Get operations
	t.Run("Concurrent Get operations", func(t *testing.T) {
		cache = NewInMemoryPolicyCache()
		cache.Set(ctx, "shared-key", testPolicy, 1*time.Hour)

		var wg sync.WaitGroup
		numGoroutines := 10
		numOpsPerGoroutine := 100

		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < numOpsPerGoroutine; j++ {
					_, found := cache.Get(ctx, "shared-key")
					if !found {
						t.Error("Expected to find policy in cache during concurrent Get")
					}
				}
			}()
		}
		wg.Wait()
	})

	// Test mixed concurrent operations
	t.Run("Mixed concurrent operations", func(t *testing.T) {
		cache = NewInMemoryPolicyCache()

		var wg sync.WaitGroup

		// Setters
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					key := string(rune('A' + ((id*50 + j) % 26)))
					cache.Set(ctx, key, testPolicy, 1*time.Hour)
				}
			}(i)
		}

		// Getters
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					key := string(rune('A' + (j % 26)))
					cache.Get(ctx, key)
				}
			}()
		}

		// Invalidators
		wg.Add(5)
		for i := 0; i < 5; i++ {
			go func(id int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					key := string(rune('A' + ((id*50 + j) % 26)))
					cache.Invalidate(ctx, key)
				}
			}(i)
		}

		wg.Wait()

		// No assertions needed - the test passes if there's no race condition
	})
}

// Test InMemoryPolicyCache with nil context
func TestCache_InMemoryPolicyCache_NilContext(t *testing.T) {
	cache := NewInMemoryPolicyCache()

	policyID := uuid.New()
	testPolicy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Note: Context is not used by InMemoryPolicyCache, so nil context should work
	// In production, context should never be nil, but the implementation should be robust

	t.Run("Set with nil context", func(t *testing.T) {
		err := cache.Set(nil, "test-key", testPolicy, 1*time.Hour)
		if err != nil {
			t.Errorf("Expected no error with nil context, got: %v", err)
		}
	})

	t.Run("Get with nil context", func(t *testing.T) {
		policy, found := cache.Get(nil, "test-key")
		if !found {
			t.Error("Expected to find policy")
		}
		if policy == nil {
			t.Error("Expected policy to not be nil")
		}
	})

	t.Run("Invalidate with nil context", func(t *testing.T) {
		err := cache.Invalidate(nil, "test-key")
		if err != nil {
			t.Errorf("Expected no error with nil context, got: %v", err)
		}
	})

	t.Run("Clear with nil context", func(t *testing.T) {
		err := cache.Clear(nil)
		if err != nil {
			t.Errorf("Expected no error with nil context, got: %v", err)
		}
	})
}

func TestRedisPolicyCache_PrefixAndTTL(t *testing.T) {
	s := miniredis.RunT(t)
	defer s.Close()

	cfg := RedisCacheConfig{
		Addr:   s.Addr(),
		Prefix: "custom:policy:",
		TTL:    2 * time.Minute,
	}

	cache, err := NewRedisPolicyCache(cfg)
	if err != nil {
		t.Fatalf("NewRedisPolicyCache failed: %v", err)
	}
	defer cache.Close()

	ctx := context.Background()
	key := "policy-123"
	policy := &models.Policy{
		ID:          uuid.New(),
		Name:        "redis-test-policy",
		Description: "policy stored in redis",
		Language:    models.PolicyLanguageJSON,
	}

	if err := cache.Set(ctx, key, policy, 0); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	fullKey := cfg.Prefix + key
	if !s.Exists(fullKey) {
		t.Fatalf("expected key %s to exist in redis", fullKey)
	}

	ttl := s.TTL(fullKey)
	if ttl > cfg.TTL || ttl <= 0 {
		t.Fatalf("expected TTL <= %v and > 0, got %v", cfg.TTL, ttl)
	}

	data, err := cache.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		t.Fatalf("failed to read raw cache entry: %v", err)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("failed to unmarshal cached policy: %v", err)
	}
	if payload["name"] != policy.Name {
		t.Fatalf("expected name %s, got %v", policy.Name, payload["name"])
	}

	customTTL := 5 * time.Second
	if err := cache.Set(ctx, key, policy, customTTL); err != nil {
		t.Fatalf("Set with custom TTL failed: %v", err)
	}
	ttl = s.TTL(fullKey)
	if ttl > customTTL || ttl <= 0 {
		t.Fatalf("expected TTL <= %v and >0, got %v", customTTL, ttl)
	}
}

// Test InMemoryPolicyCache with different policy types
func TestCache_InMemoryPolicyCache_DifferentPolicyTypes(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policies := []*models.Policy{
		{
			ID:            uuid.New(),
			Name:          "json-policy",
			Language:      models.PolicyLanguageJSON,
			PolicyContent: `{"version": "1.0", "rules": []}`,
			Effect:        models.PolicyEffectAllow,
			Priority:      100,
			Enabled:       true,
		},
		{
			ID:            uuid.New(),
			Name:          "opa-policy",
			Language:      models.PolicyLanguageOPA,
			PolicyContent: `package authz\ndefault allow = false`,
			Effect:        models.PolicyEffectAllow,
			Priority:      200,
			Enabled:       true,
		},
		{
			ID:            uuid.New(),
			Name:          "xacml-policy",
			Language:      models.PolicyLanguageXACML,
			PolicyContent: `<?xml version="1.0"?><Policy/>`,
			Effect:        models.PolicyEffectDeny,
			Priority:      50,
			Enabled:       false,
		},
	}

	// Store all policies
	for i, policy := range policies {
		key := policy.Name
		err := cache.Set(ctx, key, policy, 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to set policy %d: %v", i, err)
		}
	}

	// Verify all policies can be retrieved
	for i, policy := range policies {
		key := policy.Name
		retrieved, found := cache.Get(ctx, key)
		if !found {
			t.Errorf("Policy %d not found in cache", i)
			continue
		}
		if retrieved.ID != policy.ID {
			t.Errorf("Policy %d: Expected ID %s, got %s", i, policy.ID, retrieved.ID)
		}
		if retrieved.Name != policy.Name {
			t.Errorf("Policy %d: Expected name %s, got %s", i, policy.Name, retrieved.Name)
		}
		if retrieved.Language != policy.Language {
			t.Errorf("Policy %d: Expected language %s, got %s", i, policy.Language, retrieved.Language)
		}
	}
}

// Test InMemoryPolicyCache operations in sequence
func TestCache_InMemoryPolicyCache_OperationSequence(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policyID1 := uuid.New()
	policyID2 := uuid.New()

	policy1 := &models.Policy{
		ID:            policyID1,
		Name:          "policy-1",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	policy2 := &models.Policy{
		ID:            policyID2,
		Name:          "policy-2",
		Language:      models.PolicyLanguageOPA,
		PolicyContent: `package authz`,
		Effect:        models.PolicyEffectDeny,
		Priority:      200,
		Enabled:       false,
	}

	// 1. Set policy1
	err := cache.Set(ctx, "key1", policy1, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set policy1: %v", err)
	}

	// 2. Verify policy1 exists
	retrieved, found := cache.Get(ctx, "key1")
	if !found || retrieved.ID != policyID1 {
		t.Error("Failed to retrieve policy1")
	}

	// 3. Set policy2
	err = cache.Set(ctx, "key2", policy2, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to set policy2: %v", err)
	}

	// 4. Verify both policies exist
	if len(cache.cache) != 2 {
		t.Errorf("Expected 2 policies in cache, got %d", len(cache.cache))
	}

	// 5. Invalidate policy1
	err = cache.Invalidate(ctx, "key1")
	if err != nil {
		t.Fatalf("Failed to invalidate policy1: %v", err)
	}

	// 6. Verify only policy2 remains
	if len(cache.cache) != 1 {
		t.Errorf("Expected 1 policy in cache after invalidation, got %d", len(cache.cache))
	}

	_, found = cache.Get(ctx, "key1")
	if found {
		t.Error("policy1 should not be found after invalidation")
	}

	retrieved, found = cache.Get(ctx, "key2")
	if !found || retrieved.ID != policyID2 {
		t.Error("policy2 should still be found")
	}

	// 7. Clear cache
	err = cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// 8. Verify cache is empty
	if len(cache.cache) != 0 {
		t.Errorf("Expected empty cache after clear, got %d items", len(cache.cache))
	}

	_, found = cache.Get(ctx, "key2")
	if found {
		t.Error("policy2 should not be found after clear")
	}
}

// Test InMemoryPolicyCache with large number of policies
func TestCache_InMemoryPolicyCache_LargeDataset(t *testing.T) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	numPolicies := 1000

	// Add policies
	for i := 0; i < numPolicies; i++ {
		policy := &models.Policy{
			ID:            uuid.New(),
			Name:          "policy-" + string(rune(i)),
			Language:      models.PolicyLanguageJSON,
			PolicyContent: `{"version": "1.0"}`,
			Effect:        models.PolicyEffectAllow,
			Priority:      i,
			Enabled:       true,
		}
		err := cache.Set(ctx, string(rune(i)), policy, 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to set policy %d: %v", i, err)
		}
	}

	// Verify count
	if len(cache.cache) != numPolicies {
		t.Errorf("Expected %d policies, got %d", numPolicies, len(cache.cache))
	}

	// Random retrieval
	for i := 0; i < 100; i++ {
		key := string(rune(i * 10 % numPolicies))
		_, found := cache.Get(ctx, key)
		if !found {
			t.Errorf("Expected to find policy at key %s", key)
		}
	}

	// Clear all
	err := cache.Clear(ctx)
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	if len(cache.cache) != 0 {
		t.Errorf("Expected empty cache, got %d items", len(cache.cache))
	}
}

// Benchmark InMemoryPolicyCache operations
func BenchmarkCache_InMemoryPolicyCache_Set(b *testing.B) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "bench-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune(i % 26))
		cache.Set(ctx, key, policy, 1*time.Hour)
	}
}

func BenchmarkCache_InMemoryPolicyCache_Get(b *testing.B) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "bench-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	// Pre-populate cache
	for i := 0; i < 26; i++ {
		cache.Set(ctx, string(rune('A'+i)), policy, 1*time.Hour)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune('A' + (i % 26)))
		cache.Get(ctx, key)
	}
}

func BenchmarkCache_InMemoryPolicyCache_Invalidate(b *testing.B) {
	ctx := context.Background()
	cache := NewInMemoryPolicyCache()

	policy := &models.Policy{
		ID:            uuid.New(),
		Name:          "bench-policy",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"version": "1.0"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune(i % 26))
		// Populate before each invalidation
		cache.Set(ctx, key, policy, 1*time.Hour)
		cache.Invalidate(ctx, key)
	}
}
