package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"stratium/pkg/models"

	"github.com/redis/go-redis/v9"
)

// PolicyCache provides caching for policies to improve performance
type PolicyCache interface {
	Get(ctx context.Context, key string) (*models.Policy, bool)
	Set(ctx context.Context, key string, policy *models.Policy, ttl time.Duration) error
	Invalidate(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}

// InMemoryPolicyCache provides a simple in-memory cache
type InMemoryPolicyCache struct {
	cache map[string]*models.Policy
	mu    sync.RWMutex
}

// NewInMemoryPolicyCache creates a new in-memory policy cache
func NewInMemoryPolicyCache() *InMemoryPolicyCache {
	return &InMemoryPolicyCache{
		cache: make(map[string]*models.Policy),
	}
}

// Get retrieves a policy from the cache
func (c *InMemoryPolicyCache) Get(ctx context.Context, key string) (*models.Policy, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	policy, ok := c.cache[key]
	return policy, ok
}

// Set stores a policy in the cache (TTL is ignored for in-memory cache)
func (c *InMemoryPolicyCache) Set(ctx context.Context, key string, policy *models.Policy, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = policy
	return nil
}

// Invalidate removes a policy from the cache
func (c *InMemoryPolicyCache) Invalidate(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.cache, key)
	return nil
}

// Clear removes all policies from the cache
func (c *InMemoryPolicyCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*models.Policy)
	return nil
}

// RedisPolicyCache provides a Redis-based distributed cache
type RedisPolicyCache struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// RedisCacheConfig holds configuration for Redis cache
type RedisCacheConfig struct {
	Addr     string
	Password string
	DB       int
	Prefix   string
	TTL      time.Duration
}

// NewRedisPolicyCache creates a new Redis-based policy cache
func NewRedisPolicyCache(config RedisCacheConfig) (*RedisPolicyCache, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     config.Addr,
		Password: config.Password,
		DB:       config.DB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	prefix := config.Prefix
	if prefix == "" {
		prefix = "stratium:policy:"
	}

	cacheTTL := config.TTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	return &RedisPolicyCache{
		client: client,
		prefix: prefix,
		ttl:    cacheTTL,
	}, nil
}

// Get retrieves a policy from Redis cache
func (c *RedisPolicyCache) Get(ctx context.Context, key string) (*models.Policy, bool) {
	fullKey := c.prefix + key

	data, err := c.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, false
		}
		// Log error but don't fail - cache miss
		return nil, false
	}

	var policy models.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		// Cache corrupted, invalidate
		c.client.Del(ctx, fullKey)
		return nil, false
	}

	return &policy, true
}

// Set stores a policy in Redis cache with TTL
func (c *RedisPolicyCache) Set(ctx context.Context, key string, policy *models.Policy, ttl time.Duration) error {
	fullKey := c.prefix + key

	data, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	if ttl == 0 {
		ttl = c.ttl
	}

	if err := c.client.Set(ctx, fullKey, data, ttl).Err(); err != nil {
		return fmt.Errorf("failed to set cache: %w", err)
	}

	return nil
}

// Invalidate removes a policy from Redis cache
func (c *RedisPolicyCache) Invalidate(ctx context.Context, key string) error {
	fullKey := c.prefix + key

	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		return fmt.Errorf("failed to invalidate cache: %w", err)
	}

	return nil
}

// Clear removes all policies from Redis cache
func (c *RedisPolicyCache) Clear(ctx context.Context) error {
	// Find all keys with our prefix
	iter := c.client.Scan(ctx, 0, c.prefix+"*", 0).Iterator()

	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}

	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan cache keys: %w", err)
	}

	if len(keys) > 0 {
		if err := c.client.Del(ctx, keys...).Err(); err != nil {
			return fmt.Errorf("failed to clear cache: %w", err)
		}
	}

	return nil
}

// Close closes the Redis connection
func (c *RedisPolicyCache) Close() error {
	return c.client.Close()
}
