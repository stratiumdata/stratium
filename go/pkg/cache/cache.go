package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// CacheInvalidator provides cache invalidation capabilities for PAP API
type CacheInvalidator interface {
	InvalidatePolicy(ctx context.Context, policyID string) error
	InvalidateAllPolicies(ctx context.Context) error
	Close() error
}

// RedisCacheInvalidator implements CacheInvalidator for Redis
type RedisCacheInvalidator struct {
	client *redis.Client
	prefix string
}

// RedisCacheConfig holds configuration for Redis cache
type RedisCacheConfig struct {
	Addr     string
	Password string
	DB       int
	Prefix   string
}

// NewRedisCacheInvalidator creates a new Redis cache invalidator
func NewRedisCacheInvalidator(config RedisCacheConfig) (*RedisCacheInvalidator, error) {
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

	return &RedisCacheInvalidator{
		client: client,
		prefix: prefix,
	}, nil
}

// InvalidatePolicy removes a specific policy from the cache
func (c *RedisCacheInvalidator) InvalidatePolicy(ctx context.Context, policyID string) error {
	key := c.prefix + policyID

	if err := c.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to invalidate policy cache: %w", err)
	}

	return nil
}

// InvalidateAllPolicies removes all policies from the cache
func (c *RedisCacheInvalidator) InvalidateAllPolicies(ctx context.Context) error {
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
			return fmt.Errorf("failed to clear policy cache: %w", err)
		}
	}

	return nil
}

// Close closes the Redis connection
func (c *RedisCacheInvalidator) Close() error {
	return c.client.Close()
}

// NoOpCacheInvalidator is a cache invalidator that does nothing (for in-memory cache or when cache is disabled)
type NoOpCacheInvalidator struct{}

// NewNoOpCacheInvalidator creates a new no-op cache invalidator
func NewNoOpCacheInvalidator() *NoOpCacheInvalidator {
	return &NoOpCacheInvalidator{}
}

// InvalidatePolicy does nothing
func (c *NoOpCacheInvalidator) InvalidatePolicy(ctx context.Context, policyID string) error {
	return nil
}

// InvalidateAllPolicies does nothing
func (c *NoOpCacheInvalidator) InvalidateAllPolicies(ctx context.Context) error {
	return nil
}

// Close does nothing
func (c *NoOpCacheInvalidator) Close() error {
	return nil
}