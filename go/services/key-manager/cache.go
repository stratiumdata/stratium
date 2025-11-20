package key_manager

import (
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

// ttlCache is a simple in-memory cache with per-entry expiration.
type ttlCache[T any] struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]cacheEntry[T]
}

type cacheEntry[T any] struct {
	value     T
	expiresAt time.Time
}

func newTTLCache[T any](ttl time.Duration) *ttlCache[T] {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &ttlCache[T]{
		ttl:  ttl,
		data: make(map[string]cacheEntry[T]),
	}
}

func (c *ttlCache[T]) Get(key string) (T, bool) {
	var zero T
	if c == nil || key == "" {
		return zero, false
	}

	c.mu.RLock()
	entry, ok := c.data[key]
	c.mu.RUnlock()
	if !ok {
		return zero, false
	}

	if time.Now().After(entry.expiresAt) {
		c.mu.Lock()
		delete(c.data, key)
		c.mu.Unlock()
		return zero, false
	}

	return entry.value, true
}

func (c *ttlCache[T]) Set(key string, value T) {
	if c == nil || key == "" {
		return
	}

	c.mu.Lock()
	c.data[key] = cacheEntry[T]{
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

func (c *ttlCache[T]) Delete(key string) {
	if c == nil || key == "" {
		return
	}

	c.mu.Lock()
	delete(c.data, key)
	c.mu.Unlock()
}

func cloneKey(src *Key) *Key {
	if src == nil {
		return nil
	}
	cloned := proto.Clone(src)
	if cloned == nil {
		return nil
	}
	return cloned.(*Key)
}

func cloneKeyPair(src *KeyPair) *KeyPair {
	if src == nil {
		return nil
	}

	cp := *src
	if src.Metadata != nil {
		cp.Metadata = make(map[string]string, len(src.Metadata))
		for k, v := range src.Metadata {
			cp.Metadata[k] = v
		}
	}

	if src.ExpiresAt != nil {
		t := *src.ExpiresAt
		cp.ExpiresAt = &t
	}
	if src.LastRotated != nil {
		t := *src.LastRotated
		cp.LastRotated = &t
	}
	if src.ExternalLoadedAt != nil {
		t := *src.ExternalLoadedAt
		cp.ExternalLoadedAt = &t
	}

	return &cp
}
