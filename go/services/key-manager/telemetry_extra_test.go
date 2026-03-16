package key_manager

import (
	"context"
	"testing"
	"time"
	"fmt"
)

func TestRecordKeyManagerCacheEvent_EmptyCacheName(t *testing.T) {
	// Empty cache name should return early without panic
	recordKeyManagerCacheEvent("", "hit")
}

func TestRecordKeyManagerCacheEvent_ValidEvents(t *testing.T) {
	events := []struct {
		cacheName string
		result    string
	}{
		{"key_pairs", "hit"},
		{"key_pairs", "miss"},
		{"key_pairs", "expired"},
		{"client_keys", "hit"},
		{"client_keys", "miss"},
	}

	for _, e := range events {
		// Should not panic
		recordKeyManagerCacheEvent(e.cacheName, e.result)
	}
}

func TestRecordKeyManagerDBQuery_NoError(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	recordKeyManagerDBQuery(ctx, "key_pairs", "select", 5*time.Millisecond, nil)
	recordKeyManagerDBQuery(ctx, "key_pairs", "insert", 10*time.Millisecond, nil)
	recordKeyManagerDBQuery(ctx, "client_keys", "update", 3*time.Millisecond, nil)
	recordKeyManagerDBQuery(ctx, "client_keys", "delete", 2*time.Millisecond, nil)
}

func TestRecordKeyManagerDBQuery_WithError(t *testing.T) {
	ctx := context.Background()
	err := fmt.Errorf("connection refused")
	// Should not panic
	recordKeyManagerDBQuery(ctx, "key_pairs", "select", 100*time.Millisecond, err)
}

func TestRecordKeyManagerDBQuery_NilContext(t *testing.T) {
	// Should not panic with nil context (safeContext handles this)
	recordKeyManagerDBQuery(nil, "key_pairs", "select", 5*time.Millisecond, nil)
}

func TestAdjustRotationJobGauge(t *testing.T) {
	// Should not panic
	adjustRotationJobGauge(1)
	adjustRotationJobGauge(-1)
	adjustRotationJobGauge(0) // delta 0 is a no-op
}

func TestRecordKeyRotationLatency_Success(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	recordKeyRotationLatency(ctx, 50*time.Millisecond, true)
}

func TestRecordKeyRotationLatency_Error(t *testing.T) {
	ctx := context.Background()
	// Should not panic
	recordKeyRotationLatency(ctx, 200*time.Millisecond, false)
}

func TestRecordKeyRotationLatency_NilContext(t *testing.T) {
	// Should not panic with nil context (safeContext handles this)
	recordKeyRotationLatency(nil, 10*time.Millisecond, true)
}

func TestSafeContext_NilContext(t *testing.T) {
	ctx := safeContext(nil)
	if ctx == nil {
		t.Fatal("safeContext(nil) should not return nil")
	}
}

func TestSafeContext_ValidContext(t *testing.T) {
	original := context.Background()
	ctx := safeContext(original)
	if ctx != original {
		t.Fatal("safeContext with a valid context should return the same context")
	}
}

func TestInitKeyManagerTelemetry_Idempotent(t *testing.T) {
	// Calling multiple times should not panic (sync.Once ensures single initialization)
	initKeyManagerTelemetry()
	initKeyManagerTelemetry()
	initKeyManagerTelemetry()
}
