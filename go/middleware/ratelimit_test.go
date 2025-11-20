package middleware

import (
	"context"
	"net"
	"stratium/config"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

func TestNewRateLimiter(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 60,
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}

	if rl.limiters == nil {
		t.Error("limiters map not initialized")
	}

	if rl.config != cfg {
		t.Error("config not set correctly")
	}

	if rl.logger == nil {
		t.Error("logger not initialized")
	}

	if len(rl.limiters) != 0 {
		t.Error("limiters map should be empty initially")
	}
}

func TestGetLimiter(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 60,
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	t.Run("creates new limiter for new client", func(t *testing.T) {
		clientIP := "192.168.1.1"
		limiter1 := rl.getLimiter(clientIP)

		if limiter1 == nil {
			t.Fatal("getLimiter returned nil")
		}

		// Verify limiter is cached
		if len(rl.limiters) != 1 {
			t.Errorf("Expected 1 limiter, got %d", len(rl.limiters))
		}
	})

	t.Run("returns existing limiter for known client", func(t *testing.T) {
		clientIP := "192.168.1.2"
		limiter1 := rl.getLimiter(clientIP)
		limiter2 := rl.getLimiter(clientIP)

		if limiter1 != limiter2 {
			t.Error("getLimiter should return the same limiter instance")
		}
	})

	t.Run("creates separate limiters for different clients", func(t *testing.T) {
		limiter1 := rl.getLimiter("192.168.1.3")
		limiter2 := rl.getLimiter("192.168.1.4")

		if limiter1 == limiter2 {
			t.Error("Different clients should have different limiters")
		}
	})
}

func TestGetLimiter_Concurrent(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 60,
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	clientIP := "192.168.1.100"

	// Test concurrent access to the same client IP
	var wg sync.WaitGroup
	var limiters sync.Map

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			limiter := rl.getLimiter(clientIP)
			limiters.Store(index, limiter)
		}(i)
	}

	wg.Wait()

	// All limiters should be the same instance
	firstLimiterVal, _ := limiters.Load(0)
	for i := 1; i < 10; i++ {
		limiterVal, _ := limiters.Load(i)
		if limiterVal != firstLimiterVal {
			t.Error("Concurrent access created different limiter instances")
		}
	}

	// Should only have one limiter for this IP
	rl.mu.RLock()
	count := 0
	for ip := range rl.limiters {
		if ip == clientIP {
			count++
		}
	}
	rl.mu.RUnlock()

	if count != 1 {
		t.Errorf("Expected 1 limiter for IP, got %d", count)
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected string
	}{
		{
			name: "valid peer context",
			ctx: peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.ParseIP("192.168.1.1"),
					Port: 12345,
				},
			}),
			expected: "192.168.1.1:12345",
		},
		{
			name:     "no peer in context",
			ctx:      context.Background(),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getClientIP(tt.ctx)
			if result != tt.expected {
				t.Errorf("getClientIP() = %s, want %s", result, tt.expected)
			}
		})
	}
}

func TestUnaryServerInterceptor_Disabled(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled: false,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.UnaryServerInterceptor()

	called := false
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		called = true
		return "response", nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	resp, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{}, handler)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !called {
		t.Error("Handler was not called when rate limiting is disabled")
	}

	if resp != "response" {
		t.Errorf("Expected response 'response', got %v", resp)
	}
}

func TestUnaryServerInterceptor_AllowsWithinLimit(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 600, // 10 per second
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	// First request should succeed
	resp, err := interceptor(ctx, "request", &grpc.UnaryServerInfo{}, handler)

	if err != nil {
		t.Errorf("First request failed: %v", err)
	}

	if resp != "response" {
		t.Errorf("Expected response 'response', got %v", resp)
	}
}

func TestUnaryServerInterceptor_ExceedsLimit(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 6, // Very low limit: 0.1 per second
				Burst:          1,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	// First request should succeed (uses the burst)
	_, err := interceptor(ctx, "request1", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Errorf("First request failed: %v", err)
	}

	// Second request should fail (exceeds rate)
	_, err = interceptor(ctx, "request2", &grpc.UnaryServerInfo{}, handler)
	if err == nil {
		t.Error("Second request should have been rate limited")
	}

	// Check error code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error is not a status error")
	}

	if st.Code() != codes.ResourceExhausted {
		t.Errorf("Expected ResourceExhausted code, got %v", st.Code())
	}

	if !strings.Contains(st.Message(), "rate limit exceeded") {
		t.Errorf("Error message should mention rate limit, got: %s", st.Message())
	}
}

func TestStreamServerInterceptor_Disabled(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled: false,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.StreamServerInterceptor()

	called := false
	handler := func(srv interface{}, stream grpc.ServerStream) error {
		called = true
		return nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	mockStream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if !called {
		t.Error("Handler was not called when rate limiting is disabled")
	}
}

func TestStreamServerInterceptor_AllowsWithinLimit(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 600,
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.StreamServerInterceptor()

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	mockStream := &mockServerStream{ctx: ctx}

	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)

	if err != nil {
		t.Errorf("Stream request failed: %v", err)
	}
}

func TestStreamServerInterceptor_ExceedsLimit(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 6,
				Burst:          1,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.StreamServerInterceptor()

	handler := func(srv interface{}, stream grpc.ServerStream) error {
		return nil
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	mockStream := &mockServerStream{ctx: ctx}

	// First request should succeed
	err := interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)
	if err != nil {
		t.Errorf("First stream request failed: %v", err)
	}

	// Second request should fail
	err = interceptor(nil, mockStream, &grpc.StreamServerInfo{}, handler)
	if err == nil {
		t.Error("Second stream request should have been rate limited")
	}

	// Check error code
	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Error is not a status error")
	}

	if st.Code() != codes.ResourceExhausted {
		t.Errorf("Expected ResourceExhausted code, got %v", st.Code())
	}
}

func TestPrintRateLimitInfo_Disabled(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled: false,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	// Should not panic when called with disabled rate limiting
	rl.PrintRateLimitInfo("test-service")

	// Verify the config is properly set
	_, _, enabled := rl.GetCurrentLimit()
	if enabled {
		t.Error("Rate limiting should be disabled")
	}
}

func TestPrintRateLimitInfo_Enabled(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 120,
				Burst:          20,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	// Should not panic when called with enabled rate limiting
	rl.PrintRateLimitInfo("test-service")

	// Verify the config values are properly read
	requestsPerMin, burst, enabled := rl.GetCurrentLimit()
	if !enabled {
		t.Error("Rate limiting should be enabled")
	}
	if requestsPerMin != 120 {
		t.Errorf("Expected 120 requests/min, got %d", requestsPerMin)
	}
	if burst != 20 {
		t.Errorf("Expected burst of 20, got %d", burst)
	}

	// Test that the average calculation works correctly
	avgTime := time.Minute / time.Duration(requestsPerMin)
	expectedAvg := 500 * time.Millisecond // 60s / 120 = 0.5s
	if avgTime != expectedAvg {
		t.Errorf("Expected average time %v, got %v", expectedAvg, avgTime)
	}
}

func TestCleanup(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 60,
				Burst:          10,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	// Add some limiters
	rl.getLimiter("192.168.1.1")
	rl.getLimiter("192.168.1.2")
	rl.getLimiter("192.168.1.3")

	if len(rl.limiters) != 3 {
		t.Errorf("Expected 3 limiters, got %d", len(rl.limiters))
	}

	// Call cleanup (currently a no-op, but should not panic)
	rl.Cleanup(1 * time.Hour)

	// Verify it doesn't crash and limiters are still there
	// (since cleanup is a placeholder)
	if len(rl.limiters) != 3 {
		t.Errorf("Cleanup should not remove limiters yet, got %d", len(rl.limiters))
	}
}

func TestGetCurrentLimit(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 120,
				Burst:          30,
			},
		},
	}

	rl := NewRateLimiter(cfg)

	requestsPerMin, burst, enabled := rl.GetCurrentLimit()

	if requestsPerMin != 120 {
		t.Errorf("Expected RequestsPerMin=120, got %d", requestsPerMin)
	}

	if burst != 30 {
		t.Errorf("Expected Burst=30, got %d", burst)
	}

	if !enabled {
		t.Error("Expected Enabled=true, got false")
	}
}

func TestFormatRateLimitError(t *testing.T) {
	delay := 5 * time.Second

	errorMsg := FormatRateLimitError(delay)

	if !strings.Contains(errorMsg, "Rate limit exceeded") {
		t.Error("Error message should contain 'Rate limit exceeded'")
	}

	if !strings.Contains(errorMsg, "5s") || !strings.Contains(errorMsg, "try again in") {
		t.Error("Error message should mention the delay duration")
	}

	// Should contain a time
	if !strings.Contains(errorMsg, ":") {
		t.Error("Error message should contain a formatted time")
	}
}

func TestDifferentClientsIndependentLimits(t *testing.T) {
	cfg := &config.Config{
		Security: config.SecurityConfig{
			RateLimiting: config.RateLimitConfig{
				Enabled:        true,
				RequestsPerMin: 6,
				Burst:          1,
			},
		},
	}

	rl := NewRateLimiter(cfg)
	interceptor := rl.UnaryServerInterceptor()

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "response", nil
	}

	// Client 1
	ctx1 := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.1"), Port: 12345},
	})

	// Client 2
	ctx2 := peer.NewContext(context.Background(), &peer.Peer{
		Addr: &net.TCPAddr{IP: net.ParseIP("192.168.1.2"), Port: 12346},
	})

	// Client 1 uses up their limit
	_, err := interceptor(ctx1, "request", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Errorf("Client 1 first request failed: %v", err)
	}

	_, err = interceptor(ctx1, "request", &grpc.UnaryServerInfo{}, handler)
	if err == nil {
		t.Error("Client 1 second request should be rate limited")
	}

	// Client 2 should still be able to make requests
	_, err = interceptor(ctx2, "request", &grpc.UnaryServerInfo{}, handler)
	if err != nil {
		t.Errorf("Client 2 should not be rate limited: %v", err)
	}
}

// Mock ServerStream for testing
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func (m *mockServerStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockServerStream) RecvMsg(msg interface{}) error {
	return nil
}