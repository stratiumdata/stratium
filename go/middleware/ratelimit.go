package middleware

import (
	"context"
	"fmt"
	"stratium/config"
	"stratium/logging"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// RateLimiter manages rate limiting for gRPC requests
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	config   *config.Config
	logger   *logging.Logger
}

// NewRateLimiter creates a new rate limiter middleware
func NewRateLimiter(cfg *config.Config) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   cfg,
		logger:   logging.GetLogger(),
	}
}

// getLimiter returns or creates a rate limiter for a specific client
func (rl *RateLimiter) getLimiter(clientIP string) *rate.Limiter {
	rl.mu.RLock()
	limiter, exists := rl.limiters[clientIP]
	rl.mu.RUnlock()

	if exists {
		return limiter
	}

	// Create a new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check again in case another goroutine created it
	if limiter, exists := rl.limiters[clientIP]; exists {
		return limiter
	}

	// Calculate rate limit from requests per minute
	requestsPerMin := rl.config.Security.RateLimiting.RequestsPerMin
	burst := rl.config.Security.RateLimiting.Burst

	// Convert requests per minute to requests per second
	ratePerSec := float64(requestsPerMin) / 60.0

	limiter = rate.NewLimiter(rate.Limit(ratePerSec), burst)
	rl.limiters[clientIP] = limiter

	return limiter
}

// getClientIP extracts the client IP from the gRPC context
func getClientIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	return p.Addr.String()
}

// UnaryServerInterceptor returns a gRPC unary server interceptor for rate limiting
func (rl *RateLimiter) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if !rl.config.Security.RateLimiting.Enabled {
			return handler(ctx, req)
		}

		clientIP := getClientIP(ctx)
		limiter := rl.getLimiter(clientIP)

		// Try to reserve a token
		reservation := limiter.Reserve()
		if !reservation.OK() {
			return nil, status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		delay := reservation.Delay()
		if delay > 0 {
			// Calculate when the next call can be made
			nextCallTime := time.Now().Add(delay)

			rl.logger.Warn(
				"Rate limit exceeded for client %s. Next call allowed at %s (in %v)",
				clientIP,
				nextCallTime.Format("15:04:05"),
				delay.Round(time.Second),
			)

			// Cancel the reservation since we're rejecting the request
			reservation.Cancel()

			return nil, status.Errorf(
				codes.ResourceExhausted,
				"rate limit exceeded. Try again in %v (at %s)",
				delay.Round(time.Second),
				nextCallTime.Format("15:04:05"),
			)
		}

		// Request is allowed, proceed
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor for rate limiting
func (rl *RateLimiter) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if !rl.config.Security.RateLimiting.Enabled {
			return handler(srv, ss)
		}

		ctx := ss.Context()
		clientIP := getClientIP(ctx)
		limiter := rl.getLimiter(clientIP)

		// Try to reserve a token
		reservation := limiter.Reserve()
		if !reservation.OK() {
			return status.Errorf(codes.ResourceExhausted, "rate limit exceeded")
		}

		delay := reservation.Delay()
		if delay > 0 {
			// Calculate when the next call can be made
			nextCallTime := time.Now().Add(delay)

			rl.logger.Warn(
				"Rate limit exceeded for client %s on stream. Next call allowed at %s (in %v)",
				clientIP,
				nextCallTime.Format("15:04:05"),
				delay.Round(time.Second),
			)

			// Cancel the reservation since we're rejecting the request
			reservation.Cancel()

			return status.Errorf(
				codes.ResourceExhausted,
				"rate limit exceeded. Try again in %v (at %s)",
				delay.Round(time.Second),
				nextCallTime.Format("15:04:05"),
			)
		}

		// Request is allowed, proceed
		return handler(srv, ss)
	}
}

// PrintRateLimitInfo logs the current rate limit configuration
func (rl *RateLimiter) PrintRateLimitInfo(serviceName string) {
	if !rl.config.Security.RateLimiting.Enabled {
		rl.logger.Startup("Rate limiting: DISABLED")
		return
	}

	requestsPerMin := rl.config.Security.RateLimiting.RequestsPerMin
	burst := rl.config.Security.RateLimiting.Burst

	rl.logger.Startup(
		"Rate limiting: ENABLED - %d requests/min (burst: %d) for %s",
		requestsPerMin,
		burst,
		serviceName,
	)

	// Calculate average time between requests
	avgTimeBetween := time.Minute / time.Duration(requestsPerMin)
	rl.logger.Startup(
		"Average time between allowed requests: %v",
		avgTimeBetween.Round(time.Second),
	)
}

// Cleanup removes old limiters to prevent memory leaks
func (rl *RateLimiter) Cleanup(maxAge time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// In a real implementation, you'd track last access time
	// For now, this is a simple implementation that trusts garbage collection
	// For production, you'd want to track access times and remove stale entries

	// This is a placeholder for future enhancement
	// You could store lastAccess times and remove entries older than maxAge
}

// GetCurrentLimit returns the current rate limit configuration
func (rl *RateLimiter) GetCurrentLimit() (requestsPerMin int, burst int, enabled bool) {
	return rl.config.Security.RateLimiting.RequestsPerMin,
		rl.config.Security.RateLimiting.Burst,
		rl.config.Security.RateLimiting.Enabled
}

// FormatRateLimitError creates a user-friendly error message for rate limit exceeded
func FormatRateLimitError(delay time.Duration) string {
	nextCallTime := time.Now().Add(delay)
	return fmt.Sprintf(
		"Rate limit exceeded. Please try again in %v (at %s)",
		delay.Round(time.Second),
		nextCallTime.Format("15:04:05 MST"),
	)
}