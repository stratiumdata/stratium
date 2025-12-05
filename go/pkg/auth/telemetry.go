package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"stratium/logging"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	authTelemetryOnce sync.Once
	authMeter         metric.Meter

	authTokenValidationLatency metric.Float64Histogram
	authTokenValidationCounter metric.Int64Counter
	authJWKSCacheEvents        metric.Int64Counter
	authKeycloakRequestLatency metric.Float64Histogram
)

func initAuthTelemetry() {
	authTelemetryOnce.Do(func() {
		logger := logging.GetLogger()
		authMeter = otel.GetMeterProvider().Meter("stratium/pkg/auth")

		var err error
		if authTokenValidationLatency, err = authMeter.Float64Histogram(
			"stratium_auth_token_validation_duration_ms",
			metric.WithDescription("Latency of OIDC token validation"),
			metric.WithUnit("ms"),
		); err != nil {
			logger.Warn("Failed to register auth token validation latency: %v", err)
		}

		if authTokenValidationCounter, err = authMeter.Int64Counter(
			"stratium_auth_token_validation_total",
			metric.WithDescription("Total OIDC token validation attempts"),
		); err != nil {
			logger.Warn("Failed to register auth token validation counter: %v", err)
		}

		if authJWKSCacheEvents, err = authMeter.Int64Counter(
			"stratium_auth_jwks_cache_events_total",
			metric.WithDescription("JWKS cache refresh events observed by the auth client"),
		); err != nil {
			logger.Warn("Failed to register auth JWKS cache counter: %v", err)
		}

		if authKeycloakRequestLatency, err = authMeter.Float64Histogram(
			"stratium_auth_keycloak_http_duration_ms",
			metric.WithDescription("Latency of HTTP calls to the configured IdP/Keycloak host"),
			metric.WithUnit("ms"),
		); err != nil {
			logger.Warn("Failed to register auth Keycloak request histogram: %v", err)
		}
	})
}

func recordTokenValidation(ctx context.Context, duration time.Duration, result string, err error) {
	initAuthTelemetry()
	if authTokenValidationLatency != nil {
		authTokenValidationLatency.Record(safeAuthContext(ctx), float64(duration.Milliseconds()),
			metric.WithAttributes(attribute.String("result", result)))
	}
	if authTokenValidationCounter != nil {
		attrs := []attribute.KeyValue{attribute.String("result", result)}
		if err != nil {
			attrs = append(attrs, attribute.String("error", err.Error()))
		}
		authTokenValidationCounter.Add(safeAuthContext(ctx), 1, metric.WithAttributes(attrs...))
	}
}

func recordJWKSCacheEvent(result string, statusCode int) {
	initAuthTelemetry()
	if authJWKSCacheEvents == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("result", result),
	}
	if statusCode > 0 {
		attrs = append(attrs, attribute.Int("status_code", statusCode))
	}
	authJWKSCacheEvents.Add(context.Background(), 1, metric.WithAttributes(attrs...))
}

func recordKeycloakRequest(ctx context.Context, method, path string, status string, statusCode int, duration time.Duration) {
	initAuthTelemetry()
	if authKeycloakRequestLatency == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
		attribute.String("path", path),
		attribute.String("status", status),
	}
	if statusCode > 0 {
		attrs = append(attrs, attribute.Int("status_code", statusCode))
	}
	authKeycloakRequestLatency.Record(safeAuthContext(ctx), float64(duration.Milliseconds()),
		metric.WithAttributes(attrs...))
}

func safeAuthContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

type instrumentedTransport struct {
	base http.RoundTripper
}

func newInstrumentedTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &instrumentedTransport{base: base}
}

func (it *instrumentedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := it.base.RoundTrip(req)
	duration := time.Since(start)

	status := "success"
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
		if resp.StatusCode >= http.StatusBadRequest {
			status = "error"
		}
	}
	if err != nil {
		status = "error"
	}

	recordKeycloakRequest(req.Context(), req.Method, req.URL.Path, status, statusCode, duration)

	if strings.Contains(strings.ToLower(req.URL.Path), "jwks") {
		jwksResult := "refresh"
		if status == "error" {
			jwksResult = "error"
		}
		recordJWKSCacheEvent(jwksResult, statusCode)
	}

	return resp, err
}
