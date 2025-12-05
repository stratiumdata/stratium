package key_access

import (
	"context"
	"sync"
	"time"

	"stratium/logging"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	keyAccessOnce         sync.Once
	keyAccessTracer       trace.Tracer
	wrapLatency           metric.Float64Histogram
	wrapRequests          metric.Int64Counter
	wrapErrors            metric.Int64Counter
	unwrapLatency         metric.Float64Histogram
	unwrapRequests        metric.Int64Counter
	unwrapErrors          metric.Int64Counter
	serviceKeyCacheEvents metric.Int64Counter
)

func initKeyAccessTelemetry() {
	keyAccessOnce.Do(func() {
		logger := logging.GetLogger()
		keyAccessTracer = otel.Tracer("stratium/services/key-access")
		meter := otel.GetMeterProvider().Meter("stratium/services/key-access")

		var err error

		if wrapLatency, err = meter.Float64Histogram(
			"stratium_key_access_wrap_duration_ms",
			metric.WithUnit("ms"),
			metric.WithDescription("WrapDEK latency"),
		); err != nil {
			logger.Warn("Failed to register wrap latency metric: %v", err)
		}

		if wrapRequests, err = meter.Int64Counter(
			"stratium_key_access_wrap_requests_total",
			metric.WithDescription("Number of WrapDEK invocations"),
		); err != nil {
			logger.Warn("Failed to register wrap request counter: %v", err)
		}

		if wrapErrors, err = meter.Int64Counter(
			"stratium_key_access_wrap_errors_total",
			metric.WithDescription("Number of WrapDEK errors"),
		); err != nil {
			logger.Warn("Failed to register wrap error counter: %v", err)
		}

		if unwrapLatency, err = meter.Float64Histogram(
			"stratium_key_access_unwrap_duration_ms",
			metric.WithUnit("ms"),
			metric.WithDescription("UnwrapDEK latency"),
		); err != nil {
			logger.Warn("Failed to register unwrap latency metric: %v", err)
		}

		if unwrapRequests, err = meter.Int64Counter(
			"stratium_key_access_unwrap_requests_total",
			metric.WithDescription("Number of UnwrapDEK invocations"),
		); err != nil {
			logger.Warn("Failed to register unwrap request counter: %v", err)
		}

		if unwrapErrors, err = meter.Int64Counter(
			"stratium_key_access_unwrap_errors_total",
			metric.WithDescription("Number of UnwrapDEK errors"),
		); err != nil {
			logger.Warn("Failed to register unwrap error counter: %v", err)
		}

		if serviceKeyCacheEvents, err = meter.Int64Counter(
			"stratium_key_access_service_key_cache_events_total",
			metric.WithDescription("Service key cache hit/miss events"),
		); err != nil {
			logger.Warn("Failed to register service key cache metric: %v", err)
		}
	})
}

func startKeyAccessSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	initKeyAccessTelemetry()
	if keyAccessTracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return keyAccessTracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func recordWrapTelemetry(ctx context.Context, duration time.Duration, granted bool, err error) {
	attrs := []attribute.KeyValue{
		attribute.Bool("access_granted", granted),
	}
	if wrapLatency != nil {
		wrapLatency.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}
	if wrapRequests != nil {
		wrapRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if err != nil && wrapErrors != nil {
		wrapErrors.Add(ctx, 1, metric.WithAttributes(
			append(attrs, attribute.String("error", err.Error()))...,
		))
	}
}

func recordUnwrapTelemetry(ctx context.Context, duration time.Duration, granted bool, err error) {
	attrs := []attribute.KeyValue{
		attribute.Bool("access_granted", granted),
	}
	if unwrapLatency != nil {
		unwrapLatency.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}
	if unwrapRequests != nil {
		unwrapRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if err != nil && unwrapErrors != nil {
		unwrapErrors.Add(ctx, 1, metric.WithAttributes(
			append(attrs, attribute.String("error", err.Error()))...,
		))
	}
}

func recordServiceKeyCacheEvent(hit bool) {
	if serviceKeyCacheEvents == nil {
		return
	}
	result := "miss"
	if hit {
		result = "hit"
	}
	serviceKeyCacheEvents.Add(context.Background(), 1, metric.WithAttributes(
		attribute.String("result", result),
	))
}
