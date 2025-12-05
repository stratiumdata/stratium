package key_manager

import (
	"context"
	"sync"
	"time"

	"stratium/logging"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	keyManagerTelemetryOnce sync.Once
	keyManagerMeter         metric.Meter

	keyManagerCacheEvents       metric.Int64Counter
	keyManagerDBLatency         metric.Float64Histogram
	keyManagerDBErrors          metric.Int64Counter
	keyManagerRotationJobsGauge metric.Int64UpDownCounter
	keyManagerRotationLatency   metric.Float64Histogram
)

func initKeyManagerTelemetry() {
	keyManagerTelemetryOnce.Do(func() {
		logger := logging.GetLogger()
		keyManagerMeter = otel.GetMeterProvider().Meter("stratium/services/key-manager")

		var err error
		if keyManagerCacheEvents, err = keyManagerMeter.Int64Counter(
			"stratium_key_manager_cache_events_total",
			metric.WithDescription("Cache events for key metadata and client key lookups"),
		); err != nil {
			logger.Warn("Failed to register key manager cache counter: %v", err)
		}

		if keyManagerDBLatency, err = keyManagerMeter.Float64Histogram(
			"stratium_key_manager_db_query_duration_ms",
			metric.WithDescription("Latency of key-manager database queries in milliseconds"),
			metric.WithUnit("ms"),
		); err != nil {
			logger.Warn("Failed to register key manager DB latency histogram: %v", err)
		}

		if keyManagerDBErrors, err = keyManagerMeter.Int64Counter(
			"stratium_key_manager_db_query_errors_total",
			metric.WithDescription("Failed key-manager database queries"),
		); err != nil {
			logger.Warn("Failed to register key manager DB error counter: %v", err)
		}

		if keyManagerRotationJobsGauge, err = keyManagerMeter.Int64UpDownCounter(
			"stratium_key_manager_rotation_jobs",
			metric.WithDescription("Number of scheduled key rotation jobs"),
		); err != nil {
			logger.Warn("Failed to register key rotation job gauge: %v", err)
		}

		if keyManagerRotationLatency, err = keyManagerMeter.Float64Histogram(
			"stratium_key_manager_rotation_duration_ms",
			metric.WithDescription("Duration of key rotation operations"),
			metric.WithUnit("ms"),
		); err != nil {
			logger.Warn("Failed to register key rotation latency histogram: %v", err)
		}
	})
}

func recordKeyManagerCacheEvent(cacheName, result string) {
	if cacheName == "" {
		return
	}
	initKeyManagerTelemetry()
	if keyManagerCacheEvents == nil {
		return
	}
	keyManagerCacheEvents.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("cache", cacheName),
			attribute.String("result", result),
		))
}

func recordKeyManagerDBQuery(ctx context.Context, table, operation string, duration time.Duration, err error) {
	initKeyManagerTelemetry()
	attrs := []attribute.KeyValue{
		attribute.String("table", table),
		attribute.String("operation", operation),
	}

	if keyManagerDBLatency != nil {
		keyManagerDBLatency.Record(safeContext(ctx), float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}

	if err != nil && keyManagerDBErrors != nil {
		errorAttrs := append(attrs, attribute.String("error", err.Error()))
		keyManagerDBErrors.Add(safeContext(ctx), 1, metric.WithAttributes(errorAttrs...))
	}
}

func adjustRotationJobGauge(delta int64) {
	initKeyManagerTelemetry()
	if keyManagerRotationJobsGauge == nil || delta == 0 {
		return
	}
	keyManagerRotationJobsGauge.Add(context.Background(), delta)
}

func recordKeyRotationLatency(ctx context.Context, duration time.Duration, success bool) {
	initKeyManagerTelemetry()
	if keyManagerRotationLatency == nil {
		return
	}
	result := "success"
	if !success {
		result = "error"
	}
	keyManagerRotationLatency.Record(safeContext(ctx), float64(duration.Milliseconds()),
		metric.WithAttributes(attribute.String("result", result)))
}

func safeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
