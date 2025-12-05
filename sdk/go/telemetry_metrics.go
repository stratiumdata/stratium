package stratium

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

var (
	sdkTelemetryOnce sync.Once
	sdkTracer        trace.Tracer
	sdkRequestLat    metric.Float64Histogram
	sdkRequestCount  metric.Int64Counter
	sdkRequestErrors metric.Int64Counter
)

func initSDKTelemetryInstruments() {
	sdkTelemetryOnce.Do(func() {
		meter := otel.GetMeterProvider().Meter("github.com/stratiumdata/go-sdk")
		sdkTracer = otel.Tracer("github.com/stratiumdata/go-sdk")

		var err error
		if sdkRequestLat, err = meter.Float64Histogram(
			"stratium_sdk_request_duration_ms",
			metric.WithUnit("ms"),
			metric.WithDescription("Latency for SDK gRPC calls"),
		); err != nil {
			return
		}

		if sdkRequestCount, err = meter.Int64Counter(
			"stratium_sdk_requests_total",
			metric.WithDescription("Total SDK gRPC calls"),
		); err != nil {
			return
		}

		if sdkRequestErrors, err = meter.Int64Counter(
			"stratium_sdk_request_errors_total",
			metric.WithDescription("SDK gRPC call errors"),
		); err != nil {
			return
		}
	})
}

func startSDKSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	initSDKTelemetryInstruments()
	if sdkTracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return sdkTracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func recordSDKRequestMetrics(ctx context.Context, method string, duration time.Duration, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
	}
	if sdkRequestLat != nil {
		sdkRequestLat.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}
	if sdkRequestCount != nil {
		sdkRequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	if err != nil && sdkRequestErrors != nil {
		sdkRequestErrors.Add(ctx, 1, metric.WithAttributes(
			append(attrs, attribute.String("error", err.Error()))...,
		))
	}
}
