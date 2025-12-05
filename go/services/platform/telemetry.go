package platform

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
	pdpTelemetryOnce         sync.Once
	pdpTracer                trace.Tracer
	pdpDecisionLatency       metric.Float64Histogram
	pdpDecisionCounter       metric.Int64Counter
	pdpDecisionErrorCounter  metric.Int64Counter
	pdpPolicyCacheEvents     metric.Int64Counter
	pdpPolicyEvaluationSteps metric.Float64Histogram
	pdpEntitlementEvalSteps  metric.Float64Histogram
	pdpDefaultDenyCounter    metric.Int64Counter
)

func initPDPTelemetry() {
	pdpTelemetryOnce.Do(func() {
		logger := logging.GetLogger()
		pdpTracer = otel.Tracer("stratium/services/platform/pdp")
		meter := otel.GetMeterProvider().Meter("stratium/services/platform/pdp")

		var err error
		if pdpDecisionLatency, err = meter.Float64Histogram(
			"stratium_platform_pdp_decision_duration_ms",
			metric.WithDescription("Latency of PDP decision evaluations in milliseconds"),
			metric.WithUnit("ms"),
		); err != nil {
			logger.Warn("Failed to register PDP decision latency metric: %v", err)
		}

		if pdpDecisionCounter, err = meter.Int64Counter(
			"stratium_platform_pdp_requests_total",
			metric.WithDescription("Total PDP decision evaluations grouped by outcome"),
		); err != nil {
			logger.Warn("Failed to register PDP request counter: %v", err)
		}

		if pdpDecisionErrorCounter, err = meter.Int64Counter(
			"stratium_platform_pdp_errors_total",
			metric.WithDescription("Total PDP evaluation errors"),
		); err != nil {
			logger.Warn("Failed to register PDP error counter: %v", err)
		}

		if pdpPolicyCacheEvents, err = meter.Int64Counter(
			"stratium_platform_pdp_policy_cache_events_total",
			metric.WithDescription("Policy cache events (hit/miss) for enabled policies list"),
		); err != nil {
			logger.Warn("Failed to register PDP cache counter: %v", err)
		}

		if pdpPolicyEvaluationSteps, err = meter.Float64Histogram(
			"stratium_platform_pdp_policy_eval_steps",
			metric.WithDescription("Number of policies evaluated before reaching a decision"),
		); err != nil {
			logger.Warn("Failed to register PDP policy evaluation metric: %v", err)
		}

		if pdpEntitlementEvalSteps, err = meter.Float64Histogram(
			"stratium_platform_pdp_entitlement_eval_steps",
			metric.WithDescription("Number of entitlements scanned before reaching a decision"),
		); err != nil {
			logger.Warn("Failed to register PDP entitlement evaluation metric: %v", err)
		}

		if pdpDefaultDenyCounter, err = meter.Int64Counter(
			"stratium_platform_pdp_default_deny_total",
			metric.WithDescription("Number of requests that fell back to default deny"),
		); err != nil {
			logger.Warn("Failed to register PDP default deny counter: %v", err)
		}
	})
}

func startPDPSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	initPDPTelemetry()
	if pdpTracer == nil {
		return ctx, trace.SpanFromContext(ctx)
	}
	return pdpTracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

func recordPDPDecisionTelemetry(ctx context.Context, duration time.Duration, decision string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("decision", decision),
	}
	if err != nil {
		attrs = append(attrs, attribute.String("error", err.Error()))
		if pdpDecisionErrorCounter != nil {
			pdpDecisionErrorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
		}
	}

	if pdpDecisionLatency != nil {
		pdpDecisionLatency.Record(ctx, float64(duration.Milliseconds()), metric.WithAttributes(attrs...))
	}

	if pdpDecisionCounter != nil {
		pdpDecisionCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func recordPDPPolicyCacheEvent(ctx context.Context, hit bool) {
	if pdpPolicyCacheEvents == nil {
		return
	}
	result := "miss"
	if hit {
		result = "hit"
	}
	pdpPolicyCacheEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
	))
}

func recordPDPPolicyEvaluation(ctx context.Context, evaluated int, outcome string, language string, effect string) {
	if pdpPolicyEvaluationSteps == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("outcome", outcome),
	}
	if language != "" {
		attrs = append(attrs, attribute.String("language", language))
	}
	if effect != "" {
		attrs = append(attrs, attribute.String("effect", effect))
	}

	pdpPolicyEvaluationSteps.Record(ctx, float64(evaluated), metric.WithAttributes(attrs...))
}

func recordPDPEntitlementEvaluation(ctx context.Context, evaluated int, outcome string) {
	if pdpEntitlementEvalSteps == nil {
		return
	}
	pdpEntitlementEvalSteps.Record(ctx, float64(evaluated), metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

func recordPDPDefaultDeny(ctx context.Context) {
	if pdpDefaultDenyCounter == nil {
		return
	}
	pdpDefaultDenyCounter.Add(ctx, 1)
}
