package observability

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"stratium/config"
	"stratium/logging"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
)

// Provider wires together trace and metric exporters for a service process.
type Provider struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	metricsServer  *http.Server
}

// Init configures OpenTelemetry tracing and metrics exporters based on service configuration.
func Init(ctx context.Context, cfg *config.Config, logger *logging.Logger, serviceName, serviceVersion string) (*Provider, error) {
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion),
			semconv.DeploymentEnvironmentName(cfg.Service.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build telemetry resource: %w", err)
	}

	provider := &Provider{}
	var errs []error

	if cfg.Observability.Tracing.Enabled {
		tp, err := initTracerProvider(ctx, cfg, res, logger)
		if err != nil {
			logger.Warn("Failed to initialize tracing exporter: %v", err)
			errs = append(errs, err)
		} else {
			provider.tracerProvider = tp
			otel.SetTracerProvider(tp)
			otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
				propagation.TraceContext{},
				propagation.Baggage{},
			))
			logger.Startup("Tracing exporter initialized (provider=%s, endpoint=%s)",
				cfg.Observability.Tracing.Provider, cfg.Observability.Tracing.Endpoint)
		}
	} else {
		logger.Startup("Tracing disabled for %s", serviceName)
	}

	if cfg.Observability.Metrics.Enabled {
		mp, server, err := initMetricsProvider(ctx, cfg, res, logger)
		if err != nil {
			logger.Warn("Failed to initialize metrics exporter: %v", err)
			errs = append(errs, err)
		} else {
			provider.meterProvider = mp
			provider.metricsServer = server
			otel.SetMeterProvider(mp)
			logger.Startup("Metrics exporter listening on %s%s", cfg.Observability.Metrics.Address, cfg.Observability.Metrics.Path)
		}
	} else {
		logger.Startup("Metrics disabled for %s", serviceName)
	}

	if len(errs) > 0 {
		return provider, errors.Join(errs...)
	}

	return provider, nil
}

// Shutdown gracefully drains exporters.
func (p *Provider) Shutdown(ctx context.Context) error {
	var errs []error

	if p.metricsServer != nil {
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := p.metricsServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs = append(errs, fmt.Errorf("metrics server shutdown: %w", err))
		}
	}

	if p.meterProvider != nil {
		if err := p.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter provider shutdown: %w", err))
		}
	}

	if p.tracerProvider != nil {
		if err := p.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("tracer provider shutdown: %w", err))
		}
	}

	return errors.Join(errs...)
}

func initTracerProvider(ctx context.Context, cfg *config.Config, res *resource.Resource, logger *logging.Logger) (*sdktrace.TracerProvider, error) {
	provider := strings.ToLower(strings.TrimSpace(cfg.Observability.Tracing.Provider))
	if provider == "" {
		provider = "otlp"
	}

	switch provider {
	case "otlp", "otlpgrpc", "otlp-grpc":
		endpoint := cfg.Observability.Tracing.Endpoint
		if endpoint == "" {
			endpoint = "otel-collector:4317"
		}

		exporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("otlp trace exporter init: %w", err)
		}

		return sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(res),
		), nil
	default:
		logger.Warn("Tracing provider %s not supported, disabling tracing", provider)
		return nil, nil
	}
}

func initMetricsProvider(ctx context.Context, cfg *config.Config, res *resource.Resource, logger *logging.Logger) (*sdkmetric.MeterProvider, *http.Server, error) {
	registry := prometheus.NewRegistry()

	exporter, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, fmt.Errorf("prometheus exporter init: %w", err)
	}

	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(exporter),
	)

	path := cfg.Observability.Metrics.Path
	if path == "" {
		path = "/metrics"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	mux := http.NewServeMux()
	mux.Handle(path, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	server := &http.Server{
		Addr:    cfg.Observability.Metrics.Address,
		Handler: mux,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Warn("metrics server exited: %v", err)
		}
	}()

	return meterProvider, server, nil
}
