# Stratium Telemetry Runbook

## Scope

This runbook describes how to enable, monitor, and operate the OpenTelemetry instrumentation that now spans the PDP (platform service), Key Access service, and the Go SDK. It covers:

- Build- and config-level toggles for metrics, tracing, and rate limiting.
- Prometheus/Grafana deployment for latency, throughput, and cache insights.
- Verification steps and remediation guidance for the shipped alerts.

## 1. Enable Observability Feature Flags

Observability is disabled in production builds unless explicitly toggled. Set the following build flag before compiling any service binary:

```bash
export BUILD_FEATURES="metrics,observability,rate-limiting"
docker build --build-arg BUILD_FEATURES=$BUILD_FEATURES ...
```

At runtime, the feature flag unlocks the `observability` config block. Double-check the following keys in your YAML or environment variables:

| Service | Setting | Default | Notes |
|---------|---------|---------|-------|
| `observability.metrics.enabled` | `true/false` | `false` | Enables the Prometheus exporter. |
| `observability.metrics.address` | `:9090` (platform) / `:9093` (key-access) | Binds the `/metrics` endpoint. |
| `observability.metrics.path` | `/metrics` | Change if behind a proxy. |
| `observability.tracing.enabled` | `true/false` | `false` | Enables the OTLP trace exporter. |
| `observability.tracing.endpoint` | `otel-collector:4317` | Any OTLP gRPC collector. |
| `observability.tracing.provider` | `otlp` | Only OTLP is supported today. |

Rate limiting stays on after `FeatureRateLimiting` is present, so keep it enabled alongside metrics/tracing for symmetry with the alerting rules.

## 2. Deploy Telemetry Stack (Docker)

The Docker compose file now includes Prometheus and Grafana. To bootstrap the stack:

```bash
cd deployment/docker
docker compose up --build prometheus grafana platform key-access
```

- Platform metrics: `http://localhost:9090/metrics`
- Key Access metrics: `http://localhost:9093/metrics`
- Prometheus UI: `http://localhost:9095`
- Grafana UI: `http://localhost:3000` (admin/admin)

Grafana auto-loads the **Stratium Telemetry** dashboard with these KPIs:

1. PDP p95 decision latency.
2. Key Access wrap p95 latency.
3. PDP request volume.
4. PDP policy cache hit ratio.
5. Service key cache hit ratio.
6. Key Access request volume.
7. **PDP rule-path depth** – p95 policies evaluated & entitlements scanned plus the default deny rate so you can spot runaway rule sets.
8. **Key Manager cache & DB health** – cache hit ratio per TTL cache, p95 query latency per table, and DB error rate.
9. **Rotation manager saturation** – total scheduled jobs and rotation operation latency (success vs. error).
10. **Auth/JWKS telemetry** – token validation p95 latency, failure rates, JWKS refresh frequency, and Keycloak HTTP latency per endpoint.

All panes are grouped so Ops can immediately correlate spikes (e.g., PDP default-deny vs. Key Manager DB errors).

## 3. Alerts

Prometheus rules (`deployment/docker/prometheus/alerts.yml`) emit:

| Alert | Trigger | Runbook |
|-------|---------|---------|
| `PDPHighLatency95th` | p95 decision latency > 200ms for 2m | Check PostgreSQL/Redis health, verify CPU on platform pods. |
| `KeyAccessWrapLatency95th` | p95 wrap latency > 250ms | Ensure PDP dependency healthy, verify Key Manager latency. |
| `PolicyCacheMissSpike` | PDP policy cache miss ratio > 20% for 5m | Inspect Redis connectivity or shorten TTL in `service.policy_cache_ttl_seconds`. |
| `ServiceKeyCacheMissSpike` | Key Access service-key cache hit rate < 70% | Validate client key churn; adjust `service.service_key_cache_ttl_seconds`. |

> **New dashboards / pending alerts:** Leverage the Key Manager DB and Auth panels to create SLO-style alerts if desired (e.g., default deny budget burn or Keycloak latency). Sample PromQL snippets are documented inline in Grafana panel queries.

### Operating the new metrics

- **PDP rule-path spikes**: If the p95 policies-evaluated panel exceeds the typical baseline (usually < 4 policies), inspect recent PAP pushes for overly broad conditions or missing indexes. Combine with the default-deny rate: a surge in both indicates malformed entitlements or subject attributes.
- **Key Manager caches**: Ratios below 80% usually mean the TTL is too low for current load or there is a burst of new client keys. Adjust `service.service_key_cache_ttl_seconds` / `cache.ttl` and ensure the Postgres instance is healthy.
- **Key Manager DB latency/errors**: Use the per-table (key_pairs vs. client_keys) breakdown to isolate slow queries. Spikes typically mean vacuum/autovacuum isn’t keeping up or the DB lacks indexes. Pause heavy rotations until latency recovers.
- **Rotation queue depth & latency**: If jobs monotonically increase or p95 duration spikes, throttle callers issuing `ScheduleRotation` and verify providers (HSM, software) are online. Errors in the rotation panel correlate with the queue depth panel.
- **Auth/JWKS**: Token validation latency shares the same OTLP pipeline as services. A jump usually indicates Keycloak slowness or TLS handshakes happening on every call. JWKS “refresh” events should be rare (< 1/minute). If they spike, Keycloak’s cache headers or network path are misconfigured. Keycloak request latency by path highlights whether discovery, JWKS, or token endpoints are degraded.

Silence alerts during rollouts via the Prometheus UI if needed.

## 4. SDK Telemetry

The Go SDK now exposes a `Telemetry` config block:

```go
client, err := stratium.NewClient(&stratium.Config{
    PlatformAddress: "...",
    Telemetry: &stratium.TelemetryConfig{
        Enabled:    true,
        Endpoint:   "otel-collector:4317",
        Insecure:   true,
        ServiceName: "my-app-sdk",
    },
})
```

When enabled, the SDK:

- Adds gRPC client interceptors for trace propagation end-to-end.
- Emits spans for `Platform.GetDecision`, `KeyAccess.{Request,Unwrap}`, `KeyManager.{Register,Get,List}`.
- Records latency/throughput counters via OpenTelemetry meters (ready for future OTLP metric exporters).

Traces appear in the same collector as the services, allowing cross-tier debugging of PDP or Key Access flows.

## 5. Verification Checklist

1. **Services**: `curl http://localhost:9090/metrics | grep stratium_platform_pdp` (expect counters/histograms).
2. **Prometheus**: `promtool check config deployment/docker/prometheus/prometheus.yml`.
3. **Grafana**: Confirm dashboard panels populate within 1–2 scrape intervals.
4. **Traces**: From collector backend (Tempo/Jaeger), search for `service.name=platform-server` spans including `PDP.EvaluateDecision`.
5. **Alerts**: Temporarily lower thresholds to confirm notifications fire, then revert.

## 6. Rollback / Disable

If telemetry needs to be disabled in an emergency:

1. Rebuild binaries without the `observability` feature flag or set `observability.metrics.enabled=false` and `observability.tracing.enabled=false`.
2. Stop Prometheus/Grafana containers to avoid stale dashboards.
3. Revert rate-limiting overrides only if they interfere with recovery.

Document any deviations in Ops notes so engineers know why telemetry went dark.
