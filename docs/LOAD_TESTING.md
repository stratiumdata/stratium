# Key Access Load Testing (k6)

This guide shows how to drive WrapDEK/UnwrapDEK traffic from your workstation against the staging EKS cluster using the `stratium-load-test` Keycloak client and the k6 load-testing runtime.

## Prerequisites

- Access to the staging network/endpoints (VPN or DirectConnect).
- `k6` v0.45+ installed locally (`brew install k6` or see https://k6.io/docs/getting-started/installation/).
- The `stratium-load-test` Keycloak client secret (rotate per environment).
- `proto/services/key-access/key-access.proto` available locally (already in this repo).

## Environment Variables

The k6 script (`load-testing/k6/wrap_unwrap.js`) is fully driven by environment variables so you can point it at any cluster:

| Variable | Description | Default |
|----------|-------------|---------|
| `KAS_TARGET` | Key Access gRPC endpoint (`host:port`). Use the internal service DNS or an ingress/port-forward address. | `localhost:50053` |
| `KAS_TLS` | Set to `true` if the endpoint terminates TLS; otherwise plaintext gRPC is used. | `false` |
| `RESOURCE_NAME` | Resource identifier evaluated by PAP. | `loadtest-resource` |
| `POLICY_B64` | Base64 encoded policy/manifest string required by PAP. | simple `classification=confidential` policy |
| `CLIENT_KEY_ID` | Client key id the test should use for `UnwrapDEK`. When omitted and `REGISTER_CLIENT_KEY=true`, the script registers a fresh client key and returns its id. | `loadtest-client-key` |
| `CLIENT_KEY_CLIENT_ID` | Client identifier recorded on registered client keys. | `loadtest-user` |
| `CLIENT_KEY_PREFIX` | Name prefix applied to auto-registered client keys. | `loadtest-client-key` |
| `CLIENT_PUBLIC_KEY_PEM` | PEM-encoded subject public key to register with the Key Manager (supports `\n`). | bundled RSA-2048 sample |
| `REGISTER_CLIENT_KEY` | Set to `true` to have the script register exactly one client key up front. (Alias: `REGISTER_CLIENT_KEYS`.) | `false` |
| `KM_TARGET` | Key Manager HTTPS endpoint used for client/service key provisioning. | `localhost:50052` |
| `KM_TLS` | Whether the Key Manager endpoint requires TLS. | `false` |
| `CREATE_SERVICE_KEYS` | When `true` **and** `KEY_IDS` is empty, the script creates service (wrap/unwrap) keys before the test. | `true` if `KEY_IDS` empty, otherwise `false` |
| `SERVICE_KEY_COUNT` | Number of service keys to create when `CREATE_SERVICE_KEYS=true`. | `5` |
| `SERVICE_KEY_PREFIX` | Prefix for auto-created service key names. | `loadtest-service-key` |
| `SERVICE_KEY_ROTATION_DAYS` | Rotation interval applied to auto-created service keys. | `90` |
| `LOADTEST_ENVIRONMENT` | Value stored in key metadata for auditing (client + service keys). | `load-test` |
| `KEY_IDS` | Comma-separated list of ≤5 pre-existing Key Manager key IDs. If supplied, no service keys are created. | `kas-key-1,...,kas-key-5` |
| `KEYCLOAK_BASE_URL` | External Keycloak base URL (no trailing slash). | `http://localhost:8080` |
| `KEYCLOAK_REALM` | Realm name. | `stratium` |
| `LOADTEST_CLIENT_ID` | Keycloak client id. | `stratium-load-test` |
| `LOADTEST_CLIENT_SECRET` | Client secret. | `stratium-load-test-secret` |
| `LOADTEST_USERNAME` | Username for password grant (required for Key Access). | `loadtest-user` |
| `LOADTEST_PASSWORD` | Password for the user. | `loadtest123` |
| `LOADTEST_SCOPE` | Space-separated scopes for password grant. | `openid profile` |
| `TOKEN_REFRESH_BUFFER` | Seconds to subtract from Keycloak token expiry before refreshing. | `30` |
| `START_RPS` | Initial arrival rate for the scenario. | `100` |
| `PRE_ALLOCATED_VUS` | Pre-allocated VUs for the ramping-arrival-rate executor. | `150` |
| `MAX_VUS` | Max VUs k6 may spin up. | `500` |
| `GRACEFUL_STOP` | Graceful stop window applied to the scenario. | `30s` |
| `RATE_STAGES` | JSON array describing target RPS ramp (see example below). | 250→500→750→1000 rps |
| `THINK_TIME_MS` | Optional pause in milliseconds after each wrap+unwrap pair. | `0` |

## Running the Load Generator

1. Ensure your workstation can resolve/reach the Key Access service. If needed, start a port-forward:
   ```bash
   kubectl -n stratium port-forward svc/stratium-key-access 50053:50053
   ```

2. Export the required environment variables (update URLs, secrets, and credentials to match staging). The example below provisions one client key and five service keys automatically; omit the `REGISTER_`/`CREATE_` toggles if you want to reuse existing ids:
   ```bash
   export KAS_TARGET=key-access.stratium.svc.cluster.local:50053
   export KAS_TLS=false
   export KM_TARGET=key-manager.stratium.svc.cluster.local:50052
   export KM_TLS=false
   export RESOURCE_NAME="loadtest-resource"
   export POLICY_B64="$(printf '{"artifacts":[{"name":"classification","value":"confidential"}]}' | base64 | tr -d '\n')"
   export REGISTER_CLIENT_KEY=true
   export CLIENT_PUBLIC_KEY_PEM="$(cat /path/to/client-public.pem)"
   export CREATE_SERVICE_KEYS=true
   export SERVICE_KEY_COUNT=5
   export KEYCLOAK_BASE_URL="https://auth.demostratium.com"
   export LOADTEST_CLIENT_ID="stratium-load-test"
   export LOADTEST_CLIENT_SECRET="<staging-secret>"
   export LOADTEST_USERNAME="loadtest-user"
   export LOADTEST_PASSWORD="<rotated-password-if-changed>"
   export START_RPS=250
   export RATE_STAGES='[
     {"target":250,"duration":"1m"},
     {"target":500,"duration":"2m"},
     {"target":750,"duration":"2m"},
     {"target":1000,"duration":"4m"}
   ]'
   ```

   The `loadtest-user` profile already includes `classification=confidential`, `department=engineering`, and `role=developer`. If you rotate its password, update `LOADTEST_PASSWORD` accordingly and re-import the realm or adjust the user via the Keycloak admin console.

3. Run the script (the setup phase will register the client key, create service keys if requested, and reuse the resulting IDs for every VU):
   ```bash
   k6 run load-testing/k6/wrap_unwrap.js
   ```

The script:

- Grabs Keycloak tokens via the password grant (falls back to client credentials only if no username/password are provided), caching and refreshing them automatically.
- Registers a single client key with the Key Manager when `REGISTER_CLIENT_KEY=true`, otherwise uses the provided `CLIENT_KEY_ID`.
- Creates the requested number of service keys (or uses the supplied `KEY_IDS`), storing their ids for every virtual user.
- Generates a new random 256-bit DEK for every WrapDEK call (ensuring no reuse).
- Randomly picks among up to five configured service key IDs to satisfy the “≤5 keys” constraint.
- Immediately issues the matching UnwrapDEK call using the wrapped DEK from the previous step, so each iteration exercises both RPCs under the same auth token.
- Reports separate k6 checks for wrap/unwrap success, and exposes overall RPC latency under the `grpc_req_duration` metric.

## Customizing the Profile

- Modify `RATE_STAGES` to try different RPS ramps or sustained plateaus.
- Use `THINK_TIME_MS` to simulate client-side processing gaps between wrap/unwrap pairs.
- Override `POLICY_B64` with the exact manifest for the staged resource.
- Set `KAS_TLS=true` when targeting an HTTPS gRPC endpoint (for example, via an ALB).

## Observability Checklist

Before running the 1000 RPS scenario, make sure:

- Key Access pods and Key Manager pods are autoscaled appropriately.
- Keycloak CPU/memory dashboards are visible (token issuance adds load).
- Database metrics (connections, CPU, slow queries) are being captured so you can correlate spikes with the load test.
- Any downstream dependencies (KMS, Redis, etc.) have proper rate limits/quotas to avoid collateral impact.

With the above in place, you can confidently iterate on load profiles from your workstation and track how close the system is to the 1000 rps target before scaling.*** End Patch
