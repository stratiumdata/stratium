# `stratium-pep extauthz`

A gRPC server answering `envoy.service.auth.v3.Authorization/Check` — the
contract Envoy's `ext_authz` filter calls, synchronously, on every request it
fronts, before deciding whether to forward it.

Use it to police an agent's **HTTP** traffic. Every other mode sits beside the
thing it enforces; this one sits beside Envoy, and Envoy does the enforcing on
its word.

---

## Where it sits

```
agent ──HTTP──▶ Envoy ──Check()──▶ stratium-pep extauthz ──▶ PDP
                  │                          │
                  │◀── OK / PERMISSION_DENIED┘
                  ▼
              upstream service        (only if OK)
```

The PEP never sees the request body or forwards anything. It answers one
question per request, and Envoy acts on the answer.

---

## Configuration

Six variables — the smallest surface of the five. **Observed** with an empty
environment:

```
$ stratium-pep extauthz
stratium-pep: missing required configuration: STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR,
STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID, STRATIUM_PEP_SUBJECT,
STRATIUM_PEP_CONNECT_TIMEOUT, STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS
```

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR` | `127.0.0.1:10000` | Where Envoy connects. |
| `STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS` | `api.example.com,orders.internal` | Hosts this PEP will answer for. |
| `STRATIUM_PEP_PDP_ADDR` | `localhost:50051` | |
| `STRATIUM_PEP_AGENT_ID` | `0f8f833a-…` | |
| `STRATIUM_PEP_SUBJECT` | `you@example.com` | |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | `5s` | |

**No session file, no approval durations, no cache window.** Envoy's `ext_authz`
budget is milliseconds, not minutes, so this surface cannot hold a request open
waiting for anything — which is why the approval settings are absent rather than
optional.

---

## Worked example

```bash
export STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR="127.0.0.1:10000" \
       STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS="api.example.com" \
       STRATIUM_PEP_PDP_ADDR="localhost:50051" \
       STRATIUM_PEP_AGENT_ID="0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19" \
       STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
       STRATIUM_PEP_CONNECT_TIMEOUT=5s

stratium-pep extauthz
```

The Envoy side, in the listener that fronts the agent's traffic:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      transport_api_version: V3
      # No failure_mode_allow. The default is deny-on-error, and that is the
      # point: if this PEP is unreachable, requests must NOT sail through.
      grpc_service:
        envoy_grpc:
          cluster_name: stratium_extauthz
        timeout: 5s
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

clusters:
  - name: stratium_extauthz
    type: STATIC
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config: { http2_protocol_options: {} }
    load_assignment:
      cluster_name: stratium_extauthz
      endpoints:
        - lb_endpoints:
            - endpoint:
                address: { socket_address: { address: 127.0.0.1, port_value: 10000 } }
```

> **Never set `failure_mode_allow: true` on this filter.** It converts every PEP
> outage into a blanket allow. Deny-on-error is Envoy's default and is the
> behaviour this design assumes.

The agent attaches its delegation token as a normal HTTP header:

```
Authorization: Bearer <the session file's token>
```

---

## How the decision is built

The tool identity, the bearer token, and a **credential-stripped** `raw_input`
are extracted from the `CheckRequest`. The request path becomes the catalogable
tool name, per tenant, exactly like a filesystem tool's name.

**A request with no usable credential denies before the PDP is dialed.** No
token, no round trip, no allow.

---

## What Envoy sees back

| PDP effect | Answer |
|---|---|
| `EFFECT_ALLOW` | `OkResponse` — Envoy forwards. |
| `EFFECT_DENY` | `PERMISSION_DENIED`, carrying the PDP's reason verbatim. |
| `EFFECT_ESCALATE` | The same `PERMISSION_DENIED`, plus the pending approval's id — in a dedicated response header *and* in the denial body. |
| anything unrecognised, including unset | Treated as deny, deliberately asserted rather than assumed. |

Escalation **degrades to denial** here rather than blocking, because Envoy's
budget cannot accommodate a human. Retry once the approval lands.

---

## Limits

- **Per-request, not per-body.** The decision is built from the request line,
  headers and host. Bodies are not inspected.
- **No approval flow.** By design, per the degrade above.
- **`ALLOWED_HOSTS` closes a replay, it is not a policy.** It exists to stop a
  specific attack — a decision obtained for one host being replayed against
  another — which the request's own `Host` alone could not prevent. What is
  *permitted* for an allowed host remains entirely the PDP's business.
- **One tenant.** Like every other surface, the PDP it talks to serves exactly
  one tenant, named at that PDP's startup.

---

## See also

- [`proxy.md`](proxy.md) — the same idea for gRPC, without needing Envoy.
- [`../pep.md`](../pep.md) § "Reading a denial".
- [`../../example/extauthz/`](../../example/extauthz/) — this surface as a runnable program, policing which LLM model an agent may call.
