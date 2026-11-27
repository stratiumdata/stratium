# `stratium-pep proxy`

A transparent gRPC proxy. An agent points its existing gRPC client at this
process instead of the real target, speaks the target's own protocol completely
unchanged, and the proxy forwards — asking the PDP first.

Use it to police an agent's calls to a gRPC service **without modifying the
agent**. That is the entire reason it is worth deploying: no client rewrite, no
Stratium-specific envelope.

---

## Where it sits

```
agent's gRPC client  ──▶  stratium-pep proxy  ──▶  real service
                                  │
                                  └──▶ PDP, per call
```

It terminates the agent's connection and re-originates it against the target.
The agent sees the target's protocol; the target sees a normal client.

---

## Configuration

Nine variables, all required — **observed** with an empty environment:

```
$ stratium-pep proxy
stratium-pep: missing required configuration: STRATIUM_PEP_PROXY_LISTEN_ADDR,
STRATIUM_PEP_PROXY_TARGET_ADDR, STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID,
STRATIUM_PEP_SUBJECT, STRATIUM_PEP_CONNECT_TIMEOUT,
STRATIUM_PEP_APPROVAL_POLL_INTERVAL, STRATIUM_PEP_APPROVAL_TIMEOUT,
STRATIUM_PEP_PROXY_PUBLIC_URI
```

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_PROXY_LISTEN_ADDR` | `127.0.0.1:9292` | Where the agent connects. |
| `STRATIUM_PEP_PROXY_TARGET_ADDR` | `orders.internal:50051` | The real service. |
| `STRATIUM_PEP_PROXY_PUBLIC_URI` | `https://proxy.example.com` | The proxy's **own** address. It becomes the `htu` claim a DPoP proof (RFC 9449) is checked against — never the target's address. Required, no default. |
| `STRATIUM_PEP_PDP_ADDR` | `localhost:50051` | |
| `STRATIUM_PEP_AGENT_ID` | `0f8f833a-…` | |
| `STRATIUM_PEP_SUBJECT` | `you@example.com` | |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | `5s` | |
| `STRATIUM_PEP_PDP_CA_FILE` | `/etc/stratium/pdp-ca.pem` | Optional. PEM CA bundle to verify the PDP's TLS certificate with, instead of the system roots. Applies to the PDP connection only; the connection to `STRATIUM_PEP_PROXY_TARGET_ADDR` is unchanged. |
| `STRATIUM_PEP_PDP_INSECURE` | `true` | Optional. Plaintext connection to the PDP, for a local development stack only. Default is TLS. Conflicts with `STRATIUM_PEP_PDP_CA_FILE`. |
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | `2s` | |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | `120s` | |

**No `STRATIUM_PEP_SESSION_FILE`, and no cache staleness window.** This surface
carries no session file — it is not a companion to `session-start`. The
delegation token arrives from the caller instead, in gRPC metadata.

---

## Worked example

```bash
export STRATIUM_PEP_PROXY_LISTEN_ADDR="127.0.0.1:9292" \
       STRATIUM_PEP_PROXY_TARGET_ADDR="orders.internal:50051" \
       STRATIUM_PEP_PROXY_PUBLIC_URI="https://proxy.example.com" \
       STRATIUM_PEP_PDP_ADDR="localhost:50051" \
       STRATIUM_PEP_PDP_INSECURE=true \
       STRATIUM_PEP_AGENT_ID="0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19" \
       STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
       STRATIUM_PEP_CONNECT_TIMEOUT=5s \
       STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s \
       STRATIUM_PEP_APPROVAL_TIMEOUT=120s

stratium-pep proxy
```

Then repoint the agent — the only change on its side:

```diff
- conn, err := grpc.Dial("orders.internal:50051", …)
+ conn, err := grpc.Dial("127.0.0.1:9292", …)
```

The agent attaches a delegation token and a proof as gRPC metadata:

```
authorization: Bearer <a token bound to the agent's key>
dpop: <a proof signed with that key>
```

**The session file's token is refused here.** `session-start` issues a
bearer token, and this surface accepts only a token bound to a key the caller
holds (RFC 9449 DPoP), with a fresh proof on every call. A bearer token is
answered with

```
this surface requires a sender-constrained token (RFC 9449 DPoP), and the
delegation token presented is not bound to a key
```

whatever policy says. To get a bound token, the agent:

1. generates a P-256 key pair and keeps the private key;
2. calls the PDP's `IssueToken` with the session file's `delegation_id`, the
   session file's `token`, and the public key as a JWK in `dpop_jwk`. The
   reply's token is bound to that key;
   the delegation is now bound to that key for good, and the session file's
   own token stops working, so give this surface a session of its own;
3. signs a new proof for each call: a JWT of type `dpop+jwt`, signed ES256
   with the public key embedded, claiming `htm` `POST`, `htu`
   `STRATIUM_PEP_PROXY_PUBLIC_URI` followed by the full method path
   (`https://proxy.example.com/orders.v1.Orders/Cancel`), a unique `jti` and
   the current time as `iat`.

A proof is good for one call. `MintBoundToken` in
[`example/agent/setup.go`](../../example/agent/setup.go) and `proof` in
[`example/proxy/main.go`](../../example/proxy/main.go) are a working client.
See [Sender-constrained tokens on `proxy`](../pep.md#sender-constrained-tokens-on-proxy).

---

## How the decision is built

| Decision field | Comes from |
|---|---|
| tool | The **full gRPC method**, e.g. `/orders.v1.Orders/Cancel`. Catalogue it per tenant exactly like any other tool name. |
| token | gRPC metadata's `authorization: Bearer` value. |
| raw_input | That same metadata, JSON-encoded, **with every credential header stripped** first. |

So `tool_catalog` rows for this surface use method paths as tool names. An
uncatalogued method is not held by the delegation and denies.

## What the target receives

An allowed call is forwarded with the caller's metadata, less the three
entries that are addressed to Stratium: `authorization` (the token), `dpop`
(the proof) and `stratium-approval-id`. Everything else, a `cookie` or an API
key header included, reaches the target unchanged.

Set `STRATIUM_PEP_PROXY_FORWARD_CREDENTIALS=true` to forward those three too,
for a target that checks the Stratium token itself. The target then holds a
token it can present to the PDP, though not a proof for it.

A proxied call may stay open for `STRATIUM_PEP_PROXY_MAX_STREAM_DURATION`
(default `1h`). The proxy decides a call once, when it opens, so a long
stream is not looked at again; when the time is up the proxy ends it with
`DEADLINE_EXCEEDED`, and the call the caller opens next is decided afresh.
Lower it if a stream must not outlive a revocation by that long.

---

## What a denial looks like

A gRPC status — **not** either JSON shape the hook surfaces produce:

```
rpc error: code = PermissionDenied desc = tool "/orders.v1.Orders/Cancel" not in delegation approved_tools at depth 0
```

The PDP's reason is carried verbatim. An `EFFECT_ESCALATE` degrades to the same
`PermissionDenied` shape, with the pending approval's id attached.

---

## Limits — read these before deploying

**A stream is authorized once, at open.** One decision is made when the call
starts. A long-lived streaming RPC is not re-authorized per message, so a
revocation mid-stream does not close it. Short unary calls get the enforcement
you expect; streams get an admission check.

**Authorization cannot see message contents.** The decision is built from the
method and the metadata. Request bodies are opaque here — `Cancel(order_id: 7)`
and `Cancel(order_id: 9)` are the same decision. If which *object* is touched
matters, this surface cannot express it; the resource-labelled surfaces can.

**The evidence rule has nothing to scan.** Policies that inspect a tool's
arguments for evidence have nothing to work with on this surface.

**Escalation does not block.** Unlike `hook` and `mcp`, which hold a call open
while an approval is pending, `proxy` no longer blocks at all — an escalation
becomes a denial plus an approval id. Retry after the approval lands.

---

## See also

- [`extauthz.md`](extauthz.md) — the same idea for HTTP behind Envoy.
- [`../pep.md`](../pep.md) § "The `proxy` surface's limits" — each limit above
  with its full reasoning.
- [`../../example/proxy/`](../../example/proxy/) — this surface as a runnable program, including the direct-to-service call count that catches a forward-then-error leak.
