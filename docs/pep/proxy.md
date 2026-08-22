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

The agent must attach its delegation token as gRPC metadata:

```
authorization: Bearer <the session file's token>
```

---

## How the decision is built

| Decision field | Comes from |
|---|---|
| tool | The **full gRPC method**, e.g. `/orders.v1.Orders/Cancel`. Catalogue it per tenant exactly like any other tool name. |
| token | gRPC metadata's `authorization: Bearer` value. |
| raw_input | That same metadata, JSON-encoded, **with every credential header stripped** first. |

So `tool_catalog` rows for this surface use method paths as tool names. An
uncatalogued method is not held by the delegation and denies.

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
