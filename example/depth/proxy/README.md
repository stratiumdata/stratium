# example/depth/proxy — one agent, two depths, two different answers

A real transparent gRPC proxy (`stratium-pep proxy`, already running as `pep-proxy`), the identical
service `example/proxy` documents in full — read that directory's own README first for the proxy
surface itself, sender-constrained (DPoP) tokens, and the CallCount punchline; this file follows its
shape closely and does not re-explain what it explains. Nothing here drives a live model: every
probe is a fixed, direct gRPC call, deterministic the way `example/depth/hook`'s own hook probes
are, for the same underlying reason — nothing about this surface's own claim depends on whether
`llama3.2` feels like calling `purge`.

## The three claims

1. **`purge` is ALLOWED at depth 0.** The root delegation holds both `Fetch` and `Purge`.
2. **The SAME `purge` — same full method, same tier — is DENIED at depth 1**, and the reason names
   the depth: `tool "/stratium.target.v1.TargetService/Purge" not in delegation approved_tools at
   depth 1`. A denial for a method the parent never held would just be `example/proxy` one level
   deeper; only a real two-hop chain shows the *parent* holding what the *child* does not.
3. **A child asking for more than its parent granted is refused at creation**, before either probe
   below ever runs — `store.CreateDelegation`'s own `permset.ScopeNarrows` check — naming the
   dimension that failed: `child tool "/stratium.target.v1.TargetService/CallCount" not in parent
   approved_tools`.

`fetch` at depth 1 is probed too, alongside claim 2's `purge`, to show the child isn't simply broken
— it still works for what it does hold.

## THE ASYMMETRY — one agent narrowing its own authority, not an orchestrator and a worker

`example/depth/hook` and `example/depth/mcp` each mint a root delegation for one agent (an
"orchestrator") and a narrower child for a *second* agent (a "worker"). This example cannot do
that. `pep-proxy` (`docker-compose.yml`) is a running service configured with a **literal,
hardcoded** `STRATIUM_PEP_AGENT_ID` — read once at startup, never from anything a caller's own
request names (`cmd/stratium-pep/proxy.go`'s own package doc, "NO SESSION FILE"). Every
`DecideRequest` this surface ever sends the PDP carries that exact same agent id, for every caller,
always. There is no second identity for a "worker" delegation to belong to — minting one for any
other agent id would simply be a delegation `pep-proxy` can never resolve, proving nothing.

So this chain is **one agent narrowing its own authority**: `agent.BuildChain` is called with the
identical `04ef809a-849f-404a-9a5c-015b7f73a014` as both `parentAgentID` and `childAgentID`. It is
still a genuine depth-1 chain — the child's delegation still has `ParentDelegationId` set to the
parent's own id, and `store.CreateDelegation` still runs the identical `permset.ScopeNarrows` check
it would for a true orchestrator/worker pair, including the identical expiry-margin behavior
`example/depth/hook`'s own README documents (`agent.BuildChain`'s `childTTLMargin`) — it just proves
"the same principal, one step later, with less" rather than "a different principal, downstream,
with less." Both are real depth; this is the shape this particular surface's own fixed
configuration allows.

## Reusing `example/proxy`'s own env var names, not a new `EXAMPLE_DEPTH_PROXY_*` family

`example/depth/hook` and `example/depth/mcp` each introduced their own `EXAMPLE_DEPTH_*` names
because they point at a tenant (`tenant-pap-e2e-integration`) that no single flagship example
already owns end to end. This directory has no such gap to fill: it dials the **exact same**
`pdp-proxy`, `pap-proxy`, `pep-proxy`, and `grpc-target` that `example/proxy` already names
`EXAMPLE_PROXY_PDP_ADDR`, `EXAMPLE_PROXY_PAP_ADDR`, `EXAMPLE_PEP_PROXY_ADDR`, and
`EXAMPLE_GRPC_TARGET_ADDR` for — there is only one of each running, so reusing those four names
(plus the suite-wide `EXAMPLE_KC_ADDR`) says exactly what is true: this is the identical
infrastructure, not a parallel copy of it. A shell already exporting these for `example/proxy` needs
nothing new to run this program too.

## Running it

**One-time setup**, before the first run — identical to `example/proxy`'s own, because it is the
same fixture:

```bash
cd example
dc() { docker compose -f ../deploy/docker/docker-compose.yml "$@"; }
dc up -d pap-proxy --wait
dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
  psql -h 127.0.0.1 -U stratium_migrate -d stratium -q \
  -f /dev/stdin < ../deploy/seed/proxy-example-agent.sql
```

Then, every run:

```bash
export EXAMPLE_PROXY_PDP_ADDR="localhost:$(dc port pdp-proxy 50051 | sed -E 's/.*://')"
export EXAMPLE_PEP_PROXY_ADDR="localhost:$(dc port pep-proxy 9292 | sed -E 's/.*://')"
export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(dc port grpc-target 50051 | sed -E 's/.*://')"
export EXAMPLE_PROXY_PAP_ADDR="localhost:$(dc port pap-proxy 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
go run ./depth/proxy
```

No Ollama, no LiteLLM: `main.go`'s own `Precheck` checks only what this program actually needs —
the PDP, `pep-proxy`, `grpc-target`, `pap-proxy`, Keycloak, and the seeded agent row — and reports
any of them missing by name, with the exact fix, never as a policy denial.

## No session file, DPoP-bound tokens, minted once per hop

Exactly like `example/proxy`: an ordinary bearer token — the only kind `CreateDelegation` itself can
mint — is refused outright by this surface's own K5 proof-of-possession gate. `main.go` calls
`agent.MintBoundToken` **twice**, once for the parent's own delegation id and once for the child's,
each generating its own P-256 keypair, and every probe below attaches a fresh RFC 9449 DPoP proof
built from the matching hop's own key (`dpopProof`, duplicated from `example/proxy`'s own
`(*proxyTransport).proof`, parameterized over the key instead of fixed to one, since this program
needs the identical construction twice over).

## `CallCount`, dialled directly at `grpc-target`, is the extra evidence

Same reasoning as `example/proxy`'s own README states in full: *a proxy that forwards a denied call
and then errors has already leaked it; a caller reading only its own response cannot tell that apart
from a proper refusal.* This program reads `grpc-target`'s own call counter on a **separate
connection straight to `grpc-target`**, bypassing `pep-proxy` entirely, before and after each of the
three probes below, and asserts the delta explicitly:

| Probe | Expected gRPC-level result | Expected `CallCount` delta |
|---|---|---|
| depth 0 `purge` (parent) | ALLOW | **+1** |
| depth 1 `purge` (child) | DENY | **+0** |
| depth 1 `fetch` (child) | ALLOW | **+1** |

The middle row is the one that matters: if `pep-proxy` ever forwarded a call it should have denied
— the exact "forward, then error" leak a client alone could never detect — `grpc-target`'s own
counter would move even though this program's own view of the denial looked correct, and the
assertion would catch it. A mismatch here is treated exactly like a mismatched `Expectation`: it
sets a non-zero exit code, printed alongside `Report.Print`'s own summary rather than silently.

## Denial vs. transport error

Same rule as every other example in this suite: a gRPC status of `PermissionDenied` is a
**decision** — `agent.Result{Allowed:false, Reason: st.Message()}`. Anything else (`Unavailable`, a
dead connection, a malformed response) is this example being broken, not policy answering, and
returns a Go `error` that aborts the run rather than being recorded as either an `ALLOW` or a `DENY`
it never actually decided.

## Verifying it

```bash
cd example && go vet ./... && go build ./...
go test ./agent/...
```
