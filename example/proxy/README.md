# example/proxy — the service that never heard the denied call

A real local model (`llama3.2` via Ollama, through LiteLLM) decides its own tool
calls against a real gRPC service, `grpc-target`. Its client never dials
`grpc-target` directly for those calls: it dials `stratium-pep proxy`, a
transparent gRPC proxy already running as its own docker-compose service
(`pep-proxy`), which authorizes each RPC by its **full method path** —
`/stratium.target.v1.TargetService/Fetch` and
`/stratium.target.v1.TargetService/Purge` — before forwarding it, or refuses to
forward it at all.

The model sees two friendly tool names, `fetch` and `purge`. `main.go`'s
`proxyTransport` is what maps each to its real method; nothing about that
mapping is visible to the model, the same friendly-name/wire-identity split
`example/mcp` already draws for its own surface.

## Running it

```bash
cd example
dc() { docker compose -f ../deploy/docker/docker-compose.yml "$@"; }
export EXAMPLE_PDP_ADDR="localhost:$(dc port pdp-proxy 50051 | sed -E 's/.*://')"
export EXAMPLE_PEP_PROXY_ADDR="localhost:$(dc port pep-proxy 9292 | sed -E 's/.*://')"
export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(dc port grpc-target 50051 | sed -E 's/.*://')"
export EXAMPLE_POSTGRES_ADDR="localhost:$(dc port postgres 5432 | sed -E 's/.*://')"
export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"
go run ./proxy
```

`main.go` then, in order: prechecks Ollama/LiteLLM/the PDP/postgres; seeds its
own tenant (`tenant-proxy-integration`, pdp-proxy's own `STRATIUM_TENANT_ID`)
with one agent, both tool_catalog rows, and one blanket-permit cedar policy —
see **Seeding a tenant with no PAP**, below, for why that is direct SQL rather
than an HTTP call; runs `stratium-pep session-start` requesting **only**
Fetch's full method path; mints a second, DPoP-bound token (see **Sender-
constrained tokens**, below); and hands the whole thing to `agent.Run` with a
task that calls `fetch` then `purge`, expecting Fetch **ALLOWED** and Purge
**DENIED** for `not in delegation approved_tools` — both methods are cataloged
at the identical action tier, so a tier ceiling can never be the reason; only
the requested-tools list can.

## Sender-constrained tokens (K5)

`cmd/stratium-pep/proxy.go` refuses to forward **any** call whose token is not
bound to a caller-held key and proven with a fresh RFC 9449 DPoP proof (spec
§4.7.2 K5) — an ordinary bearer token, the only kind `session-start`'s
`CreateDelegation` call can produce, is refused even for an action the
delegation would otherwise permit. So this program does one thing past what
`session-start` gives it: it generates its own P-256 keypair, calls the PDP's
`IssueToken` RPC directly with that key's public half (there is no
`session-start` flag for this — `STRATIUM_PEP_REQUESTED_TOOLS` and its
siblings are its entire env var contract), and attaches a fresh proof to every
call. `session-start` still does exactly what it always does — create the
delegation, cache it to `.session.json` — this program just reads the
delegation id back out of that file and mints a second, bound token from it,
rather than sending the file's own bearer token over the wire.

## Seeding a tenant with no PAP

`pdp-proxy` is fixed to tenant `tenant-proxy-integration` (docker-compose.yml),
and unlike `stratium-pap`'s own tenant, no PAP instance in this compose file is
wired to serve it. `seedTenant` in `main.go` writes the one agent row, the two
`tool_catalog` rows, and one blanket-permit policy directly, with plain SQL
under Postgres row-level security's own per-transaction tenant switch — the
identical shape and the identical target tenant
`services/internal/store/proxy_integration_test.go` already uses to test this
same surface. Every insert is `ON CONFLICT DO NOTHING`, so re-running this
program is safe.

## THE PUNCHLINE: why CallCount is dialled directly

`grpctarget.TargetService` has a third method, `CallCount`, and this program
dials it on a **separate connection straight to `grpc-target`**, bypassing
`pep-proxy` entirely, before and after the run:

> A proxy that forwards and THEN errors has already leaked the request. A
> caller reading only its own response cannot tell that apart from a proper
> refusal — both look like an error. Asking the service what it actually
> received is the only check that distinguishes them, and routing that
> question through the proxy would make the check depend on the component
> under test.

The delta between the two reads is **1** — the one Fetch that was ever
actually pending a policy question. Purge is denied at the proxy every time
it is tried, and the direct call count proves it, rather than merely trusting
`pep-proxy`'s own `PermissionDenied` response.

## Denial vs. transport error

A gRPC status of `PermissionDenied` is a **decision** — the PDP, or this
surface's own K5 gate, looked at the exact call and said no —
`agent.Result{Allowed:false, Reason: st.Message()}`. Anything else
(`Unavailable`, a dead connection, a malformed response) is this example being
broken, not policy answering, and is returned as a Go `error` so `agent.Run`
aborts instead of recording a transport failure as a decision — which would
let a down stack report "enforcement working."

## A model that will not stop calling `fetch`

`llama3.2` is unreliable at recognizing that a step is done: run live, it
often repeats an already-**ALLOWED** `fetch` call across several turns instead
of moving on to `purge`, before `agent.go`'s own `maxTurns` cap ends the loop.
Every one of those repeats is still correctly authorized and still shown in
the transcript (`agent.Run`'s own `ALLOW fetch ...` line prints once per
attempt) — but re-forwarding an already-answered idempotent read to
`grpc-target` would inflate its own call counter with calls that prove nothing
new and corrupt the one number this example's whole punchline rests on.
`proxyTransport` memoizes a successful `fetch` result by its arguments within
one run — never a denial, which must always be asked fresh — so the call
count stays a true count of how many requests were ever actually pending a
policy decision, regardless of how many times a weak local model asks for the
same answer twice.

## Tenant-wide catch-all label rule

An earlier example in this suite registered a tenant-wide catch-all resource
label rule (prefix `""` → `nato UNCLASSIFIED`) on **its own** tenant. It has no
effect here: this program owns a different tenant
(`tenant-proxy-integration`) end to end, and this surface's own denial is
tool-not-held on a gRPC method, never a missing classification label.
