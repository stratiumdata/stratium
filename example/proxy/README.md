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
dc up -d pap-proxy --wait   # one-time: brings up this tenant's control plane, disturbs nothing else
export EXAMPLE_PDP_ADDR="localhost:$(dc port pdp-proxy 50051 | sed -E 's/.*://')"
export EXAMPLE_PEP_PROXY_ADDR="localhost:$(dc port pep-proxy 9292 | sed -E 's/.*://')"
export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(dc port grpc-target 50051 | sed -E 's/.*://')"
export EXAMPLE_PAP_ADDR="localhost:$(dc port pap-proxy 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
export EXAMPLE_POSTGRES_ADDR="localhost:$(dc port postgres 5432 | sed -E 's/.*://')"
export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"
go run ./proxy
```

`main.go` then, in order: prechecks Ollama/LiteLLM/the PDP/pap-proxy/postgres;
seeds the tool catalog and a blanket-permit policy through **pap-proxy's own
HTTP API** (see **A control plane for this tenant**, below); ensures the one
agent row that API cannot create (see **The one row SQL still owns**, below);
runs `stratium-pep session-start` requesting **only** Fetch's full method
path; mints a second, DPoP-bound token (see **Sender-constrained tokens**,
below); and hands the whole thing to `agent.Run` with a task that calls
`fetch` then `purge`, expecting Fetch **ALLOWED** and Purge **DENIED** for
`not in delegation approved_tools` — both methods are cataloged at the
identical action tier, so a tier ceiling can never be the reason; only the
requested-tools list can.

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

## A control plane for this tenant

`pdp-proxy` is fixed to tenant `tenant-proxy-integration` (docker-compose.yml).
Until this fix round, nothing served it over HTTP — `stratium-pap` serves
`tenant-pap-e2e-integration` and `pap-extauthz` serves
`tenant-extauthz-integration`, and that was the whole list. `pap-proxy` closes
that gap: a second PAP, modelled directly on `pap-extauthz`, bound to
`tenant-proxy-integration`. `setUpCatalogAndPolicy` in `main.go` seeds both
`tool_catalog` rows and one blanket-permit policy through its real HTTP API —
`POST /v1/tool-catalog`, `POST /v1/policies` — the same idempotent-POST
convention (`example/mcp/main.go`'s own `setUpPolicy`) where a `201` or a
`409` (already exists) both count as success.

## The one row SQL still owns

`pep-proxy` (docker-compose.yml) is configured with a literal
`STRATIUM_PEP_AGENT_ID`, read from its own startup config and never from
anything a caller's session names — so the only agent row its principal leg
will ever resolve is the one whose `id` matches that exact literal.
`POST /v1/agents` cannot produce that row: `store.CreateAgent`'s own doc
comment states plainly that `id` is ignored on input, and the row's id always
comes from the table's own `uuid_generate_v4()` default. `ensureAgentRow` is
one idempotent `INSERT ... ON CONFLICT DO NOTHING` with that one pre-known id
— the identical literal `services/internal/store/proxy_integration_test.go`'s
own `proxyAgentID` hardcodes, since both this example and that test suite
must agree with docker-compose.yml's `pep-proxy` and neither may invent a
different value. This is the one write in this program that cannot move to
`pap-proxy`, and it is a property of the PAP's own admin-API design (a
caller-chosen primary key is exactly the kind of write it should refuse), not
a shortcut.

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

`proxyTransport` also counts its own `forwarded` calls — every time IT saw a
call complete successfully (no error, genuinely `Allowed`). The assertion is
`delta == forwarded`, not a fixed number: every response the client watched
succeed is one only `grpc-target` itself could have produced, so the two must
agree exactly, however many times the model asks. `delta > forwarded` would
mean something reached the target the client was never told about — a
forwarded-then-errored call, THE PUNCHLINE's own failure mode; `delta <
forwarded` would mean the client saw successes for calls the target never
counted, which is impossible unless something else is badly wrong. Purge is
denied at the proxy every time it is tried and never adds to either side, and
the direct call count proves it, rather than merely trusting `pep-proxy`'s own
`PermissionDenied` response.

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
Nothing here suppresses that — every repeat is genuinely re-authorized and
genuinely re-forwarded, exactly as a real caller's repeat would be, and every
`ALLOW fetch` line in the transcript names a call that really happened. A
client-side cache that answered "allowed" without asking would be the exact
anti-pattern a PEP exists to eliminate — it would survive a revocation, an
epoch bump, or a TTL expiry that a real re-ask would not. So `forwarded`
(above) simply grows with every genuine repeat, and the `delta == forwarded`
assertion holds regardless of how chatty the model gets: a run that asks for
`fetch` five times shows five `ALLOW fetch` lines, a call-count delta of 5,
and `forwarded` of 5 — still exactly equal, still exit 0.

## Tenant-wide catch-all label rule

An earlier example in this suite registered a tenant-wide catch-all resource
label rule (prefix `""` → `nato UNCLASSIFIED`) on **its own** tenant. It has no
effect here: this program owns a different tenant
(`tenant-proxy-integration`) end to end, and this surface's own denial is
tool-not-held on a gRPC method, never a missing classification label.
