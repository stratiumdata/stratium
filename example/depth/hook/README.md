# example/depth/hook — one tool, two depths, two different answers

`example/hook` ships a configuration and a captured transcript, deliberately with no program of its
own (see that directory's README). This directory *is* a program, but it still never drives a live
model: it feeds the real `stratium-pep hook` binary the same stdin a harness like Claude Code would,
with fixed JSON, so the three claims below are deterministic rather than dependent on whether a
model feels like calling `Grep` twice.

## The three claims

1. **`Grep` is ALLOWED at depth 0.** The orchestrator's own root delegation holds it.
2. **The SAME `Grep` — same tool, same shape — is DENIED at depth 1**, and the reason names the
   depth: `tool "Grep" not in delegation approved_tools at depth 1`. This is the whole point: a
   denial for a tool the parent never held would just be `example/proxy` one level deeper. Only a
   real two-hop chain can show the *parent* holding what the *child* does not.
3. **A child asking for more than its parent granted is refused at creation**, before any hook ever
   runs — `store.CreateDelegation`'s own `models.ScopeNarrows` check — and the refusal names the
   dimension that failed: `child tool "Write" not in parent approved_tools`.

`Read` at depth 1 is probed too, alongside claim 2's `Grep`, to show the child isn't simply broken —
it still works for what it does hold.

## Running it

```bash
cd example
export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"
export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"
go run ./depth/hook
```

No Ollama, no LiteLLM, no `npx` — this surface probes directly, so none of the model-serving
prerequisites the other three runnable examples need apply here. `main.go`'s own `Precheck` checks
only what this program actually needs: the PDP, the PAP, and a built `stratium-pep` binary at
`../bin/stratium-pep` (override with `EXAMPLE_PEP_BIN`).

## Why this shares `pdp-pap`/`stratium-pap` with `example/mcp`

Adding a new tenant means a new PDP+PAP pair in `docker-compose.yml`, and this suite is not adding
docker-compose services for one more example — the stack is already at the service count it's meant
to stay at. `pdp-pap`/`stratium-pap` (`tenant-pap-e2e-integration`) is the one PDP+PAP pair in this
stack not already dedicated to a specific enforcement surface the way `pdp-proxy`/`pap-proxy` and
`pdp-extauthz`/`pap-extauthz` are, and it's exactly what a delegation-chain demo needs: full HTTP PAP
access, nothing surface-specific about it.

Sharing a tenant with `example/mcp` is safe because this program registers its own, narrowly scoped
policy — `permit(principal == User::"depth-hook@example.com", action, resource);` — rather than a
tenant-wide blanket permit like `example/proxy`'s or `example/extauthz`'s own setup. A blanket
`permit(principal, action, resource)` would widen what *every* principal in the shared tenant may be
granted, not just this example's own subject; scoping it to `depth-hook@example.com` means this
example's setup can never change what `example/mcp`'s own `agent-tester@example.com` may do, or vice
versa. It also registers its own two agents (`depth-hook-orchestrator`, `depth-hook-worker`) rather
than reusing `example/mcp`'s single agent — an agent row is `UNIQUE(tenant_id, name)`, so this is
idempotent across repeated runs exactly the way every other example's own agent setup already is.

## Why `agent.BuildChain`, not `stratium-pep session-start`

`session-start` creates roots only — it has no `ParentDelegationId` flag at all, because a root has
no parent to narrow. A child delegation only exists by calling the PDP's `CreateDelegation` RPC
directly with `ParentDelegationId` set, and there is no CLI subcommand for that. `example/agent/chain.go`'s
`BuildChain` calls that RPC directly for **both** hops — not `session-start` for the root and the RPC
only for the child — so one code path builds the whole chain and this program gets both delegations'
responses back from one call, rather than shelling out once and reading a session file back for the
second.

## Two session files, not one

`mcp`, `proxy` and `extauthz` all default to the same `.session.json` in `example/` and warn against
running two of them at once for exactly that reason (see `example/README.md`'s "One session file per
example"). This program needs **two** files live at once — one per depth — so it writes
`depth/hook/.session-parent.json` and `depth/hook/.session-child.json` instead, each named uniquely
to this program and gitignored like every other example's own session file.

## The TTL wrinkle `BuildChain` hides

`models.ScopeNarrows` checks expiry as one of its dimensions, alongside tier and tools. Requesting
the *identical* `ttl_seconds` for both the parent and the child does not produce identical absolute
expiries: `store.CreateDelegation` computes each delegation's `ExpiresAt` from `time.Now()` at the
moment *that* RPC runs, and the child's call unavoidably runs some (small) amount of time after the
parent's — so an identical requested duration always yields a strictly *later* absolute expiry for
the child, which a real PDP correctly refuses (`child expires_at exceeds parent`, hit while building
this example against the live stack). `BuildChain` requests a TTL 60 seconds shorter for the child
than for the parent to leave comfortable room for that gap; a consumer of `BuildChain` does not need
to think about this at all.

## What claim 3 is *not*

The widening attempt in `main.go` reuses the worker's own agent id and the already-built parent's
delegation id — it does not mint a third agent. It asks for the same tier as the parent
(`readOnlyTier`) but adds `"Write"` to the requested tools, so the refusal is unambiguously about the
**tool** dimension: the principal's own policy (the blanket permit above) would happily grant
`"Write"` at the principal level, so if this created successfully at all, the only thing that could
have stopped it is the parent-narrowing check this claim exists to prove.

## Traps this example ran into, so a reader doesn't have to

- **`Read` and `Grep` need no `tool_catalog` row.** Both are `READ_ONLY` in `BuiltinTier`'s own
  shipped defaults (`services/internal/authz/catalog.go`) — unlike `example/proxy`'s `Fetch`/`Purge`,
  which exist only in this tenant's own catalog, this example seeds none.
- **No classification caps are set on either agent**, deliberately: `classification.CheckCap` treats
  an empty cap map as unconditionally satisfied, so this example's two claims are purely about
  `approved_tools` and depth, never about a resource label fight it isn't trying to have.
- **A hit on `stratium-pep hook`'s own local decision cache is not a risk here.** The cache key
  includes the delegation id (`services/cmd/stratium-pep/local_cache.go`), and the parent and child
  hold two different ones — claim 1 and claim 2 can never be served from each other's cache entry
  even though both ask about the identical tool.
