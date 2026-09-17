# widening — the loop the other five never closed

Every other directory in this suite puts Stratium in front of a tool call and asks
*does this go through?* [`containment`](../containment/README.md) asks the admin
plane a different question, in isolation: *does this change let an agent do
anything it could not do before?* Nothing before this program ever showed both
questions answered for the **same agent, in order**:

1. A tool call goes through `stratium-pep hook` → **DENIED** — the tool is not in
   the agent's allowlist.
2. An operator widens that agent's grant via `PUT /v1/agents/{id}`, adding the
   tool.
3. That write appends a **`containment`** audit row: `agent grant widened: <reason>`.
4. The identical tool call, on the **same** delegation minted before step 1, now →
   **ALLOWED**.
5. This program reads the containment row back through **`GET /v1/audit`**, then
   corroborates it against Postgres directly — the route and the table must agree.

## Running it

```bash
cd example
dc() { docker compose -f ../deploy/docker/docker-compose.yml "$@"; }
export EXAMPLE_WIDENING_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
export EXAMPLE_WIDENING_PDP_ADDR="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"
export EXAMPLE_WIDENING_PG_ADDR="localhost:$(dc port postgres 5432 | sed -E 's/.*://')"
go run ./widening
```

Needs the whole compose stack up (`docker compose ... up -d --wait`) and the real
`stratium-pep` binary built (`cd services && go build -o ../bin/stratium-pep
./cmd/stratium-pep`, or set `EXAMPLE_PEP_BIN`). `Precheck` reports exactly which of
those is missing, with the fix, before anything else runs.

Safe to re-run: the agent is found-by-name, not recreated, and this program resets
its `allowed_tools` back to `[Read]` at the top of every run before widening it
again — a previous run leaving the agent already widened does not stop the next
run from reproducing the denial. Every run mints a fresh delegation and appends
exactly one new `containment` row; step 5 always reads back the most recent one.

## What it proves

**The denial in step 1 is the AGENT leg, not the delegation leg.** This program
mints its one delegation approved for `[Read Write]` from the very first call —
wider than the agent's own starting allowlist (`[Read]`) — deliberately. The tool
call in step 1 fails because `authz.AgentLeg` reads the agent's live
`allowed_tools` on every decision (no caching layer; `internal/pdpgrpc/server.go`
calls `store.LoadAgent` fresh per `Decide`), and finds `Write` missing there — not
because the delegation itself is too narrow.

**Step 4 needs no new session, and that is not a given.** A delegation's own
`approved_tools` is fixed at mint time (`models.Delegation.HasTool`); the agent's
`allowed_tools` is live. Because this delegation already held `Write`, widening the
agent's own allowlist in step 2 removes the one leg that was failing, and the
*same* delegation id — asserted, not just narrated, in the program's own output —
answers differently on the very next call. Had the delegation instead been minted
narrowly, matching the agent's own starting allowlist, step 4 would need a
brand-new session: the delegation leg would keep refusing `Write` no matter how
wide the agent's own allowlist became. Which shape a real operator is holding is
not visible from the outside — this is the distinction worth knowing before
promising "it'll work as soon as I widen the grant."

**The containment row is written inside the write it describes, and is now
readable.** `internal/store/containment_audit.go`'s `recordWideningTx` appends
the row inside the *same transaction* as the `PUT` — it commits with the write
it describes or not at all. `example/containment` shows `POST /v1/containment`
answering the same `permset.Contains` question on demand, against two sets a
caller supplies; this program shows the identical computation running as a
*side effect* of an ordinary write.

**Why this program still opens Postgres.** It no longer has to: `GET /v1/audit`
arrived on 2026-09-16 and step 5 reads the row through it, as a **viewer** —
the lowest role that can, which is itself the point. The direct read stayed as
**corroboration**. An endpoint that returned a plausible row assembled from
anywhere would satisfy every assertion about actor, timestamp and reason; only
a second, independent read of the table can tell the difference, and the
program fails loudly if the two disagree. `example/proxy` makes the same move
with `grpc-target`'s own call counter, for the same reason.

This example predates the route, which is why it is written this way round.

## Traps a reader will hit

**A freshly-authored policy that is silently never evaluated.** Building this
example, the very first live run denied delegation creation outright —
*"none of the requested tools are held by this principal"* — even though the
policy this program had just created unconditionally permitted its own subject.
The cause: `example/agent.EnsurePolicy`, the helper this program and
`example/depth/hook` both call to register a scoped policy, POSTed a body that
never set `"enabled"`. `models.Policy.Enabled` has no server-side default, and
`internal/store`'s own `loadAllPoliciesQuery` — the read both the principal leg
and `CreateDelegation`'s own grant clamp use — filters `WHERE enabled = true`. The
policy existed, and no decision ever saw it. Fixed in `example/agent/setup.go`
(now sends `"enabled": true` explicitly) — a shared-helper bug, not anything
specific to this example, and it was silently breaking `depth/hook` too until this
was found.

**The actor recorded on the containment row is a Keycloak `sub`, not an email.**
`Operator.Subject` (`cmd/stratium-pap/role.go`) is the verified token's `sub`
claim — a UUID for `pap-editor`, not the username or email a reader might expect
from the other examples' own `subject` constants (which name the *delegation's*
principal, a different identity entirely).

**Connecting to Postgres directly means the `stratium` database, not
`postgres`.** `deploy/docker/docker-compose.yml`'s `postgres` service sets
`POSTGRES_DB: postgres`, but `deploy/docker/init-db.sql` creates a *separate*
`stratium` database and every table this suite touches lives there. This program
connects as the `postgres` superuser specifically because every tenant table
(`audit_chain` included) is `FORCE ROW LEVEL SECURITY`, scoped by a
`current_tenant()` session setting only `stratium-pap`'s own connection pool ever
sets — and Postgres exempts a superuser from RLS unconditionally regardless of
FORCE. That is exactly what an operator reaching for `psql` against this compose
stack would do; there is no lesser-privileged read path available.
