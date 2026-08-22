# example

Four things, one story: a real local model decides its own tool calls, and
Stratium sits in front of the tool call — not the model — deciding whether it
goes through. Three directories are runnable programs; the fourth is a
configuration, on purpose (see below).

`stratium/example` is its own Go module (tied into the repo via the root
`go.work`) so it can stay dependency-light and never bleeds into `services`'
own build.

## The four directories

| Directory | What it is | What it proves |
|---|---|---|
| [`hook`](hook/README.md) | Configuration + a captured transcript, **no program** | A `PreToolUse` hook in front of **Claude Code itself** — the harness a hand-written client would only ever approximate, so this directory ships the real contract and a real denial instead of a fake client. |
| [`mcp`](mcp/README.md) | Runnable: agent ↔ `stratium-pep mcp` ↔ real `@modelcontextprotocol/server-filesystem` | `stratium-pep mcp` is a transparent MCP proxy: swap it out for the real server directly and the agent's own code doesn't change, only the enforcement outcome does. |
| [`proxy`](proxy/README.md) | Runnable: agent ↔ `stratium-pep proxy` ↔ real `grpc-target` service | A gRPC proxy authorizing calls by full method path, with sender-constrained (DPoP) tokens and a direct side-channel call count that catches a "forward, then error" leak a client alone could never detect. |
| [`extauthz`](extauthz/README.md) | Runnable: agent → Envoy `ext_authz` → `stratium-pep extauthz` → LiteLLM | Policing the *tools an agent calls*, not the agent's own reasoning: an `ask_model` tool call is checked before Envoy ever routes it onward, using the request path itself as the tool identity. |

Each runnable example uses the identical local model (`llama3.2` via Ollama,
through LiteLLM) and the identical shared agent loop in `agent/` — `Transport`
(how a call is placed), `Report` (ALLOW/DENY expectations vs. what actually
happened), and `Precheck` (fail fast on a missing prerequisite, never mistaken
for a policy denial). Only the transport — the wire the tool call actually
travels — differs per directory.

## The one sentence that ties it together

**Each surface issues its OWN delegation, through the identical `session-start`,
and what differs is only how the resulting token is carried**: as a session
file for `mcp`, as gRPC metadata for `proxy`, as an HTTP header for `extauthz`.
That is three separate `session-start` runs, not one shared across the suite —
`mcp` mints in tenant `tenant-pap-e2e-integration` (subject
`agent-tester@example.com`); `proxy` mints in `tenant-proxy-integration` for
the fixed agent `04ef809a-849f-404a-9a5c-015b7f73a014`; `extauthz` mints in
`tenant-extauthz-integration` for the fixed agent
`72d38ebe-2e5c-4918-9e73-b0de3607fbfa`. The portability lesson survives that
correction intact: the delegation — what's held, at what tier, under what
classification cap — is still a single decision made once per session, by the
same `session-start` mechanism every time; only the pipe the resulting token
travels down changes per transport.

Why three tenants rather than one: each PEP process is pinned to a single
tenant at startup (its own PDP dials exactly one tenant, never a request-named
one), and `pep-proxy` and `pep-extauthz` are each configured with their own
fixed `STRATIUM_PEP_AGENT_ID` — a literal in `docker-compose.yml`, not
something a caller's session can name. `mcp` is the one surface free to mint
its own agent row and pick its own tenant, because `hook` and `mcp` both read
identity from a session file this program controls, while `proxy` and
`extauthz` read it from the caller's own token on the wire and so must agree,
in advance, with whatever fixed identity their PEP process was started with.

`proxy` and `extauthz` go one step further than carrying the token as-is:
both require a **sender-constrained (DPoP)** token — an ordinary bearer token
is refused even for an action the delegation would otherwise permit (RFC 9449,
spec §4.7.2 K5) — so those two examples mint a SECOND, bound token from the
delegation `session-start` already created, rather than sending the session
file's own bearer token over the wire. `mcp` has no such requirement and uses
the session file's token directly. See each example's own README (`proxy`'s
"Sender-constrained tokens" section, in particular) for why.

## Shared preconditions

All three runnable examples need:

- **Ollama running locally with `llama3.2` pulled** — `ollama list` should
  show it; `ollama pull llama3.2` if not. Each example's `Precheck` reports
  this by name rather than surfacing it as a Stratium-shaped denial.
- **The Docker Compose stack up**: `docker compose -f
  deploy/docker/docker-compose.yml up -d --wait`. Every example resolves its
  own service ports from the running stack (they're ephemeral) rather than
  assuming fixed ones — see each README's own `export EXAMPLE_*_ADDR` block.
  The PDP and PAP address variables are named per example
  (`EXAMPLE_MCP_PDP_ADDR`/`EXAMPLE_MCP_PAP_ADDR`,
  `EXAMPLE_PROXY_PDP_ADDR`/`EXAMPLE_PROXY_PAP_ADDR`,
  `EXAMPLE_EXTAUTHZ_PDP_ADDR`/`EXAMPLE_EXTAUTHZ_PAP_ADDR`) rather than a single
  shared `EXAMPLE_PDP_ADDR`/`EXAMPLE_PAP_ADDR` pair — each example's PDP and
  PAP are a different backing tenant, and one shell exporting the shared name
  for one example, then running another, would silently point the second
  example at the first one's tenant instead of its own. `EXAMPLE_KC_ADDR` and
  `EXAMPLE_LITELLM_ADDR` stay shared: Keycloak and LiteLLM are the same
  instance for all three.
- **Node.js**, for `mcp` only — it launches the real
  `@modelcontextprotocol/server-filesystem` via `npx`.
- **Go 1.25+** to build and run any of the three programs:
  `cd example && go build ./... && go vet ./...`.

`example/hook` needs none of this to *read* — it ships a configuration and an
already-captured transcript — but reproducing that capture yourself needs the
stack, a real Claude Code install, and the throwaway-directory approach its
own README describes.

## Why `hook` alone has no program

The other three directories exist because the harness on the other side of
the enforcement point — an MCP client loop, a gRPC client, an HTTP client — is
something this suite invents for the demo, so it's reasonable for this suite
to also write the client. `hook`'s harness is **Claude Code itself**, a
product that already exists with its own hook contract. Writing a
hand-rolled program that fed `stratium-pep hook` synthetic JSON on stdin would
demonstrate the shape of that contract, not Claude Code actually using it —
and it would silently drift the moment Claude Code's real hook payload
changed. So `example/hook` ships the configuration, an explanation, and a
**real, captured transcript** of Claude Code itself hitting the deny path,
instead of a program pretending to be Claude Code. See
[`hook/README.md`](hook/README.md) for the full reasoning and the capture
itself in [`hook/transcript.md`](hook/transcript.md).

## One session file per example — do not run two at once

`mcp`, `proxy` and `extauthz` all default `sessionFile` to the identical
relative name, `.session.json`, in the CWD `go run` is launched from
(`example/`). Running two of them concurrently from the same directory means
the second one's `session-start` overwrites the first one's session file
while it may still be in use, and whichever program reads it next gets the
wrong delegation. Run the three examples one at a time from `example/`, not
in parallel; nothing currently gives each its own filename.

## Tenant-wide catch-all label rules do not carry over

If you add a fourth example: a tenant-wide catch-all resource-label rule
(prefix `""` → some default classification) registered by one example has no
effect on another's. Each of `mcp`, `proxy` and `extauthz` owns its own
tenant end to end, so a rule seeded into one tenant is invisible from the
others — a resource-label rule, like every other piece of setup here, is
per-tenant, and a new example needs its own if its own surface's denial is
meant to be a classification-cap refusal rather than tool-not-held.

## Seeding, re-running, and tearing down

**The manual `psql` seed step.** `proxy` and `extauthz` each need one agent
row seeded once with `psql` before their first run —
`deploy/seed/proxy-example-agent.sql` and
`deploy/seed/extauthz-example-agent.sql` respectively — because the fixed
agent id their PEP process is configured with cannot be created through the
PAP's own `POST /v1/agents` (see each README's own "The one row that lives in
`deploy/seed/`" section for why). `mcp` needs no such step; it registers its
own agent row through the PAP's HTTP API at every run.

**Re-running the suite is safe.** Every one of the three programs is
idempotent: resource-label rules, tool-catalog rows and policies are all
POSTed with `201`-or-`409`-means-success handling, agent rows are
find-by-name (or a fixed, pre-seeded id) rather than created fresh, and the
`psql` seed files use `INSERT ... ON CONFLICT DO NOTHING`. Nothing errors on
a second run. The one thing that does accumulate is delegations: each run
mints a fresh one with a one-hour TTL, so repeated runs leave behind
short-lived rows that expire on their own rather than being cleaned up.

**What the suite writes to the shared tenants.** `mcp` writes to
`tenant-pap-e2e-integration`: two resource-label rules (a catch-all at
`UNCLASSIFIED` and `secret-` at `SECRET`), its own agent row, a
classification cap on that agent, and one delegation per run. `proxy` writes
to `tenant-proxy-integration`: two tool-catalog rows (Fetch, Purge), one
blanket-permit policy, and one delegation per run — never the agent row
itself, which is the `psql`-seeded fixture. `extauthz` writes to
`tenant-extauthz-integration`: one tool-catalog row per model name, one
blanket-permit policy, and one delegation per run — likewise never its own
agent row.

**`deploy/stratium down` takes LiteLLM with it.** It tears down the entire
compose project, `-v` and all — LiteLLM along with every other service, not
just the PEP/PDP/PAP pieces this suite talks to directly. Bringing the stack
back up re-runs every seed step compose itself owns; the `psql` fixtures
above are not part of that and still need re-applying once, the same as on a
brand-new stack.
