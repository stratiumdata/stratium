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

**One `session-start` issues one delegation, and the same token is carried
three different ways**: as a session file for `mcp`, as gRPC metadata for
`proxy`, as an HTTP header for `extauthz`. The delegation — what's held, at
what tier, under what classification cap — is a single decision made once, at
session start; everything after that is just how the resulting token reaches
the enforcement point for that particular transport.

`proxy` and `extauthz` go one step further than carrying the token as-is:
both require a **sender-constrained (DPoP)** token — an ordinary bearer token
is refused even for an action the delegation would otherwise permit (RFC 9449,
spec §4.7.2 K5) — so those two examples mint a second, bound token from the
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
