# Design — runnable examples for the PEP surfaces

**Date:** 2026-08-22
**Status:** approved, not implemented

---

## The problem

`docs/pep/` now documents all five PEP surfaces with worked configuration, but a
reader cannot *run* any of them. The two surfaces that most need showing are the
two with no client anyone has written: `mcp`, where the point is that an agent
speaks plain MCP and never learns Stratium exists, and `proxy`, where the point
is that a service the agent thought it was calling directly never receives the
denied request.

This design adds `example/`, four directories, three of them runnable, sharing
one agent that reasons with a real local model.

## What already exists, and is therefore not built here

Almost all of it. These are compose services today:

| Service | Role here |
|---|---|
| `envoy` (`:10000`) + `pep-extauthz` | the extauthz path, already wired |
| `pep-proxy` (`:9292`) | the proxy path, already wired |
| `grpc-target` (`:50051`) | a real gRPC service, `proto/target/v1/target.proto` |
| `echo-upstream` | trivial HTTP upstream, superseded here by LiteLLM |
| `pdp-*` | a PDP per surface |

`services/internal/grpctarget` holds generated client stubs.
`deploy/seed/tool-catalog-mcp-filesystem.sql` already catalogues
`@modelcontextprotocol/server-filesystem`'s tools.

**Only one new service is required: `litellm`.**

## Decisions

| # | Question | Decision |
|---|---|---|
| 1 | What is the agent? | A real agent reasoning through **Ollama via LiteLLM**, not a scripted client. |
| 2 | Where does LiteLLM live? | A compose service, **fronted by Envoy + `extauthz`** — which model an agent may call becomes a policy decision. |
| 3 | What does "worked" mean? | Assert on **PEP decisions only**; narrate the model. No tool call is `INCONCLUSIVE`, not failure. |
| 4 | What is in `example/hook/`? | **Config only** — `settings.json`, README, a real transcript. No custom agent. |
| 5 | How is the agent shared? | A **package plus a thin `main.go` per example**, so `go run ./example/mcp` works. |
| 6 | How is the delegation carried? | **One `session-start`, one token, three carriers.** |

Decision 3 is the one that keeps the suite honest. The model is a
non-deterministic component in a demonstration about determinism, so the
assertion has to be on the part that is deterministic: what the PEP decided.

Decision 6 exists because a delegation being portable across enforcement points
*is* the lesson. Three separate delegations would hide it.

## Layout

```
example/
  README.md            which example shows what, and the preconditions
  agent/
    agent.go           the loop: task -> LiteLLM -> tool calls -> Report
    transport.go       type Transport interface
    report.go          the tally and the exit code
    precheck.go        named precondition failures with their fixes
    agent_test.go      the loop and the tally, against a fake transport
  mcp/main.go          Transport: stdio JSON-RPC through `stratium-pep mcp`
  proxy/main.go        Transport: gRPC client -> `stratium-pep proxy`
  extauthz/main.go     Transport: HTTP -> Envoy -> LiteLLM
  hook/
    README.md          how Claude Code is wired, and what a denial looks like
    settings.json      the two-hook block
    transcript.md      a real denied session, captured
```

## The shared agent

```go
package agent

type ToolSpec struct {
    Name        string
    Description string
    Schema      map[string]any   // JSON Schema, sent to the model
}

type ToolCall struct {
    Name string
    Args map[string]any
}

type Result struct {
    Allowed bool
    Reason  string   // the PDP's own words when denied
    Output  string   // what the tool returned when allowed
}

type Transport interface {
    Tools() []ToolSpec
    Call(context.Context, ToolCall) (Result, error)
}

type Expectation struct {
    ToolPrefix string   // matches a call by name plus a distinguishing argument
    Want       Outcome  // Allow | Deny
}

func Run(ctx context.Context, t Transport, task string, want []Expectation) Report
```

`Run` owns the loop and nothing else: send the task and `t.Tools()` to LiteLLM,
receive tool calls, hand each to `t.Call`, feed the result back as a tool
message, repeat until the model stops or a turn limit is reached. It never
learns which surface it is on — that is the entire reason the same agent can
demonstrate three.

`Report` tallies **enforcement only**: an expectation is satisfied when a call
matching it was allowed or denied as predicted. It exits non-zero on a mismatch
in either direction — an allowed call refused, or a denied call that went
through. A turn in which the model called no tool increments `Inconclusive`,
prints, and does not fail the run.

The failure text names both halves, because the two mean opposite things:

```
enforcement: 1/2 as expected                                     exit 1
  MISMATCH  purge /tmp/example-data  expected DENY, was ALLOWED
```

## The three transports

### `example/mcp/` — the agent never learns Stratium exists

`main.go` launches `stratium-pep mcp` as a child process:

```
STRATIUM_PEP_MCP_UPSTREAM_COMMAND=npx
STRATIUM_PEP_MCP_UPSTREAM_ARGS=-y @modelcontextprotocol/server-filesystem /tmp/example-data
```

plus the eight decision variables. `Tools()` issues a real `tools/list` and
returns whatever the upstream advertises. `Call()` issues a real `tools/call`.

**The demonstration is what is absent.** The agent holds no Stratium types, no
PEP import, no awareness of a policy layer. Point the same code at
`npx @modelcontextprotocol/server-filesystem` directly and it behaves
identically, minus the refusals. That substitutability is the integration story,
and the README says to try it.

Plan: read `/tmp/example-data/notes.txt` — allowed. Read
`/tmp/example-data/secret-x/plans.txt` — denied on classification, because
`up` already labels `/tmp/secret-` at `nato SECRET`; the example registers
`/tmp/example-data/secret-` the same way.

### `example/proxy/` — the service never heard the request

A `TargetService` client from `services/internal/grpctarget`, dialled at
`pep-proxy` rather than `grpc-target`. Two tools offered to the model: `fetch`
and `purge`.

`Fetch` is allowed. `Purge` is destructive and is not in the delegation, so it
denies with a gRPC `PermissionDenied` carrying the PDP's reason.

Then the example calls `CallCount` and prints it. That RPC exists in the proto
expressly *"so a proof that a denied call never reached this service can be
made"*, and it turns a refusal into evidence:

```
  ALLOW  fetch                      -> "ok"
  DENY   purge                      tool "/stratium.target.v1.TargetService/Purge" not in
                                    delegation approved_tools at depth 0

  grpc-target saw: Fetch=1  Purge=0        <- the denial never arrived
```

**`CallCount` is dialled directly at `grpc-target`, deliberately bypassing the
proxy.** Being a side channel is the entire reason that RPC exists — its own
comment says so: *"a proof that a denied call never reached this service can
check this service's own state rather than trusting the proxy's own response."*

The reasoning is worth repeating in the example's README, because it is the
subtlest thing in this suite. **A proxy that forwards and then errors has
already leaked the request.** A caller that only reads its own response cannot
tell that case apart from a proper refusal — both look like an error. Asking the
service what it actually received is the only check that distinguishes them, and
routing that question back through the proxy would make it depend on the
component under test.

### `example/extauthz/` — the agent's own cognition, policed

The tool offered to the model is `ask_model(model, prompt)`, which issues an
HTTP request to Envoy, which calls `extauthz`, which asks the PDP, and only then
reaches LiteLLM.

Plan: `ask_model("llama3.2", …)` — allowed. `ask_model("gpt-4o", …)` — denied,
because the delegation does not hold that tool.

**The agent's own reasoning traffic goes direct to LiteLLM, bypassing Envoy.**
Only the `ask_model` tool takes the policed path. Route both through Envoy and
the example deadlocks the instant the deny fires: the agent needs a model call
in order to narrate that its model call was refused. Keeping the reasoning
channel unpoliced is what lets it react to its own governance — and it matches a
real deployment, where you police an agent's outbound model access rather than
the loop that *is* the agent.

## LiteLLM and Envoy

One compose service:

```yaml
litellm:
  image: ghcr.io/berriai/litellm:main-latest
  command: ["--config", "/etc/litellm/config.yaml", "--port", "4000"]
  volumes: ["./litellm/config.yaml:/etc/litellm/config.yaml:ro"]
  extra_hosts: ["host.docker.internal:host-gateway"]
  ports: ["4000"]
```

`deploy/docker/litellm/config.yaml` declares two model names:

- `llama3.2` → `ollama/llama3.2` at `http://host.docker.internal:11434`
- `gpt-4o` → declared, deliberately **unreachable**

`gpt-4o` is unreachable on purpose. Policy must refuse it before reachability is
ever consulted; if the example only worked because the upstream was missing, it
would prove nothing. The denial must carry a PDP reason, not a connection error,
and the README says to check which one you got.

Envoy gains a route to `litellm:4000` behind the existing `ext_authz` filter.
`failure_mode_allow` stays unset — the default is deny-on-error and this design
depends on it.

Two catalog rows are seeded, one per model name, so each is a nameable tool the
delegation either holds or does not.

## Credentials

`session-start` runs once into `example/.session.json` (gitignored). The token is
read out of it and attached three ways:

| Surface | Carrier |
|---|---|
| `mcp` | the session file itself, via `STRATIUM_PEP_SESSION_FILE` |
| `proxy` | gRPC metadata, `authorization: Bearer <token>` |
| `extauthz` | HTTP header, `Authorization: Bearer <token>` |

One delegation, three enforcement points. `example/README.md` states that
explicitly, because it is the thing a reader is most likely to get wrong when
adapting this.

## Preconditions

Each example checks these before starting the agent, and names the fix. A
missing prerequisite must never look like a Stratium denial:

| Check | Failure text |
|---|---|
| Ollama reachable on `:11434` | `start ollama, or set OLLAMA_HOST` |
| the model is pulled | `ollama pull llama3.2` |
| LiteLLM answers on its port | `docker compose up -d litellm` |
| the stack is up | `deploy/stratium up --harness claude` |
| `npx` on PATH (mcp only) | `install Node 18+` |

## Testing

`example/agent/agent_test.go` drives `Run` against a fake `Transport` and a fake
LiteLLM, asserting: an expected-allow that is allowed passes; an expected-deny
that is allowed **fails**; an expected-allow that is denied **fails**; a turn
with no tool call is `INCONCLUSIVE` and does not fail. No model, no stack, no
network — this runs in `make test`.

The examples themselves are **not** in `make test`. They need Ollama, a pulled
model and a live stack, and a test suite that fails when a laptop lacks a 2 GB
model is a test suite people learn to ignore.

## Out of scope

- **`example/hook/` running the agent.** `hook` is a configuration contract for
  a harness that already exists; a custom client implementing it would be
  demonstrating a contract rather than a product, and would drift from what
  Claude Code actually sends.
- **Multi-turn conversational demos.** One task, a handful of tool calls, a
  tally. Anything longer buries the enforcement in transcript.
- **Model quality work.** `llama3.2:3b` will sometimes answer in prose instead
  of calling a tool. That is what `INCONCLUSIVE` is for; it is not this suite's
  job to make a small model reliable.

## Risks

- **The model may not call tools at all**, producing an all-inconclusive run
  that looks broken. The report must state plainly that zero tool calls means
  the model did not cooperate, and suggest a larger one.
- **`host.docker.internal` is not universal.** It works on Docker Desktop; on
  plain Linux the `extra_hosts` gateway mapping covers it, but a reader on an
  unusual setup will need to point LiteLLM at Ollama themselves.
- **The suite adds a compose service to a stack the quickstart also manages.**
  `deploy/stratium down` will remove `litellm` along with everything else, which
  is correct but worth stating.
