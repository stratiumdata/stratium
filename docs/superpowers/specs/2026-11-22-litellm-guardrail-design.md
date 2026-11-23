# LiteLLM guardrail design

Status: approved 2026-11-22, with the recommendations in "Open questions".

Outcome notes (built 2026-11-22):

- **The Python client already existed.** `sdk/python` had `Client` and
  `Session`; the design's `clients/python/stratium_pdp` was not built. The SDK
  gained `harness`, `cwd` and `report`.
- **The SDK's stubs are now generated with grpcio-tools 1.71.** The committed
  ones needed protobuf 7.35 and would not load in LiteLLM's image (5.29).
  Stubs from the older generator load on both. The committed stubs were also
  stale: they lacked `harness` and `cwd`.
- **Two guardrail classes, not one.** LiteLLM does not call the reply hooks on
  a class that implements `apply_guardrail`, which the MCP gateway needs.
  `StratiumMCPGuardrail` and `StratiumChatGuardrail` share one engine, so a
  key has one delegation.
- **Configured subject and agent as a fallback.** A proxy with no database has
  only its master key, whose user is a placeholder. `STRATIUM_PEP_AGENT_ID`
  and `STRATIUM_PEP_SUBJECT` cover that; a key's metadata still wins.
- **What is not read is refused, not passed.** The guardrail lists the
  replies it reads (completions) and the kinds that cannot carry a tool
  call; every other reply returns 501 unless
  `STRATIUM_LITELLM_UNREAD_ROUTES=allow`. A list of unread routes would have
  passed any route added later.
- **Every choice of a streamed reply is decided**, for a request with `n`
  above 1.
- **Not built:** the guardrail in the compose stack and integration tests
  through it. The existing LiteLLM service there serves the `extauthz`
  example with no keys. Verified instead by unit tests and the live run the
  docs page describes.

## Intent

Teams that route their agents through a LiteLLM proxy should get Stratium's
decisions there, with no hook in the agent harness. That reaches agents
Stratium has no harness adapter for, and it puts a check on the MCP servers
LiteLLM runs on a team's behalf.

The maintainer chose a Python guardrail loaded by LiteLLM ("approach B") over
an external HTTP endpoint, for the widest coverage LiteLLM allows.

## Goals

- Decide every MCP tool call LiteLLM's gateway is about to execute, and
  report it afterwards.
- Decide every tool call a model proposes in a chat reply, streamed or not,
  before the client receives it.
- One Stratium agent and one audit trail per LiteLLM key, using the PDP's
  existing `CreateDelegation`, `Decide` and `ReportToolUse` calls unchanged.
- Refuse when the PDP cannot be reached or the guardrail fails.

## Non-goals

- Deciding which model a key may call. `example/extauthz` shows that with
  Envoy; a guardrail version can follow.
- The Responses API and Anthropic Messages shapes in the first build (see
  "Build order").
- Python adapters for agent frameworks. The PDP client written here is the
  piece they would reuse.

## Anti-goals

- A chat-reply check presented as a boundary. LiteLLM sees what the model
  proposes, not what the client runs, and a client that calls a model
  provider directly is not checked. The docs page must open with that.
- Logic duplicated from the PDP. The guardrail extracts nothing from tool
  input; it sends the name and raw input and acts on the answer.

## What a probe showed

A throwaway guardrail was run in the repository's pinned LiteLLM image
(1.111.0, Python 3.13) against a mock model and a mock MCP server.

**MCP gateway**

- The guardrail runs before, during and after each call. Before the call it
  receives `mcp_tool_name`, `mcp_arguments` as a structured object, and
  `mcp_server_name`.
- Raising there refused the call. The client got an MCP tool error
  (`isError: true`) and the upstream server did not run.
- The guardrail also runs once per tool on `tools/list`, with empty
  arguments. A tool it refused there was left out of the listing.
- After the call it receives the result text and the tool name and
  arguments again.

**Chat replies**

- Not streamed: the guardrail receives the reply's tool calls as structured
  objects. Raising returned HTTP 400 to the client with the reason.
- Editing the tool-call list through `apply_guardrail` came back wrong: one
  call removed from two left two copies of the other. Rewriting has to be
  done on the response object directly.
- Streamed: `apply_guardrail` runs after the chunks have reached the client.
  A refusal there only appends an error event; the tool calls were already
  delivered.
- Streamed, with `async_post_call_streaming_iterator_hook`: the guardrail can
  hold back every chunk from the first tool-call delta, decide when the
  stream ends, and release them or send a refusal instead. Text before the
  tool calls still streams as it arrives. This worked.

**Identity and environment**

- The guardrail receives the key's hash, user and team, and a session id
  when the client sends `litellm_session_id`.
- The image has `grpc` and `protobuf` but not `grpc_tools`, so the PDP
  client's stubs must be generated ahead of time and shipped.
- `default_on: true` runs the guardrail on every request without an
  Enterprise licence. Locking guardrails per key or team needs one.

## Approaches

1. **Go HTTP endpoint speaking LiteLLM's external guardrail contract.** No
   Python and it fits the existing binary. The contract is labelled beta,
   can refuse but not edit, and cannot hold back a streamed tool call.
2. **Python guardrail loaded by LiteLLM, talking to the PDP (chosen).** Full
   access to the MCP modes and the streaming hook. Needs a Python PDP client
   and follows LiteLLM's Python interfaces, which change often.
3. **Thin Python guardrail forwarding to a Go endpoint.** Same hooks with the
   logic in Go, at the cost of two components to ship.

The maintainer picked 2 for coverage. Streaming is what rules out 1.

## Design

### Pieces

- `clients/python/stratium_pdp/`: a small gRPC client for `CreateDelegation`,
  `Decide`, `GetApproval` and `ReportToolUse`, with stubs generated from
  `proto/pdp/v1/pdp.proto` by a `make` target and committed. TLS and the
  user agent follow `stratium-pep`'s rules.
- `deploy/litellm/stratium_guardrail.py`: one `CustomGuardrail` subclass.
- `deploy/litellm/README` content lives in `docs/pep/litellm.md`: how to
  mount the two into LiteLLM and the config to add.
- The compose stack's LiteLLM service gains the guardrail, so the
  integration suite can exercise it.

### Configuration

Environment variables on the LiteLLM process, named as `stratium-pep`'s are:
`STRATIUM_PEP_PDP_ADDR`, `STRATIUM_PEP_CONNECT_TIMEOUT`,
`STRATIUM_PEP_APPROVAL_POLL_INTERVAL`, `STRATIUM_PEP_APPROVAL_TIMEOUT`,
`STRATIUM_PEP_TTL_SECONDS`. A missing one stops LiteLLM at start-up.

```yaml
guardrails:
  - guardrail_name: stratium
    litellm_params:
      guardrail: stratium_guardrail.StratiumGuardrail
      mode: [post_call, pre_mcp_call, post_mcp_call]
      default_on: true
```

### Who is calling

One LiteLLM key is one Stratium agent. The key's metadata carries
`stratium_agent_id`, and optionally `stratium_harness` and
`stratium_tools`, set when the key is created. A request from a key with no
`stratium_agent_id` is refused. The subject is the key's user id.

### Sessions

The guardrail creates a delegation the first time it sees a
(key, session) pair and keeps the token in memory until it expires.
`session` is `litellm_session_id` when the client sends one, and otherwise
the key itself, so a key with no session id has one delegation per TTL.
LiteLLM run with several workers creates one delegation per worker; that is
more rows in the audit trail, not a different decision.

### MCP gateway calls

- **Before the call:** `Decide` with the tool as LiteLLM names it
  (`<server>-<tool>`), the arguments as raw input, and no harness. Deny
  raises, which the client sees as an MCP tool error carrying the PDP's
  reason. An escalation waits for approval up to the approval timeout, then
  denies.
- **On `tools/list`:** allow everything. Deciding with empty arguments would
  audit a call nobody made, and hiding a tool is not this design's job.
- **After the call:** `ReportToolUse` with the same tool and raw input.

### Tool calls in chat replies

- **Each tool call** is decided with its name, its arguments as raw input,
  and the key's `stratium_harness`, so the PDP applies that harness's tool
  names. Without a harness the name is decided as sent.
- **A refused call is removed from the reply**, and the reply's text gains
  one line per refused call: the tool name and the PDP's reason. Allowed
  calls in the same reply go through. If nothing is left, the finish reason
  becomes `stop`.
- **Not streamed:** done in `async_post_call_success_hook`, editing the
  response object.
- **Streamed:** done in `async_post_call_streaming_iterator_hook`, holding
  chunks from the first tool-call delta until the stream ends. A stream with
  no tool call is not delayed.
- **Nothing is reported afterwards.** LiteLLM never learns whether the client
  ran the call.
- **Working directory.** The gateway does not know it, so a file tool call
  with a relative path is refused by the PDP's existing rule.

### Failure

Any exception in the guardrail refuses the request or the call. The PDP
unreachable, a deadline exceeded, an unparseable tool call and an unknown
response shape are all refusals, with the reason in LiteLLM's log and a
short one to the client.

## Build order

1. Python PDP client with tests against the integration stack.
2. MCP gateway checks and reporting.
3. Chat reply checks on the OpenAI chat completions shape, streamed and not.
4. Docs page and the compose wiring.
5. Later, each its own change: Anthropic Messages and Responses shapes;
   model access.

## Testing

- Unit tests for the guardrail with a fake PDP client: allow, deny,
  escalate, PDP down, streamed and not, mixed allowed and refused calls.
- Integration tests through the compose stack's LiteLLM: an MCP call allowed,
  refused and reported; a chat reply's tool call allowed and refused, both
  ways of streaming.
- A new CI job runs the Python tests. The repository has no Python tests
  today apart from the installer's self-test.

## Left to the builder

- The layout of the generated stubs and the `make` target that builds them.
- The exact refusal wording added to a reply.
- How the in-memory token cache is bounded.

## Open questions for the maintainer

1. **A refused tool call in a chat reply: remove that call, or refuse the
   whole reply?** Recommended: remove the call and say why, as above, so one
   refused call does not end an agent's turn. The alternative is simpler and
   stricter: HTTP 400 for the whole reply.
2. **Hide refused MCP tools from `tools/list`?** Recommended: no, as above.
   The alternative decides every tool at listing time with empty arguments.
3. **Where the Python client lives.** Recommended: `clients/python/`, beside
   the UI client, so framework adapters can depend on it later.
