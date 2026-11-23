# LiteLLM guardrail

Stratium checks tool calls inside a [LiteLLM](https://docs.litellm.ai) proxy
with two guardrails, loaded from one file,
`deploy/litellm/stratium_guardrail.py`. They need no hook in the agent
harness.

| Guardrail | What it checks | How firm it is |
|---|---|---|
| `StratiumMCPGuardrail` | a tool call LiteLLM's MCP gateway is about to execute | LiteLLM runs the call itself, so a refused call does not run |
| `StratiumChatGuardrail` | a tool call a model proposes in a chat completion | a refused call is removed from the reply; what the client then does is not seen |

**The chat check is not a boundary.** LiteLLM sees what a model proposes, not
what the client runs. A client that reaches a model provider without going
through the proxy is not checked, and nothing is reported after a call runs.
Use it to bring agents with no Stratium hook under the same policy and audit
trail, alongside a boundary such as [`proxy`](proxy.md) or
[`extauthz`](extauthz.md) for what must be protected.

**How this was verified.** Run on LiteLLM 1.111.0 (the image this repository
pins) against a quickstart PDP, a mock model that proposes one granted and
one ungranted tool call, and a mock MCP server:

- chat, not streamed: the granted call was delivered, the other was removed,
  and the reply's text carried the PDP's reason;
- chat, streamed: the same, with the text before the tool calls streaming as
  it arrived and the granted call delivered whole;
- MCP: the granted call ran and was reported and matched; the other was
  refused with the PDP's reason as an MCP tool error, and the upstream server
  did not run;
- with the PDP unreachable, every tool call in a reply was removed and every
  MCP call refused;
- with a LiteLLM virtual key carrying the agent in its metadata, both
  guardrails found it; with a key naming no agent, every call was refused.

Not observed: a real model or agent harness as the client, an approval wait
(the SDK's tests cover it), LiteLLM run with several workers, and the routes
listed under [What is not covered](#what-is-not-covered).

---

## Installing

LiteLLM loads a guardrail from a Python file beside its `config.yaml`. Put
the guardrail and the [Python SDK](../../sdk/python/README.md) it uses there.
With LiteLLM's Docker image:

```sh
docker run \
  -v ./config.yaml:/app/config.yaml \
  -v ./deploy/litellm/stratium_guardrail.py:/app/stratium_guardrail.py \
  -v ./sdk/python/stratium:/app/stratium \
  -e STRATIUM_PEP_PDP_ADDR=pdp.example.com:50051 … \
  ghcr.io/berriai/litellm --config /app/config.yaml
```

The image already has the two libraries the SDK needs (`grpcio` and
`protobuf` 5.29 or later). Add both guardrails to `config.yaml`:

```yaml
guardrails:
  - guardrail_name: stratium-mcp
    litellm_params:
      guardrail: stratium_guardrail.StratiumMCPGuardrail
      mode: [pre_mcp_call, post_mcp_call]
      default_on: true
  - guardrail_name: stratium-chat
    litellm_params:
      guardrail: stratium_guardrail.StratiumChatGuardrail
      mode: post_call
      default_on: true
```

`default_on: true` runs a guardrail on every request, whatever the request
asks for. LiteLLM's settings that stop a key or team changing its guardrails
are part of its Enterprise licence.

## Configuration

Environment variables on the LiteLLM process, under the names
[`hook`](hook.md) uses. LiteLLM does not start without the required ones.

| Variable | |
|---|---|
| `STRATIUM_PEP_PDP_ADDR` | required |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | required, as `500ms`, `5s` or `2m` |
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL`, `STRATIUM_PEP_APPROVAL_TIMEOUT` | required |
| `STRATIUM_PEP_TTL_SECONDS` | required: how long a delegation lasts |
| `STRATIUM_PEP_REQUESTED_TIER`, `STRATIUM_PEP_REQUESTED_TOOLS` | required: what a delegation asks for, unless the key says otherwise |
| `STRATIUM_PEP_PDP_CA_FILE`, `STRATIUM_PEP_PDP_INSECURE` | TLS, as for `stratium-pep` |
| `STRATIUM_PEP_AGENT_ID`, `STRATIUM_PEP_SUBJECT`, `STRATIUM_PEP_HARNESS` | optional defaults for keys that name none |
| `STRATIUM_LITELLM_UNREAD_ROUTES` | `refuse` (default) or `allow`; see below |

## Who is calling

One LiteLLM key is one Stratium agent. Set these in the key's metadata when
you create it:

```sh
curl "$LITELLM/key/generate" -H "Authorization: Bearer $MASTER_KEY" -d '{
  "key_alias": "build-agent",
  "metadata": {
    "stratium_agent_id": "6f1c…",
    "stratium_subject": "ana@example.com",
    "stratium_harness": "cursor",
    "stratium_tools": "Read,Grep,Bash",
    "stratium_tier": 2
  }
}'
```

| Metadata | |
|---|---|
| `stratium_agent_id` | the agent. Falls back to `STRATIUM_PEP_AGENT_ID`. With neither, every call is refused |
| `stratium_subject` | the person the agent acts for. Falls back to the key's own user, then `STRATIUM_PEP_SUBJECT` |
| `stratium_harness` | the agent harness, so its tool names are decided as [`hook`](hook.md) decides them. Chat only |
| `stratium_tools`, `stratium_tier` | what the delegation asks for |

The guardrail creates a delegation the first time a key is seen and reuses
it. A client that sends `litellm_session_id` gets a delegation per session.

The PDP must run with principal verification off, or the delegation cannot be
created: the guardrail has no OIDC token for the subject.

## MCP gateway calls

- The call is decided under the name the client uses for it,
  `<server>-<tool>`, with its arguments. Catalog entries and delegations must
  use that name: `files-read_file`, not `read_file`.
- A refusal reaches the client as an MCP tool error with the PDP's reason.
- A call that ran is reported, so the PDP can flag one it never allowed.
- Listing tools decides nothing, and a tool that would be refused is still
  listed.

## Tool calls in chat replies

- Each tool call in a reply is decided under its name, with its arguments as
  the model wrote them.
- A refused call is removed and the reply gains a line saying so:
  `[Stratium refused Write: tool "Write" not in delegation approved_tools at depth 0]`.
  The other calls in the reply go through. When none is left the reply ends
  as plain text.
- In a streamed reply, the text before the first tool call streams as it
  arrives. From the first tool call on, the reply is held until it ends and
  the calls are decided.
- A reply with several choices (`n` above 1) has the tool calls of every
  choice decided, streamed or not.
- The older `function_call` form, one call per reply, is decided the same
  way.

## What is not covered

- **Anything but chat and text completions.** Tool calls are read from
  completion replies, and from streams on the `…/completions` routes. Every
  other reply that could carry a tool call is refused with HTTP 501, so that
  it is not passed unchecked without anyone choosing that: Anthropic Messages
  (`/v1/messages`), the Responses API (`/v1/responses`), and any route
  LiteLLM adds later. Replies that cannot carry one, such as embeddings,
  images and transcriptions, pass.
  `STRATIUM_LITELLM_UNREAD_ROUTES=allow` passes the refused ones unchecked.
- **File tools with a relative path.** The proxy does not know the client's
  working directory, so the PDP refuses them.
- **Which model a key may call.** [`example/extauthz`](../../example/extauthz/README.md)
  shows that with Envoy.
- **Several LiteLLM workers** each keep their own delegations, so one key has
  one per worker in the audit trail.

## When a call goes through undecided

- **The guardrails are not in `config.yaml`**, or `default_on` is false and
  the request does not ask for them.
- **`STRATIUM_LITELLM_UNREAD_ROUTES=allow`**, for the replies above.
- **The client does not use the proxy.**

A PDP that cannot be reached, a key with no agent and an error inside the
guardrail all refuse. The reason sent to the client does not include the
PDP's address; the full error is in LiteLLM's log under `stratium.litellm`.
