# agentgateway: `stratium-pep extmcp`

A gRPC server that [agentgateway](https://agentgateway.dev) asks before it
forwards an MCP tool call. agentgateway already stands in front of your MCP
servers; this mode lets Stratium decide each `tools/call` that passes through
it, with no change to the client or the servers.

It is [`mcp`](mcp.md)'s decision on a different transport. `mcp` fronts one
MCP server on stdio; `extmcp` sits beside a gateway that fronts many.

**Only MCP tool calls are decided.** agentgateway also routes chat requests to
models, and its guardrail webhook for model replies carries the reply's text
only, not the tool calls in it (agentgateway 1.7.0). Stratium therefore has
nothing to decide on that path. A tool call a model proposes is decided when
it is executed through the gateway's MCP route, not when it is proposed.

**How this was verified.** Run against agentgateway 1.7.0 in Docker, a
quickstart PDP and a mock MCP server, with a delegation holding one of the
server's two tools:

- the held tool ran and its result reached the client;
- the other was refused with the PDP's reason as an MCP tool error, and the
  MCP server did not run;
- with the PDP unreachable, the call was refused the same way;
- with `extmcp` stopped and `failureMode: failClosed`, agentgateway refused
  the call itself (`guardrail check failed`);
- on a route with two targets, each tool was decided under the name the
  client called it by (`fs_read_file`, `docs_read_file`), and a tool held on
  one target was refused on the other;
- a call the PDP escalated was held for 11 seconds, with the processor's
  timeout raised, and ran once a person approved it; left unapproved, it was
  refused when `STRATIUM_PEP_APPROVAL_TIMEOUT` ran out; with the gateway's
  default timeout, agentgateway refused it itself after 10 seconds;
- with Claude Code as the MCP client, the held tool's result reached the
  model and the other tool's refusal reached it as the tool's error.

---

## Where it sits

```
MCP client ──▶ agentgateway ──CheckRequest──▶ stratium-pep extmcp ──▶ PDP
                    │                                  │
                    │◀──────── pass / refuse ──────────┘
                    ▼
               MCP server          (only on a pass)
```

agentgateway calls the `ExtMcp` service
([`proto/agentgateway/ext_mcp.proto`](https://github.com/agentgateway/agentgateway/blob/v1.7.0/crates/protos/proto/ext_mcp.proto),
vendored unmodified) through a `remote` guardrail processor. `extmcp` never
sees the MCP server's reply and forwards nothing itself.

---

## Configuration

Nine variables: `hook`'s seven, plus the listen address and the cache window.
Observed with an empty environment:

```
$ stratium-pep extmcp
stratium-pep: missing required configuration: STRATIUM_PEP_EXTMCP_LISTEN_ADDR;
missing required configuration: STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID,
STRATIUM_PEP_SUBJECT, STRATIUM_PEP_SESSION_FILE, STRATIUM_PEP_CONNECT_TIMEOUT,
STRATIUM_PEP_APPROVAL_POLL_INTERVAL, STRATIUM_PEP_APPROVAL_TIMEOUT;
missing required configuration: STRATIUM_PEP_CACHE_STALENESS_WINDOW
```

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_EXTMCP_LISTEN_ADDR` | `127.0.0.1:9011` | Where agentgateway connects. Cleartext gRPC: keep it on loopback or a private network. |
| `STRATIUM_PEP_CACHE_STALENESS_WINDOW` | `30s` | As for [`mcp`](mcp.md). |
| `STRATIUM_PEP_PDP_CA_FILE`, `STRATIUM_PEP_PDP_INSECURE` | | Optional, as for every mode. |
| *(the seven from [`hook.md`](hook.md))* | | Same meanings, same values. |

Run [`session-start`](session-start.md) first, with the same variables, on the
machine that runs `extmcp`. It creates the delegation and writes the session
file `extmcp` reads on every call.

In agentgateway, add a `remote` processor to the MCP route:

```yaml
routes:
- policies:
    mcpGuardrails:
      processors:
      - kind: remote
        host: "127.0.0.1:9011"
        failureMode: failClosed
        methods:
          tools/call: request
  backends:
  - mcp:
      targets:
      - name: files
        mcp:
          host: http://files.internal:9002/mcp
```

Keep `failureMode: failClosed`. It is agentgateway's default, and it is what
refuses a call when `extmcp` is not running. With `failOpen`, a stopped
`extmcp` means every call is forwarded unchecked.

---

## The tool name the PDP sees

`<target>_<tool>`: the route's name for the MCP server, an underscore, then
the server's own name for the tool. `read_file` on the target `files` is
decided as `files_read_file`. This is also the name agentgateway shows a
client when a route has more than one target.

The target is part of the name so that two servers offering a tool with the
same name can be granted separately. Use this form in the delegation's
requested tools (`STRATIUM_PEP_REQUESTED_TOOLS`) and in the tool catalog. As
with [`mcp`](mcp.md#seeding-the-catalog), a tool that is not in the catalog is
not held and is refused.

A target name cannot contain an underscore. With one, two different tools
could be given the same name (`a` + `b_c` and `a_b` + `c`). agentgateway 1.7.0
refuses to start with such a name (`invalid MCP target name`), and `extmcp`
refuses every call to such a target, and says why, should a gateway ever send
one.

The tool's `arguments` are sent to the PDP as they arrived.

---

## Who is calling

One identity: the agent and subject in `STRATIUM_PEP_AGENT_ID` and
`STRATIUM_PEP_SUBJECT`, under the one delegation in the session file. Every
client of the gateway route is decided as that agent.

`extmcp` does not read the caller's headers or the gateway's `metadata`
block. To decide different callers under different delegations, run one
`extmcp` per identity and point each route at its own.

---

## What a refusal looks like

agentgateway answers the client with an MCP tool result marked `isError:
true` whose text is the PDP's reason. The call does not reach the MCP server.

Every refusal is sent to agentgateway as an answer, not as a failed call: a
policy denial, an unreachable PDP, a missing session file, and a call that
cannot be read. `failureMode` only governs failed calls, so it cannot turn
any of these into a forward.

---

## Approvals

When the PDP escalates, `extmcp` holds the call and polls, as `mcp` does, for
up to `STRATIUM_PEP_APPROVAL_TIMEOUT`. agentgateway gives a guardrail call 10
seconds by default and then treats it as failed, which under `failClosed`
refuses the call. To let a human answer, raise the processor's timeout to at
least the approval timeout:

```yaml
      - kind: remote
        host: "127.0.0.1:9011"
        policies:
          http:
            requestTimeout: "130s"
```

The MCP client must also be willing to wait that long.

---

## Limits

- **`tools/call` only.** Every other MCP method passes undecided, and
  `tools/list` is not filtered, for the reason given in
  [`mcp`](mcp.md#toolslist-is-not-filtered).
- **Nothing is reported after a call runs.** agentgateway's response-phase
  call does not say which tool or arguments it belongs to.
- **Only what the processor's `methods` map names is sent.** A route without
  the processor, or a `methods` map without `tools/call: request`, is not
  checked.
- **Arguments are authorized as sent.** What the MCP server does with them is
  not seen.

---

## See also

- [`mcp`](mcp.md) for a single MCP server on stdio.
- [LiteLLM guardrail](litellm.md) for the same check inside a LiteLLM proxy.
- [`session-start`](session-start.md) for the delegation `extmcp` enforces.
