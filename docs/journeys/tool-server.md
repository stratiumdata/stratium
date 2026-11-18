# Govern a tool server

**You are** a platform engineer. **You want** calls to an MCP server, an HTTP
API, or a gRPC service checked by Stratium, whichever agent or client is
calling.

Pick the surface by **what you are protecting**:

| You're protecting | Use | How it fits in |
|---|---|---|
| An MCP server used by Claude Desktop, ChatGPT desktop, Claude Code, or Codex | [`mcp`](../pep/mcp.md) | Runs in place of the server's launch command and wraps it. Checks every `tools/call`. |
| An HTTP API behind Envoy | [`extauthz`](../pep/extauthz.md) | Envoy asks Stratium about every request before forwarding it. |
| A gRPC service | [`proxy`](../pep/proxy.md) | The client points at the proxy instead of the service. No other change. |
| Something else, from your own Python code | [Python SDK](https://github.com/stratiumdata/stratium/blob/main/sdk/python/README.md) | Call `Session.check()` before each action. |

## The MCP journey

1. **Register the agent and start a session**, as in
   [Your first governed agent](first-agent.md), with the tools the agent may
   call.
2. **Replace the server's command** in the harness's MCP configuration with
   `stratium-pep mcp`, and pass the real server in
   `STRATIUM_PEP_MCP_UPSTREAM_COMMAND` and `STRATIUM_PEP_MCP_UPSTREAM_ARGS`.
3. **Use the agent normally.** Allowed calls pass through to the real server.
   A refused call never reaches it: the agent gets a JSON-RPC error carrying
   the reason instead.

The agent still sees the server's full tool list. Stratium checks calls, not
the menu, so the agent finds its limits by being refused.

[`mcp`](../pep/mcp.md) lists every variable, with a worked configuration.

## The API and gRPC journey

1. **Give the calling client a delegation**, with `session-start` or the
   Python SDK, granting the requests or methods it may call. For `proxy`, tool
   names are full gRPC method paths, such as `/orders.v1.Orders/Cancel`. Add
   them to the tool catalog like any other tool.
2. **Put the PEP in the path:** register `extauthz` as Envoy's external
   authorization service, or point the client at `proxy`. For gRPC, that is
   the only change on the client side.
3. **Have the client attach its token to every request**, along with a DPoP
   proof. These surfaces require *sender-constrained* tokens, so a stolen
   token is useless without the client's key. A refused gRPC call returns
   `PermissionDenied` with the reason.

## Choosing between them

| | `hook` / `mcp` | `extauthz` / `proxy` |
|---|---|---|
| Who's calling | a local agent you launched | any client on the network |
| If the PDP is down | `mcp` can replay a recent decision from memory; `hook` refuses | **refuses everything**, with no cache |
| Token | bearer, from the session file | sender-constrained (DPoP) |

!!! warning "A PDP outage is an outage of what it guards"
    `extauthz` and `proxy` never fall back to a cache, because on the network
    the caller is the party being checked. If the PDP is unreachable, every
    request to the API behind it is refused. Size the PDP's availability to
    match the API's.

## Limits to know

- **The catalog decides what Stratium can see.** Register each tool the server
  exposes in the [tool catalog](../user-guide.md#56-crud-tools-the-tool-catalog),
  naming the argument that holds the resource, so caps and scopes can apply.
  Don't guess the field names: capture a real call first, as described in
  [Installing stratium-pep](../pep.md).
