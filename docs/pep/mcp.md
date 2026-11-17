# `stratium-pep mcp`

A stdio JSON-RPC proxy that stands in front of a real MCP server. It launches
the upstream server as a child process, relays every frame in both directions,
and asks the PDP to authorize each `tools/call` before it reaches the real
server.

Use it for harnesses that have **no hook system** — ChatGPT, Claude Desktop, or
anything else that speaks MCP but cannot run a `PreToolUse` command.

---

## Where it sits

```
harness  ──stdio──▶  stratium-pep mcp  ──stdio──▶  real MCP server (child process)
                            │
                            └──▶ PDP, on every tools/call
```

Nothing about how your harness talks MCP changes. The proxy speaks the same
stdio JSON-RPC framing on both sides; it is a man in the middle by design.

---

## Configuration

Nine variables: `hook`'s eight, plus the upstream command. Observed with an
empty environment:

```
$ stratium-pep mcp
stratium-pep: missing required configuration: STRATIUM_PEP_MCP_UPSTREAM_COMMAND;
missing required configuration: STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID,
STRATIUM_PEP_SUBJECT, STRATIUM_PEP_SESSION_FILE, STRATIUM_PEP_CONNECT_TIMEOUT,
STRATIUM_PEP_APPROVAL_POLL_INTERVAL, STRATIUM_PEP_APPROVAL_TIMEOUT;
missing required configuration: STRATIUM_PEP_CACHE_STALENESS_WINDOW
```

Two loaders report separately — the MCP-specific one and the shared decision
config — which is why the message has more than one `missing required
configuration` clause. All of it must be satisfied.

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_MCP_UPSTREAM_COMMAND` | `npx` | The real server's executable. |
| `STRATIUM_PEP_MCP_UPSTREAM_ARGS` | `-y @modelcontextprotocol/server-filesystem /srv/data` | Optional. Space-separated. |
| `STRATIUM_PEP_PDP_CA_FILE` | `/etc/stratium/pdp-ca.pem` | Optional. PEM CA bundle to verify the PDP's TLS certificate with, instead of the system roots. |
| `STRATIUM_PEP_PDP_INSECURE` | `true` | Optional. Plaintext connection to the PDP, for a local development stack only. Default is TLS. Conflicts with `STRATIUM_PEP_PDP_CA_FILE`. |
| *(the eight from [`hook.md`](hook.md))* | | Same meanings, same values. |

---

## Worked example

Wrapping `@modelcontextprotocol/server-filesystem`. Where you would have
configured this in your harness:

```json
{ "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"] }
```

you configure the proxy instead, and pass the real server through the
environment:

```json
{
  "command": "/opt/stratium/bin/stratium-pep",
  "args": ["mcp"],
  "env": {
    "STRATIUM_PEP_MCP_UPSTREAM_COMMAND": "npx",
    "STRATIUM_PEP_MCP_UPSTREAM_ARGS": "-y @modelcontextprotocol/server-filesystem /srv/data",

    "STRATIUM_PEP_PDP_ADDR": "localhost:50051",
    "STRATIUM_PEP_PDP_INSECURE": "true",
    "STRATIUM_PEP_AGENT_ID": "0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19",
    "STRATIUM_PEP_SUBJECT": "agent-tester@example.com",
    "STRATIUM_PEP_SESSION_FILE": "/run/stratium/session.json",
    "STRATIUM_PEP_CONNECT_TIMEOUT": "5s",
    "STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "2s",
    "STRATIUM_PEP_APPROVAL_TIMEOUT": "120s",
    "STRATIUM_PEP_CACHE_STALENESS_WINDOW": "30s"
  }
}
```

Run [`session-start`](session-start.md) before the harness launches, or every
call denies for want of a session.

### Trying it without a harness

The proxy is just a process on stdio, so you can drive it by hand:

```bash
cat > /tmp/frames.jsonl <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/srv/data/notes.txt"}}}
EOF

{ cat /tmp/frames.jsonl; sleep 25; } | stratium-pep mcp
```

The trailing `sleep` matters: the proxy exits when its stdin closes, and without
it the pipe closes before the upstream has answered.

---

## Seeding the catalog

The PDP needs to know which argument of each tool names the resource. The
filesystem server's tools are **not** Claude Code's — `read_text_file` takes
`path`, where `Read` takes `file_path`. Seed both catalogs:

```bash
psql … -v tenant_id="$TENANT" -f deploy/seed/tool-catalog-mcp-filesystem.sql
```

An uncatalogued tool is not a hole — the delegation's `approved_tools` is checked
before the catalog matters, so a tool nobody has catalogued is simply not held
and denies. The catalog governs how a *held* tool's arguments are read.

---

## What a denial looks like

The proxy answers the harness with a JSON-RPC error carrying the PDP's reason,
in place of the upstream's result. The call never reaches the real server.

## `tools/list` is not filtered

The proxy authorizes `tools/call`. It does **not** trim `tools/list` down to
what the delegation holds, so a model sees the upstream's full menu and
discovers the boundary by being refused.

That is deliberate — filtering the list would make the proxy's view of the
grant authoritative in a second place, and the two would drift. It does mean a
model may plan around tools it cannot use.

---

## Limits

- **One decision per `tools/call`.** Anything the upstream does off its own
  initiative is not seen.
- **Arguments are authorized as sent.** The proxy does not evaluate what the
  upstream will do with them.
- **The upstream is a child process.** It inherits the proxy's environment —
  including every `STRATIUM_PEP_*` variable. If that matters for your upstream,
  scrub them in a wrapper script.

---

## See also

- [`hook.md`](hook.md) — the equivalent for harnesses that do have hooks.
- [`../pep.md`](../pep.md) § "Installing the `mcp` proxy" and § "Seeding the tool
  catalog".
- [`../../example/mcp/`](../../example/mcp/) — this surface as a runnable program: a real local model, a real MCP server, a real deny.
