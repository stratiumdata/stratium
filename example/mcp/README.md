# example/mcp — the agent that never learns Stratium exists

This is the flagship example. A real local model (`llama3.2` via Ollama, through
LiteLLM) decides its own tool calls and speaks plain MCP — newline-delimited
JSON-RPC 2.0 over stdio — to what it believes is a filesystem server.
`stratium-pep mcp` sits in between as a transparent proxy, authorizing every
`tools/call` against the PDP before it ever reaches the real
`@modelcontextprotocol/server-filesystem`.

The thing to notice is what is **absent**: `mcpclient.go` and `stratium/example/agent`
contain no Stratium code at all. They know MCP; they do not know Stratium exists.
Every Stratium-aware line lives in `main.go`'s setup, before the agent loop starts,
and in the two arguments handed to `startMCP`.

## Running it

```bash
cd example
export EXAMPLE_MCP_PAP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"
export EXAMPLE_MCP_PDP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port pdp-pap 50051   | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port keycloak 8080    | sed -E 's/.*://')"
export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"
go run ./mcp
```

`EXAMPLE_MCP_PAP_ADDR` must point at `stratium-pap` and `EXAMPLE_MCP_PDP_ADDR`
at `pdp-pap` — named per example, not shared, because `proxy` and `extauthz`
each point at a *different* PAP/PDP pair for a different tenant; exporting one
example's PDP/PAP address and then running another would otherwise send that
program to the wrong tenant.

`main.go` then, in order: prechecks Ollama/LiteLLM/the PDP/`npx` (a missing
prerequisite is reported as setup, never as a policy denial); seeds
`/tmp/example-data/notes.txt` and `/tmp/example-data/secret-x/plans.txt`;
registers the resource-label rules a classification cap needs (a catch-all at
`UNCLASSIFIED` and `/tmp/example-data/secret-` at `SECRET`); ensures its agent
row exists and caps it at `{"nato":"CONFIDENTIAL"}`; runs
`stratium-pep session-start`; launches `stratium-pep mcp` as a child; and hands
the whole thing to `agent.Run` with a task that reads both files and an
expectation that the plain read is **ALLOWED** and the read under `secret-x/`
is **DENIED** for exceeding the delegation's classification cap.

## The substitution test

This is the whole point of the example, so it is worth doing once by hand.

In `main.go`, `startMCP` is called with:

```go
transport, err := startMCP(pepBin, []string{"mcp"}, mcpEnv(pdpAddr, agentID, subject, sessionFile), os.Stderr)
```

Replace that call with:

```go
transport, err := startMCP("npx", []string{"-y", "@modelcontextprotocol/server-filesystem", exampleDataDir}, nil, os.Stderr)
```

— i.e. swap `stratium-pep mcp` for the real server directly, with no PEP in the
loop at all — and re-run `go run ./mcp`.

**Both reads now succeed.** There is no PDP to deny the `secret-x` read, so
nothing does; the real filesystem server enforces only its own directory
allow-list, which permits everything under `/tmp/example-data`.

**Nothing else changes.** Not `mcpclient.go`, not `agent.Run`, not the task, not
the expectations' shape (only their outcome). The agent was never talking to
Stratium — it was talking to an MCP server, full stop — and swapping which
process sits behind that pipe is a one-line edit in the harness's own setup
code, not a rewrite of the agent. That substitutability, demonstrated rather
than asserted, is the integration story this whole example exists to tell: a
PEP that requires the agent to change to adopt it has already failed at the one
thing it promises.
