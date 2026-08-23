# example/depth/mcp — one tool, two depths, two different answers, live

`example/depth/hook` probes `stratium-pep hook` directly with fixed JSON, because that surface's
harness is Claude Code and this suite has no business pretending to be it. `stratium-pep mcp` is
different: its harness (an MCP client loop) is something this suite already writes for
`example/mcp`, so this directory drives a real local model, twice, exactly the way that flagship
example does — see that directory's own README first if MCP transport or the substitution test are
unfamiliar.

## The three claims

1. **`search_files` is ALLOWED at depth 0.** The orchestrator's own root delegation holds it.
2. **The SAME `search_files` — same tool, same task, same tools offered to the model — is DENIED at
   depth 1**, and the reason names the depth: `tool "search_files" not in delegation approved_tools
   at depth 1`. A denial for a tool the parent never held would just be `example/mcp` one level
   deeper; only a real two-hop chain shows the *parent* holding what the *child* does not.
3. **A child asking for more than its parent granted is refused at creation**, before either `mcp`
   run below ever starts — `store.CreateDelegation`'s own `models.ScopeNarrows` check — naming the
   dimension that failed: `child tool "write_file" not in parent approved_tools`.

`read_text_file` at depth 1 is probed too, alongside claim 2, to show the child isn't simply broken
— it still works for what it does hold.

## The run-twice shape

`main.go` launches `stratium-pep mcp` wrapping the identical real
`@modelcontextprotocol/server-filesystem`, against the identical directory, **twice**: once
configured with the parent's session file and agent id (depth 0), once with the child's (depth 1).
`tools/list` is never filtered by depth (`stratium-pep`'s own `mcp.go` package doc, "TOOLS/LIST IS
DELIBERATELY NOT FILTERED"), so the model is offered the exact same 14-tool catalog both times —
identical request, two depths, two answers, and the reason on the deny says which depth decided.

The `search_files` claim and the `read_text_file` "still works" claim are each their own one-shot
`agent.Run` call, not two turns of one conversation — see **Two single-tool tasks, not one chained
task**, below, for why.

## Running it

```bash
cd example
export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"
export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"
export EXAMPLE_KC_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"
export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"
go run ./depth/mcp
```

Needs everything `example/mcp` needs — Ollama with `llama3.2` pulled, LiteLLM, `npx`, the Docker
Compose stack up, a built `stratium-pep` binary at `../bin/stratium-pep` (override with
`EXAMPLE_PEP_BIN`) — `main.go`'s own `Precheck` reports any of these that are missing by name, with
the exact fix, never as a policy denial.

## Why `EXAMPLE_DEPTH_PDP_ADDR`/`EXAMPLE_DEPTH_PAP_ADDR`, not `EXAMPLE_MCP_*`

This program shares its tenant — `tenant-pap-e2e-integration`, served by `pdp-pap`/`stratium-pap` —
with `example/mcp` *and* with `example/depth/hook`, which already established these two env var
names as the depth suite's own, for the identical reason that example's own README gives: adding a
new tenant means a new PDP+PAP pair in `docker-compose.yml`, and this suite isn't adding
docker-compose services for one more example. A shell already exporting these two for
`example/depth/hook` needs nothing new to run this program too. Sharing the tenant is safe because
this program registers its own narrowly-scoped policy —
`permit(principal == User::"depth-mcp@example.com", action, resource);` — and its own two agents
(`depth-mcp-orchestrator`, `depth-mcp-worker`), never touching `example/mcp`'s own
`agent-tester@example.com` or `example/depth/hook`'s own subject and agents.

`search_files` and `read_text_file` need no new `tool_catalog` seeding: both already have rows in
this tenant from `deploy/seed/tool-catalog-mcp-filesystem.sql`, applied as a prerequisite of
`example/mcp` itself (confirmed live via `GET /v1/tool-catalog` before writing this program) — this
program's own `Precheck` does not re-check for it, since `example/mcp` already depends on it working
and this example runs nowhere `example/mcp` doesn't already.

## Two single-tool tasks, not one chained task

An earlier version of this file asked the model, in one message, to search for a file and then read
whatever it found. That reliably failed: confirmed against a live litellm/ollama, llama3.2 answers
the FIRST turn of a fresh conversation with a genuine tool call reliably, but the turn immediately
AFTER it has already made one real tool call and been handed that call's result back reliably
degrades into prose describing a *fake* tool call instead of emitting a real one — a multi-turn,
tool-switching weakness distinct from the schema-ordering defect fixed in `agent/litellm.go` (see
below). Splitting `taskSearch` (`search_files`) and `taskRead` (`read_text_file`) into two separate,
single-turn `agent.Run` calls against the same depth-1 transport sidesteps that weakness entirely
rather than working around it — each conversation only ever needs the model to make its very first
tool call.

## `search_files`' pattern is a glob, not a substring

Confirmed against the real server: calling `search_files` with `pattern: "sentinel"` against a file
literally named `sentinel.txt` answers `"No matches found"` — glob semantics, not "contains". This
program's task asks for `pattern="sentinel*"` explicitly; the wildcard is load-bearing, not
decorative.

## A real bug this example's own flakiness exposed, fixed for the whole suite

Chasing why `search_files` — and only `search_files`, never `read_text_file` — was unreliable led to
`agent.ToolSpec.Schema` (`example/agent/transport.go`) and `agent/litellm.go`'s own tool-definition
wrapper: both held a tool's JSON Schema as `map[string]any`, and `encoding/json` always
re-serializes a Go map's keys **sorted alphabetically**, regardless of insertion order. A real MCP
tool's `inputSchema`, as the wire actually sends it, opens `"$schema"`, then `"type":"object"`, then
`"properties"`. Round-tripped through a Go map, it comes back out as `$schema`, `properties`,
`required`, `type` — `"type":"object"` moved away from where the server put it. Confirmed
empirically, repeatedly, and in isolation from every other candidate explanation (top-level request
key order, JSON whitespace, HTTP headers, `tool_choice` forcing — all ruled out one at a time against
a live litellm/ollama): an otherwise byte-for-byte identical request whose tool schemas were
reordered this way made llama3.2 answer with prose instead of a genuine `tool_calls` entry, for a
schema with more than one property. `search_files`' own schema (`path`, `pattern`,
`excludePatterns`) has three; `read_text_file`'s (`path`, `head`, `tail`) mostly survived the same
reordering by luck rather than by being immune to it.

The fix — `Schema`/`InputSchema`/`Parameters` are now `json.RawMessage` end to end
(`example/mcpwire`, `example/agent/transport.go`, `example/agent/litellm.go`) — carries a tool's
schema byte-for-byte from the upstream server's own `tools/list` response all the way into the
request this suite's shared `agent.LLM` sends, the identical "relay faithfully, never re-encode"
principle `stratium-pep`'s own `mcp.go` package doc already states for JSON-RPC frames, applied here
to a payload one level up. `example/proxy` and `example/extauthz`'s own hand-built, single-property
schemas moved to `json.RawMessage` literals for the same reason, even though their own flakiness (if
any) was never directly observed — a map-shaped schema is the same latent defect regardless of how
many properties happen to survive it by chance.

This fix lives in the SHARED `example/agent` and `example/mcpwire` packages, not only in this
directory, because the defect was never specific to `depth/mcp` — it is a property of every tool
schema this suite has ever sent a model, including `example/mcp`'s own. Re-running `example/mcp`
after this fix (see its own transcript) shows real tool calls on every turn, with no prose fallback
at all — an improvement that fix happened to surface, not something this directory needed for its
own sake.

## `agent.LLM.ToolChoice`: a model-reliability knob, not a policy one

Even with the schema fix above, this example still forces which tool each conversation probes via
`agent.LLM`'s new `ToolChoice` field (empty by default; every other example leaves it unset and gets
today's unchanged "auto" behavior). This is belt-and-suspenders, not a second bug being patched over
by the same mechanism: forcing which tool the model *attempts* never predetermines whether the real
PDP **allows or denies** that attempt — `stratium-pep mcp` still authorizes the call exactly as it
would for a call the model chose on its own, and the transcripts below show genuine `ALLOW`/`DENY`
lines from that live decision, not a canned response. It exists because CPU-based `llama.cpp`
inference is documented not to be bit-for-bit reproducible across runs even at `temperature: 0` —
confirmed here too: the exact same request, replayed later, sometimes answered differently with no
code-path difference behind the change. Forcing the one tool a conversation exists to probe removes
that last bit of drift from a demo that would otherwise occasionally need a retry to catch a live
pass.

## Denial vs. transport error, and the local decision cache

Same rules as every other example in this suite: a `Result{Allowed:false, Reason}` is
`stratium-pep mcp` answering (a JSON-RPC error on `tools/call`, per `mcpclient.go`'s own package
doc); a dead process, a broken pipe, or a malformed response is a Go `error` that aborts the run,
never a recorded decision. The parent and child hold two different delegation ids, so claim 1 and
claim 2 can never be served from each other's entry in `stratium-pep`'s own local decision cache,
even though both ask about the identical tool and identical arguments.

## Verifying it

```bash
cd example && go vet ./... && go build ./...
go test ./agent/...
```
