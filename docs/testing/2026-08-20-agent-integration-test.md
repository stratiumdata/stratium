# Testing Stratium against a real agent

How to put this system in front of a live coding agent and watch it deny
something, using the enforcement surfaces that actually exist.

**Everything in Parts 1–3 was executed end to end on 2026-08-20** against a
live stack, a real Claude Code hook contract, and the real
`@modelcontextprotocol/server-filesystem`. The output shown is what was
observed. Part 4 (ChatGPT) is the honest exception and is marked as such.

---

## Read this first: what can and cannot be intercepted

Stratium does not integrate with a *model*. It integrates with the **harness**
that executes the model's tool calls, and it can only enforce where that harness
gives it a hook. `stratium-pep` ships four enforcement surfaces:

| Surface | What it is | Fits |
| --- | --- | --- |
| `hook` | A **Claude Code PreToolUse hook**. Reads `tool_name`/`tool_input` on stdin; exit 0 allows, exit 2 denies with a reason. | **Claude Code** |
| `mcp` | An **MCP proxy over stdio**. The harness launches it in place of a real MCP server; it spawns the real one as a child and gates `tools/call`. | **Any harness that runs a local stdio MCP server** |
| `extauthz` | A gRPC server answering Envoy's `ext_authz` `Check`. Envoy calls it before forwarding any HTTP request. | **Any agent calling an HTTP API you control** |
| `proxy` | A gRPC proxy in front of a target service. | gRPC tools |

**The consequence for the two products in the title is asymmetric, and worth
being blunt about:**

- **Claude Code** has a first-class integration — the `hook` surface exists
  specifically for it, and it intercepts *every* tool call including `Bash`.
- **ChatGPT** has **no equivalent**. There is no ChatGPT tool-call hook, and this
  project ships nothing ChatGPT-specific. What you can do is gate the *tools it
  reaches*: an MCP server (Part 3, if your client runs local stdio MCP) or an
  HTTP API behind Envoy (Part 4). See Part 4 before planning around it.

---

## Part 0 — shared prerequisites

Bring the stack up and set the environment exactly as in the resource-labelling
plan (`docs/testing/2026-08-19-resource-labelling-manual-test.md`, §0 and §1) —
`dc`, `psqlm`, `$PAP`, `$PDP`, `$TENANT`, and an `$EDITOR` token. Then:

### 0a — Build the PEP

```bash
cd services && go build -o /tmp/stratium-pep ./cmd/stratium-pep && cd ..
```

### 0b — A policy that lets your principal hold tools

**Without this, nothing else works.** `session-start` calls `CreateDelegation`,
which is clamped by what the *principal* may delegate; with no policy it fails
with `none of the requested tools are held by this principal`.

```bash
curl -sS -w '\n%{http_code}\n' -X POST "http://$PAP/v1/policies" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"agent-trial-grant","description":"grant for an agent session",
       "language":"rego","effect":"deny","enabled":true,
       "policy_content":"package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"agent-tester@example.com\"\n}"}'
```

**Expected:** `201`, echoing the policy back.

> **`"effect"` must be `"deny"` for a Rego policy**, and that is not a typo. A
> Rego policy can produce either outcome depending on the request, so the column
> holds a fixed placeholder a display screen must not read as behaviour. Sending
> `"allow"` returns a `400` that says exactly this.

### 0c — Seed the tool catalog for the agent you are testing

The catalog is what tells the PDP how to read a tool's arguments — which field
is the resource, which is the command. Two seeds ship:

```bash
# Claude Code's twelve built-in tools
dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
  psql -h 127.0.0.1 -U stratium_migrate -d stratium -v tenant_id="$TENANT" -q \
  -f /dev/stdin < deploy/seed/tool-catalog-claude-code.sql

# @modelcontextprotocol/server-filesystem's tools
dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres \
  psql -h 127.0.0.1 -U stratium_migrate -d stratium -v tenant_id="$TENANT" -q \
  -f /dev/stdin < deploy/seed/tool-catalog-mcp-filesystem.sql
```

**PASS if** the row count rises:

```bash
psqlm -tAc "SELECT set_config('app.tenant_id','$TENANT',false);
            SELECT count(*) FROM tool_catalog;" | tail -1
```

Claude Code's seed alone gives `12`. Note two things in it that matter later:

- `Read` uses `file_path`, not `path`.
- `Glob`, `Grep`, `WebFetch`, `WebSearch` and `TodoWrite` have **no**
  `resource_field` — deliberately. They cannot be resource-labelled at all.
- `Bash` has **no tier** and a `command_field` instead: its tier is derived from
  the command text, server-side, per call.

### 0d — An agent row

```bash
export AGENT=$(curl -sS -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"claude-code-trial","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":false,"allowed_tools":[]}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "AGENT=$AGENT"
```

Use a **fresh `name`** on each run — `UNIQUE (tenant_id, name)` applies.

---

## Part 1 — Claude Code, by hand

Prove the hook works before wiring it into a real session. Everything here is
exactly what Claude Code itself will do.

### 1a — Start a session

```bash
export SESSION=/tmp/stratium-session.json
STRATIUM_PEP_PDP_ADDR="$PDP" \
STRATIUM_PEP_AGENT_ID="$AGENT" \
STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
STRATIUM_PEP_SESSION_FILE="$SESSION" \
STRATIUM_PEP_CONNECT_TIMEOUT=5s \
STRATIUM_PEP_REQUESTED_TOOLS="Read,Grep,Glob,Write,Bash" \
STRATIUM_PEP_REQUESTED_TIER=3 \
STRATIUM_PEP_PURPOSE="agent trial" \
STRATIUM_PEP_TTL_SECONDS=3600 \
/tmp/stratium-pep session-start; echo "exit=$?"
cat "$SESSION"
```

**Expected** — `exit=0` and a session file holding the *granted* scope (which
may be narrower than requested) plus a token:

```json
{
  "delegation_id": "9031097c-45fd-4265-a4f4-9e90994a9825",
  "granted_scope": { "max_action_tier": 3,
                     "tools": ["Read","Grep","Glob","Write","Bash"] },
  "token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**PASS if** `granted_scope.tools` is non-empty. An empty list, or
`none of the requested tools are held by this principal`, means 0b's policy is
missing or its `subject` does not match `STRATIUM_PEP_SUBJECT`.

### 1b — Call the hook directly

```bash
hook() {
  echo "$1" | STRATIUM_PEP_PDP_ADDR="$PDP" STRATIUM_PEP_AGENT_ID="$AGENT" \
    STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
    STRATIUM_PEP_SESSION_FILE="$SESSION" \
    STRATIUM_PEP_CONNECT_TIMEOUT=5s \
    STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s STRATIUM_PEP_APPROVAL_TIMEOUT=30s \
    STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s \
    /tmp/stratium-pep hook
  echo "  exit=$?"
}

hook '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.txt"}}'
hook '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'
hook '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'
hook '{"tool_name":"Write","tool_input":{"file_path":"/tmp/x.txt","content":"hi"}}'
```

**Expected** — three silent allows and one denial:

```
  exit=0
  exit=0
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"action tier DESTRUCTIVE exceeds delegation max_action_tier EXTERNAL_COMMS at depth 0"}}
  exit=2
  exit=0
```

**PASS if** lines 2 and 3 differ. **That pair is the whole demonstration**: both
are the *same tool* with the same delegation, and the only difference is the
command text. `ls -la` derives READ_ONLY and passes; `rm -rf /` derives
DESTRUCTIVE and is refused. The tier is computed **in the PDP** from
`raw_input` — the hook sends the arguments verbatim and classifies nothing, so
there is no local rule to bypass.

> **If every call denies with `missing required configuration: …`**, add the
> variables it names. The hook needs eight, and a missing one **fails closed
> with the reason on stdout** rather than allowing. That is correct behaviour,
> and it is why the reason text matters: a configuration failure and a policy
> denial look different.

### 1c — Make it enforce a classification

This is where the resource-labelling feature meets a real agent.

```bash
for r in '{"prefix":"","hierarchy":"nato","level":"UNCLASSIFIED"}' \
         '{"prefix":"/secret/","hierarchy":"nato","level":"SECRET"}'; do
  curl -sS -o /dev/null -w "  rule -> %{http_code}\n" \
    -X POST "http://$PAP/v1/resource-label-rules" \
    -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' -d "$r"
done

DELEG=$(python3 -c "import json;print(json.load(open('$SESSION'))['delegation_id'])")
psqlm -q -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
  UPDATE delegations SET classification_caps='{\"nato\":\"CONFIDENTIAL\"}'
  WHERE id='$DELEG'; COMMIT;"

hook '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.txt"}}'
hook '{"tool_name":"Read","tool_input":{"file_path":"/secret/plans.txt"}}'
```

**Expected:**

```
  rule -> 201
  rule -> 201
  exit=0
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"}}
  exit=2
```

**PASS if** the two `Read` calls differ. Same tool, same session — the path is
the only variable, and the label came from a rule registered through the admin
API seconds earlier.

> The cap is set with SQL because **no route can set one**. See the
> resource-labelling plan's §0. This is the single largest gap in the feature
> and is recorded in the spec's open items.

### 1d — Wire it into a real Claude Code session

Add a `PreToolUse` hook to your Claude Code settings, with the eight variables
in its environment. In `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command", "command": "stratium-pep hook", "timeout": 10 }
        ]
      }
    ]
  }
}
```

**Keep the `timeout`.** Every tool call becomes a synchronous round trip to the
PDP; without one, an unreachable PDP hangs the session instead of failing.

`stratium-pep hook` reads its configuration from the environment, so those eight
variables must be exported in the shell that launches Claude Code. Run
`session-start` (1a) first — the hook reads the session file **fresh on every
call**, so a revocation between two tool calls takes effect on the next one.

> `docs/pep.md` is the operator reference for this surface and covers
> installation, every configuration value, and a "Reading a denial" section for
> telling a policy denial apart from a misconfiguration. It also states the rule
> worth internalising before you panic: **every tool call is denied until a
> session is started and a policy permits it** — so if you install the hook and
> see everything denied, that is most likely correct behaviour for an agent with
> no session, not a bug.

**PASS if** asking Claude to read `/secret/plans.txt` produces a refusal quoting
the classification reason, while reading another file succeeds. Claude will
surface `permissionDecisionReason` as the reason it could not proceed.

**Start with a narrow `matcher`** (`"Read"`) rather than `"*"` on a session you
care about: every tool call becomes a synchronous round trip to the PDP, and a
misconfigured hook denies everything.

---

## Part 2 — what the hook does *not* cover

Worth knowing before you trust a demo:

- **Only tool calls.** Anything the model does that is not a tool call is not
  seen. The hook is not a content filter.
- **Fieldless tools cannot be labelled.** `Glob`, `Grep`, `WebFetch`,
  `WebSearch` have no `resource_field`, so they produce no resource id and no
  rule matches them — not even the empty-prefix catch-all. Under a
  classification cap they **deny outright**. Test this before enabling a cap on
  a session that needs them.
- **`tools/list` is not filtered** on the MCP surface (Part 3); an agent can
  see a tool it cannot call and finds out at call time.

---

## Part 3 — Any MCP harness (Claude Desktop, Claude Code, others)

The `mcp` surface wraps a real MCP server. The harness launches
`stratium-pep mcp`; that process launches the true server as a child and relays
JSON-RPC both ways, calling the PDP for **`tools/call` only**.

Verified below against the real `@modelcontextprotocol/server-filesystem`.

### 3a — A session for the MCP tool names

The tool names are the *upstream server's*, not Claude Code's:

```bash
mkdir -p /tmp/mcp-sandbox/classified
echo hello > /tmp/mcp-sandbox/notes.txt
echo "top secret plans" > /tmp/mcp-sandbox/classified/plans.txt

export MCP_SESSION=/tmp/stratium-mcp-session.json
STRATIUM_PEP_PDP_ADDR="$PDP" STRATIUM_PEP_AGENT_ID="$AGENT" \
STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
STRATIUM_PEP_SESSION_FILE="$MCP_SESSION" \
STRATIUM_PEP_CONNECT_TIMEOUT=5s \
STRATIUM_PEP_REQUESTED_TOOLS="read_text_file,write_file,list_directory" \
STRATIUM_PEP_REQUESTED_TIER=3 STRATIUM_PEP_PURPOSE="mcp trial" \
STRATIUM_PEP_TTL_SECONDS=3600 \
/tmp/stratium-pep session-start && echo "exit=0"
```

**Expected:** `granted: ['read_text_file', 'write_file', 'list_directory']`

### 3b — Label a path *inside* the server's own sandbox

This is the important detail. The filesystem server refuses anything outside its
allowed directory on its own — so to prove **Stratium** denied something, the
path must be one the upstream server would happily have served.

```bash
curl -sS -o /dev/null -w "  rule -> %{http_code}\n" \
  -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"prefix":"/tmp/mcp-sandbox/classified/","hierarchy":"nato","level":"SECRET"}'

MDELEG=$(python3 -c "import json;print(json.load(open('$MCP_SESSION'))['delegation_id'])")
psqlm -q -c "BEGIN; SELECT set_config('app.tenant_id','$TENANT',true);
  UPDATE delegations SET classification_caps='{\"nato\":\"CONFIDENTIAL\"}'
  WHERE id='$MDELEG'; COMMIT;"
```

### 3c — Drive it

```bash
cat > /tmp/mcp-frames.jsonl <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"trial","version":"1"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/tmp/mcp-sandbox/notes.txt"}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/tmp/mcp-sandbox/classified/plans.txt"}}}
EOF

{ cat /tmp/mcp-frames.jsonl; python3 -c "import time; time.sleep(25)"; } \
| STRATIUM_PEP_PDP_ADDR="$PDP" STRATIUM_PEP_AGENT_ID="$AGENT" \
  STRATIUM_PEP_SUBJECT="agent-tester@example.com" \
  STRATIUM_PEP_SESSION_FILE="$MCP_SESSION" \
  STRATIUM_PEP_CONNECT_TIMEOUT=5s STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s \
  STRATIUM_PEP_APPROVAL_TIMEOUT=30s STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s \
  STRATIUM_PEP_MCP_UPSTREAM_COMMAND="npx" \
  STRATIUM_PEP_MCP_UPSTREAM_ARGS="-y,@modelcontextprotocol/server-filesystem,/tmp/mcp-sandbox" \
  /tmp/stratium-pep mcp 2>/dev/null
```

**Expected** — `id=2` returns the file, `id=3` returns a JSON-RPC **error**:

```
id=1 initialize -> ok
id=3 DENIED: resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
id=2 ALLOWED: {"content": [{"type": "text", "text": "hello\n"}], ...}
```

**PASS if** `id=2` returns `hello` and `id=3` is an error naming the
classification. Responses arrive **out of order** — that is correct, the relay
is concurrent.

> The trailing `sleep` keeps stdin open. Closing it immediately shuts the proxy
> down before the gated calls complete, and you see only `id=1`. A real harness
> holds the pipe open for the session's life.

### 3d — Wire it into a harness

Replace the real MCP server's command with `stratium-pep mcp`, moving the
original into `STRATIUM_PEP_MCP_UPSTREAM_COMMAND`/`_ARGS`. In an
MCP client config:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "/tmp/stratium-pep",
      "args": ["mcp"],
      "env": {
        "STRATIUM_PEP_MCP_UPSTREAM_COMMAND": "npx",
        "STRATIUM_PEP_MCP_UPSTREAM_ARGS": "-y,@modelcontextprotocol/server-filesystem,/tmp/mcp-sandbox",
        "STRATIUM_PEP_PDP_ADDR": "localhost:PORT",
        "STRATIUM_PEP_AGENT_ID": "…",
        "STRATIUM_PEP_SUBJECT": "agent-tester@example.com",
        "STRATIUM_PEP_SESSION_FILE": "/tmp/stratium-mcp-session.json",
        "STRATIUM_PEP_CONNECT_TIMEOUT": "5s",
        "STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "2s",
        "STRATIUM_PEP_APPROVAL_TIMEOUT": "30s",
        "STRATIUM_PEP_CACHE_STALENESS_WINDOW": "5s"
      }
    }
  }
}
```

**The trust model depends on the harness launching this process, not the agent.**
That is why the surface is stdio and not HTTP: the session file it reads is not
something the agent supplied.

---

## Part 4 — ChatGPT

**This part was not executed.** Everything above ran; this did not, and the
reason is the finding.

**There is no ChatGPT tool-call hook.** Claude Code exposes a `PreToolUse`
extension point and this project implements it; ChatGPT exposes no equivalent,
and nothing here is ChatGPT-specific. So you cannot intercept ChatGPT's tool
calls the way Part 1 intercepts Claude Code's. Any document claiming otherwise
is describing something that does not exist.

What you *can* do is gate what it reaches. Two routes, in order of confidence:

### 4a — HTTP tools behind Envoy (works regardless of client)

If ChatGPT reaches a tool through an HTTP API you control — a custom GPT action,
a function whose implementation is your service, an agent framework calling your
endpoint — put Envoy in front of it with `ext_authz` pointed at
`stratium-pep extauthz`. Every request is checked before it is forwarded.

The compose stack already runs this shape: `envoy` (port 10000) → `ext_authz` →
`pep-extauthz` (9191) → `echo-upstream`. Use `deploy/docker/envoy.yaml` as the
worked example.

**This does not depend on ChatGPT at all** — it enforces at your API, so it works
for any caller. It is the route to plan around.

**What it costs you:** the PDP sees an HTTP request, not a tool call with named
arguments, so tier derivation and resource labelling are only as good as what
`decideRequestFromCheck` can extract from the method, path and body. Expect to
catalog the endpoint as a "tool" and choose a `resource_field` deliberately.

### 4b — MCP, if your client runs local stdio servers

Part 3's proxy is protocol-level, not client-specific: **it works with any client
that launches a local stdio MCP server.** If your ChatGPT client does, it will
work there too, unchanged.

**Verify that before designing around it**, because two things must both hold:
the client must support MCP *and* support **local stdio** servers rather than
only remote HTTP/SSE connectors. This proxy is stdio-only by design — the trust
model in 3d depends on it. A remote-MCP-only client cannot use it.

The check: configure it exactly as in 3d and see whether the client lists the
tools. If it does, Part 3's test applies verbatim.

### 4c — What will not work

- **Pointing ChatGPT's web connectors at `stratium-pep mcp`.** It speaks stdio,
  not HTTP/SSE. There is no remote-MCP mode.
- **Expecting `Bash`-style interception.** ChatGPT's own code interpreter runs
  in OpenAI's sandbox; nothing local sees those calls.

---

## What this proves, and what it does not

**Proven live:**

- A real Claude Code hook contract denies `rm -rf /` and allows `ls -la` through
  the *same* tool, with the tier derived server-side.
- A resource-label rule registered through the admin API changes what a live
  agent may read, one call later.
- A real third-party MCP server is gated at `tools/call`, with a denial the
  agent receives as a JSON-RPC error.

**Not proven, and not claimed:**

- Anything about ChatGPT. Part 4 is analysis of the surfaces, not a test result.
- Any behaviour of a real Claude Code session — 1d is a configuration recipe;
  1a–1c are what was executed.
- Approval flows. A tool call that escalates rather than denies will block on a
  human approval; none was exercised here.
- Performance. Every tool call is a synchronous PDP round trip.

## Cleaning up

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
rm -f /tmp/stratium-pep /tmp/stratium-session.json /tmp/stratium-mcp-session.json \
      /tmp/mcp-frames.jsonl
rm -rf /tmp/mcp-sandbox
```

Remove the `PreToolUse` hook from your Claude Code settings if you added it in
1d — it denies every tool call once the stack is down.
