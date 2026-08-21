# Testing Stratium against a real agent

How to put this system in front of a live coding agent and watch it deny
something, using the enforcement surfaces that actually exist.

**Parts 1, 3 and 4 were executed end to end on 2026-08-20** against a live
stack, a real Claude Code hook contract, and the real
`@modelcontextprotocol/server-filesystem`. The output shown is what was
observed.

**Part 2 (Codex) was verified on 2026-08-21 against a real `codex-cli`
install** — its hook contract, config discovery and trust gate are read from
the shipped binary and from Codex's own `hooks/list`, not assumed — but no live
Codex *session* was run, for a reason given in §2f. Part 5 (Envoy) is a
configuration recipe. Both are marked where they appear.

---

## Read this first: what can and cannot be intercepted

Stratium does not integrate with a *model*. It integrates with the **harness**
that executes the model's tool calls, and it can only enforce where that harness
gives it an extension point. `stratium-pep` ships four enforcement surfaces:

| Surface | What it is | Fits |
|---|---|---|
| `hook` | A **PreToolUse hook**. Reads `tool_name`/`tool_input` on stdin; exit 0 allows, exit 2 denies with a reason. | **Coding agents with a hook system: Claude Code, Codex** |
| `mcp` | An **MCP proxy over stdio**. The harness launches it in place of a real MCP server; it spawns the real one as a child and gates `tools/call`. | **Any harness that runs a local stdio MCP server** |
| `extauthz` | A gRPC server answering Envoy's `ext_authz` `Check`. Envoy calls it before forwarding any HTTP request. | **Any agent calling an HTTP API you control** |
| `proxy` | A gRPC proxy in front of a target service. | gRPC tools |

**Sort the products by what kind of harness they are, not by who makes them.**
The vendor axis (Anthropic vs OpenAI) predicts nothing; the harness axis
predicts everything:

| Product | Class | How you get in | Part |
|---|---|---|---|
| **Claude Code** | coding agent, runs tool calls locally | `PreToolUse` hook, `.claude/settings.json` | 1 |
| **Codex** | coding agent, runs tool calls locally — OpenAI's counterpart to Claude Code, not to ChatGPT | `PreToolUse` hook, `~/.codex/hooks.json` | 2 |
| **Claude Desktop** | chat app | MCP servers **the user installs** | 4 |
| **ChatGPT desktop** | chat app | MCP servers **the user installs** (`[mcp_servers]` in `~/.codex/config.toml`) | 4 |
| **ChatGPT on the web** | chat app | remote connectors only — no local stdio | 5 |
| anything calling an HTTP API you own | — | Envoy `ext_authz` | 5 |

Two consequences worth stating before you plan around them:

- **Both coding agents hook, and they hook almost identically.** Codex's
  `PreToolUse` payload, its deny JSON, and its matcher-group config file are
  Claude Code's, deliberately. `stratium-pep hook` is a near drop-in; §2e is the
  single difference and the five-line shim that closes it.
- **Both chat apps take MCP, and neither takes a hook.** For Claude Desktop and
  ChatGPT the interception point is the *server*, not the tool call — which is
  why the `mcp` surface exists, and why it is stdio. That an MCP server has to
  be installed by a human is not a caveat, it is the trust model (§4d).

---

## Part 0 — shared prerequisites

> **There is a one-command version of everything in this Part.**
>
> ```bash
> deploy/stratium up --harness claude     # or codex, or both
> deploy/stratium run claude              # launches with the environment set
> ```
>
> It does 0a–0d plus the delegation and the hook wiring, then **ends by observing
> a real denial** rather than by reporting success — a held tool allowed, an
> unheld tool denied, asserted against the actual binary. Roughly a minute cold,
> ten seconds warm. `deploy/stratium doctor` diagnoses a broken one and names the
> fix; `deploy/stratium down` unwinds it, hooks first.
>
> Two things it deliberately does **not** do. It will not write
> `classification_caps` by SQL, so classification enforcement — Part 1c and the
> labelling plan's Part B — stays out of reach and it says so on every run. And
> run from **inside** an agent session it stops before wiring hooks, because a
> `matcher: "*"` hook takes effect in the running session immediately and that
> session was not launched with the environment the hook reads: every tool call
> would deny, including the ones you would use to undo it.
>
> Work through this Part by hand when you want to see the moving parts, or when
> you need the classification path. Use the script when you want a stack.

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

`UNIQUE (tenant_id, name)` applies, so the name carries a per-run suffix — the
same idiom the labelling plan uses for probe prefixes. Nothing downstream reads
the name; only `$AGENT` matters.

```bash
NAME="claude-code-trial-$(python3 -c 'import uuid;print(uuid.uuid4().hex[:6])')"
RESP=$(curl -sS -w '\n%{http_code}' -X POST "http://$PAP/v1/agents" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$NAME\",\"provider\":\"anthropic\",\"model_id\":\"claude\",
       \"trust_tier\":3,\"enabled\":true,\"suspended\":false,\"allowed_tools\":[]}")
echo "$RESP"
export AGENT=$(echo "$RESP" | head -1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
echo "AGENT=$AGENT"
```

**Expected** — the agent row, then `201`, then the id:

```
{"id":"0b556ec7-8a22-4c3e-bcf5-89f098c18484","tenant_id":"tenant-pap-e2e-integration","name":"claude-code-trial-318977",...}
201
AGENT=0b556ec7-8a22-4c3e-bcf5-89f098c18484
```

**PASS if** `AGENT` is a uuid. An empty `AGENT` plus a `JSONDecodeError` from
`json.load` means the POST did not return JSON at all — read the two lines
`echo "$RESP"` printed, because **both failures here are a bare word, not a JSON
error body**:

| Body | Code | What it means |
|---|---|---|
| `unauthorized` | `401` | The `$EDITOR` token aged out — five minutes. Re-run the three `tok` exports from §1 of the labelling plan and repeat this step. |
| `store: already exists: agent named "…"` | `409` | A name collision. With the suffix above this should not happen; without it, a second run of this plan always hits it. |

> An earlier draft of this step piped `curl` straight into `json.load`. Both
> failures then surfaced only as `JSONDecodeError: Expecting value: line 1
> column 1 (char 0)` — the same traceback for two unrelated causes, with the
> status code and the actual message thrown away. Print the response, then parse
> it.

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

`deploy/stratium` writes that block for you, merging into whatever the
file already holds rather than replacing it. **The harness flag is required** —
there is no default, because the two harnesses write different files and a
hook installed on the one you are not running is silently no enforcement at all:

```bash
deploy/stratium --claude --bin /tmp/stratium-pep --only PreToolUse --matcher Read install
deploy/stratium --claude status
```

**Expected:**

```
installed PreToolUse (matcher 'Read', command '/tmp/stratium-pep') in .claude/settings.json
PreToolUse matcher='Read' command='/tmp/stratium-pep hook' timeout=10
  env: missing STRATIUM_PEP_APPROVAL_POLL_INTERVAL, STRATIUM_PEP_APPROVAL_TIMEOUT, STRATIUM_PEP_CACHE_STALENESS_WINDOW
(this is the environment of this shell; what counts is the one that launches the agent)
```

**PASS if** `status` reports the hook and `env: all 8 set`. It checks two things
that both fail silently otherwise: that the command actually resolves — a
`PreToolUse` hook that cannot run exits `127`, and Claude Code lets the tool
call through on any non-zero that is not `2`, so a typo'd path is **fail-open** —
and that the environment is whole. It exits `1` if either is wrong.

> **`--only PreToolUse` matters here.** With no `--only` the script installs the
> pair `docs/pep.md` documents, and the `SessionStart` half runs `session-start`
> on every session — issuing a *fresh* delegation over the one 1a created by
> hand and 1c edited by SQL, silently undoing both. Install the pair when you
> want the real thing; install this half while walking the plan.

`stratium-pep hook` reads its configuration from the environment, so its eight
variables must be exported in the shell that launches Claude Code. Run
`session-start` (1a) first — the hook reads the session file **fresh on every
call**, so a revocation between two tool calls takes effect on the next one.

> **`hook`'s eight are not `session-start`'s eight.** They overlap in five;
> exporting 1a's block and stopping there leaves `hook` missing three, and every
> tool call denies with `missing required configuration` — a denial that reads
> exactly like a policy denial until you look at the reason. Add:
>
> ```bash
> export STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s \
>        STRATIUM_PEP_APPROVAL_TIMEOUT=120s \
>        STRATIUM_PEP_CACHE_STALENESS_WINDOW=30s
> ```
>
> `deploy/stratium --claude status` names whichever are missing, per
> event; the lists come from `session_start.go` and `hook.go`/`cache.go`, and
> its selftest fails if they drift from the binary.

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

## Part 2 — Codex

Codex is OpenAI's Claude Code — the same class of thing, a coding agent that
runs your tool calls on your machine — and **it has a hook system too**. Its
`PreToolUse` contract is Claude Code's, deliberately and almost field for field.
`stratium-pep hook` is a near drop-in.

Two things stand between "near" and "actually enforcing", and neither is
obvious: a **trust gate** that leaves a freshly installed hook not running
(§2c), and **one contract difference** that silently costs you the denial reason
(§2e).

> **Verified 2026-08-21 against `codex-cli 0.133.0`.** Everything quoted below
> came from that install: the JSON Schemas the binary itself embeds, its own
> `hooks/list` output, and its own error strings. **A live Codex session was not
> run** — see §2f.

### 2a — Turn hooks on

```bash
codex features list | grep -E '^(hooks|plugin_hooks) '
```

**Observed:**

```
hooks                                   stable             true
plugin_hooks                            stable             true
```

**PASS if** `hooks` reads `true`. If not: `codex features enable hooks`, or
`[features].hooks = true` in `~/.codex/config.toml`. If you find `codex_hooks`
in an older config, it still works but Codex now says so on every run:

```
deprecated: `[features].codex_hooks` is deprecated. Use `[features].hooks` instead.
```

### 2b — Install at **user** scope, not project scope

`~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          { "type": "command",
            "command": "/usr/local/bin/stratium-codex-hook",
            "timeout": 10 }
        ]
      }
    ]
  }
}
```

Same shape as Claude Code's `settings.json` hook block — a list of matcher
groups, each with a list of command handlers. Event keys are PascalCase
(`PreToolUse`); Codex normalises them to `pre_tool_use` internally, which is
what you will see echoed back in §2c.

**Codex also reads `<repo>/.codex/hooks.json`. Do not put an enforcement hook
there.** Project-local hooks are disabled until the project is trusted, and
Codex says so only if you ask:

```
Project-local config, hooks, and exec policies are disabled in the following
folders until the project is trusted, but skills still load.
```

For a linter that is a shrug. For a policy enforcement point it is fail-open:
the hook does not run, and every tool call proceeds unchecked. `~/.codex/hooks.json`
is always loaded.

`deploy/stratium --codex` writes that file and refuses to write any other:

```bash
deploy/stratium --codex install
deploy/stratium --codex status
```

**Expected:**

```
installed PreToolUse (matcher '*', command 'stratium-codex-hook') in /Users/you/.codex/hooks.json
PreToolUse matcher='*' command='stratium-codex-hook' timeout=10
```

`--codex` differs from `--claude` in the three ways this part has established,
and the flag carries all three rather than leaving them to you:

| | `--claude` | `--codex` |
|---|---|---|
| file | `.claude/settings.json`, or `~/…` with `--user` | `~/.codex/hooks.json`, and **only** that — a project-local path is refused, because a disabled enforcement hook is fail-open (above) |
| command | `stratium-pep hook` | `stratium-codex-hook`, bare — the shim *is* the hook and calls `stratium-pep hook` itself (2e) |
| events | `SessionStart` + `PreToolUse` | `PreToolUse` only; run `session-start` by hand (2e) |

Pointing `--codex` at the raw binary with `--bin` still works and still enforces,
but warns: Codex reads a blocking reason off stderr and `stratium-pep hook`
writes it to stdout, so you keep the denial and lose the sentence (2e).

### 2c — Confirm it is loaded **and** trusted

Codex answers this over its app-server, no session required:

```bash
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"probe","title":"probe","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"hooks/list","params":{}}'; sleep 4; } \
| codex app-server 2>/dev/null | grep '"id":2'
```

**Observed** (reformatted; one entry per discovered hook):

```json
{"id":2,"result":{"data":[{
  "cwd": "/Users/you/project",
  "hooks": [{
    "key":          "/Users/you/.codex/hooks.json:pre_tool_use:0:0",
    "eventName":    "preToolUse",
    "handlerType":  "command",
    "matcher":      "*",
    "command":      "/usr/local/bin/stratium-codex-hook",
    "timeoutSec":   10,
    "sourcePath":   "/Users/you/.codex/hooks.json",
    "source":       "user",
    "enabled":      true,
    "isManaged":    false,
    "currentHash":  "sha256:b97384dfffea48650f69136e7aaf89549d28d02aedc98e23c1c998af74c110ad",
    "trustStatus":  "untrusted"
  }],
  "warnings": [], "errors": []
}]}}
```

**PASS if** the hook appears at all, with `"source":"user"`, `"enabled":true`,
and an empty `errors`. A `"hooks":[]` here is the project-trust trap from §2b —
this is exactly what an untrusted project-local config produces.

**Then read `trustStatus`, and do not skip it.** Codex content-hashes every
hook and will not run one you have not reviewed:

```
2 new/modified hooks need review before they can run.
```

A freshly installed hook is `untrusted`, and for an enforcement hook `untrusted`
means **not enforcing**. Approve it in the TUI's `/hooks` browser and re-run the
command above until it reads `trusted`. Editing the hook script changes
`currentHash` and sends it back for review — including when you swap the
discovery hook of §2d for the real one.

This is a good property, not an obstacle: nothing can quietly replace the
enforcement hook behind the operator's back. It just has to be a step in the
install runbook rather than a surprise.

### 2d — What Codex sends, and what your catalog must already know

The payload is Claude Code's plus two fields. Required by the shipped
`pre-tool-use.command.input` schema:

```
cwd  hook_event_name  model  permission_mode  session_id
tool_input  tool_name  tool_use_id  transcript_path  turn_id
```

`stratium-pep hook` reads `tool_name` and `tool_input` and ignores everything
else, so the two Codex-only fields (`model`, `turn_id`) cost nothing.

**Tool names arrive Claude-Code-shaped**, which is the part that saves you real
work: the shell tool is `Bash`, the edit tool is `apply_patch` (which an
`Edit|Write` matcher also matches), MCP tools are `mcp__<server>__<tool>`.
So the `Bash` row already in `deploy/seed/tool-catalog-claude-code.sql` — NULL
tier, `command_field`, tier derived server-side per call — **is already the
right catalog row for Codex's shell tool**, and §1b's demonstration transfers
unchanged.

`apply_patch` is *not* in that seed. Do not guess its argument names — capture
one real payload first. Point the hook at a logger:

```sh
#!/bin/sh
# DISCOVERY ONLY — ALLOWS EVERYTHING. Do not leave this installed.
tee -a /tmp/codex-hook-payloads.jsonl > /dev/null
exit 0
```

Re-approve it (§2c), run any Codex session, and read the file: one JSON object
per tool call, each carrying the real `tool_name` and `tool_input`. Seed
`tool_catalog` from what you actually observed, the same way §0c does for Claude
Code — then put the real hook back and approve it again.

### 2e — The one contract difference: where the reason goes

| | what `stratium-pep hook` emits | what Codex accepts |
|---|---|---|
| allow | exit 0, no output | exit 0, no output — silence is consent |
| deny | exit 2, deny JSON on **stdout**, nothing on stderr | exit 0 + deny JSON on **stdout**, *or* exit 2 + reason on **stderr** |
| explicit allow | never emitted | rejected anyway: `PreToolUse hook returned unsupported permissionDecision:allow` (same for `:ask`) |
| deny with empty reason | never emitted | rejected: `…permissionDecision:deny without a non-empty permissionDecisionReason` |

The bottom two rows are traps `stratium-pep` happens to sidestep: it never emits
an explicit allow, and never denies without a reason. **Row two is the one that
bites.** Under Codex the call is still blocked — exit 2 is a block — but Codex
looks to stderr for the reason, finds an empty stream, and says so:

```
PreToolUse hook exited with code 2 but did not write a blocking reason to stderr
```

Enforcement survives; the *reason* does not. That is the sentence §1b exists to
produce, and the only thing that tells a policy denial apart from a
misconfiguration. Close it with the per-agent shim the design spec already plans
for — five lines:

```sh
#!/bin/sh
# stratium-codex-hook — `stratium-pep hook` with the deny reason also on stderr,
# which is where Codex reads it when a PreToolUse hook exits non-zero. Any
# non-zero exit is normalised to 2, Codex's block code, so a missing or crashed
# binary denies rather than falling through.
out=$(stratium-pep hook); rc=$?
[ "$rc" -eq 0 ] && exit 0
printf '%s\n' "${out:-stratium-pep: denied with no output (exit $rc)}" >&2
printf '%s' "$out"
exit 2
```

It keeps the JSON on stdout as well, which costs nothing and covers the
documented exit-0 path too. Note the shape of the guard: **the allow case is the
only one that exits 0.** Everything else — a deny, a crash, an empty response, a
binary that is not there — becomes a block, which is the same fail-closed rule
the hook itself follows (§1b's note on `missing required configuration`).

Run it against a stub `stratium-pep` before you trust it. **Observed**, with a
stub that exits 0 / exits 2 with the deny JSON / exits 3 with nothing / is
absent from `PATH` entirely:

| stub | shim exit | stdout | stderr |
|---|---|---|---|
| allows | `0` | *(empty)* | *(empty)* |
| denies | `2` | the deny JSON | the deny JSON |
| exits 3, no output | `2` | *(empty)* | `stratium-pep: denied with no output (exit 3)` |
| not installed | `2` | *(empty)* | `…command not found` + `…(exit 127)` |

**PASS if** only the first row exits 0.

What lands in Codex's block message is the whole JSON object, not just the
sentence inside it — legible, but noisy. Pipe it through a parser and print only
`permissionDecisionReason` if you would rather have it clean; that buys tidier
output at the cost of a process spawn on every denied tool call.

The eight environment variables from §1d apply here unchanged, exported in
whatever shell launches Codex. So does §1a: run `session-start` first, or every
tool call denies for want of a session.

### 2f — What was not run, and why

**No live Codex session.** Two independent blockers on the machine this was
verified on, neither of them about Stratium:

```
ERROR: You've hit your usage limit. Upgrade to Plus to continue using Codex…
ERROR: failed to refresh available models: unknown variant `max`, expected one
       of `none`, `minimal`, `low`, `medium`, `high`, `xhigh`
```

The account was rate-limited, and `0.133.0` cannot parse the current model
catalog (`codex doctor` offers `0.149.0`). So §2a–2e are the real contract read
off a real install — not a transcript of a denial reaching a model.

Two things are therefore undetermined, and only one of them matters:

- **Whether Codex, on exit 2, also honours the deny JSON on stdout.** The shim
  is written so the answer does not change the outcome either way.
- **How the block reads to the agent and to you in a live session.** Run §2a–2c,
  then repeat §1b's `rm -rf /` against Codex's `Bash` and read what comes back.
  That is the one step left, and it needs nothing but a working Codex.

---

## Part 3 — what the hook surface does *not* cover

Worth knowing before you trust a demo:

- **Only tool calls.** Anything the model does that is not a tool call is not
  seen. The hook is not a content filter.
- **Fieldless tools cannot be labelled.** `Glob`, `Grep`, `WebFetch`,
  `WebSearch` have no `resource_field`, so they produce no resource id and no
  rule matches them — not even the empty-prefix catch-all. Under a
  classification cap they **deny outright**. Test this before enabling a cap on
  a session that needs them.
- **`tools/list` is not filtered** on the MCP surface (Part 4); an agent can
  see a tool it cannot call and finds out at call time.

---

## Part 4 — Chat apps and any other MCP harness

**This is where Claude Desktop and ChatGPT both live**, and they live there for
the same reason: a chat app does not run your tool calls, it runs *tools you
installed*, and the only thing you can put yourself in front of is the server.
Neither exposes a `PreToolUse` hook. Both take local stdio MCP servers from a
config file a human writes:

| Client | Config | Verified |
|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` → `mcpServers` | present on this machine |
| ChatGPT desktop (macOS) | `~/.codex/config.toml` → `[mcp_servers.*]` — the app bundles Codex at `/Applications/ChatGPT.app/Contents/Resources/codex` and shares its config | config plumbing observed on this machine; the tool calls themselves were not exercised |
| ChatGPT on the web | remote connectors (HTTP/SSE) only — **this surface cannot help you**, see Part 5 | — |
| Codex CLI | `~/.codex/config.toml` → `[mcp_servers.*]` | — |

The `mcp` surface wraps a real MCP server. The harness launches
`stratium-pep mcp`; that process launches the true server as a child and relays
JSON-RPC both ways, calling the PDP for **`tools/call` only**.

Verified below against the real `@modelcontextprotocol/server-filesystem`.

### 4a — A session for the MCP tool names

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

### 4b — Label a path *inside* the server's own sandbox

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

### 4c — Drive it

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

### 4d — Wire it into a harness

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
something the agent supplied. "The user has to install the MCP" is the same fact
seen from the other side — the config above is written by a human with
filesystem access, and that is precisely what makes the substitution
trustworthy.

---

## Part 5 — HTTP tools behind Envoy

The surface that does not care what the agent is. If a tool is reached through
an HTTP API **you** control — a ChatGPT custom-GPT action, a function whose
implementation is your service, an agent framework calling your endpoint, a web
client with no local anything — put Envoy in front of it with `ext_authz`
pointed at `stratium-pep extauthz`. Every request is checked before it is
forwarded.

This is the only route for **ChatGPT in a browser**: web connectors speak
HTTP/SSE, `stratium-pep mcp` speaks stdio, and there is no remote-MCP mode. It
is also the right route whenever the caller is not a harness you can install
anything into.

The compose stack already runs this shape: `envoy` (port 10000) → `ext_authz` →
`pep-extauthz` (9191) → `echo-upstream`. Use `deploy/docker/envoy.yaml` as the
worked example.

**What it costs you:** the PDP sees an HTTP request, not a tool call with named
arguments, so tier derivation and resource labelling are only as good as what
`decideRequestFromCheck` can extract from the method, path and body. Expect to
catalog the endpoint as a "tool" and choose a `resource_field` deliberately.

**What will not work, in any configuration:**

- **Pointing a web connector at `stratium-pep mcp`.** It speaks stdio, not
  HTTP/SSE.
- **Expecting `Bash`-style interception inside a hosted sandbox.** ChatGPT's
  code interpreter runs on OpenAI's machines; nothing local sees those calls.
  The same is true of any cloud-executed agent — the hook surface needs the tool
  call to happen on a machine you own.

---

## What this proves, and what it does not

**Proven live:**

- A real Claude Code hook contract denies `rm -rf /` and allows `ls -la` through
  the *same* tool, with the tier derived server-side.
- A resource-label rule registered through the admin API changes what a live
  agent may read, one call later.
- A real third-party MCP server is gated at `tools/call`, with a denial the
  agent receives as a JSON-RPC error.

**Verified against a real `codex-cli`, but not run (Part 2):**

- That Codex has a `PreToolUse` hook whose payload, deny JSON and config format
  are Claude Code's — read from the schemas the binary embeds.
- That a hook installed at user scope is discovered, and reports back
  `trustStatus: untrusted` until reviewed.
- That `stratium-pep hook` needs a five-line shim, and exactly why: Codex reads
  the block reason from stderr on exit 2. The shim itself **was** run, against a
  stub, and denies on all four failure shapes (§2e).

**Not proven, and not claimed:**

- A live Codex session denying anything. §2f names the two blockers.
- Anything about ChatGPT's own tool calls. Part 4's ChatGPT row is config
  plumbing observed on one machine; Part 5 is analysis of the surfaces.
- Any behaviour of a real Claude Code session — 1d is a configuration recipe;
  1a–1c are what was executed.
- Approval flows. A tool call that escalates rather than denies will block on a
  human approval; none was exercised here.
- Performance. Every tool call is a synchronous PDP round trip.

## Cleaning up

Tearing the stack down takes the agent rows with it — `-v` drops the volume, so
nothing below is needed if you are done for the day:

```bash
docker compose -f deploy/docker/docker-compose.yml down -v --remove-orphans
rm -f /tmp/stratium-pep /tmp/stratium-session.json /tmp/stratium-mcp-session.json \
      /tmp/mcp-frames.jsonl
rm -rf /tmp/mcp-sandbox
```

Remove the `PreToolUse` hook from your Claude Code settings (1d) and from
`~/.codex/hooks.json` (2b) if you added them — each denies every tool call in
its harness once the stack is down.

```bash
deploy/stratium --claude uninstall  # .claude/settings.json, or --user
deploy/stratium --codex uninstall   # ~/.codex/hooks.json, if you did 2b
```

Each removes only entries whose command names `stratium-pep` or
`stratium-codex-hook`, then prunes the containers that leaves empty, so an
unrelated hook of your own in the same `PreToolUse` array survives. `status`
afterwards should print `no Stratium hooks` and exit `1`.

### Keeping the stack, dropping the agent rows

Every rerun of 0d leaves another agent behind. To clear them without a teardown
— note **`$ADMIN`, not `$EDITOR`**; delete is the one agent route that requires
the admin role, and an editor token gets a bare `forbidden` and `403`:

> **Only run this between passes, never during one.** It matches on the name
> prefix, and the `409` guard below protects a row *only once a delegation
> exists against it*. An agent created by 0d but not yet used by 1a is in the
> one window where nothing references it — the loop deletes it, and the next
> `session-start` fails with `rpc error: code = NotFound desc = agent …: not
> found`. Re-run 0d and re-export `$AGENT` if that happens.

```bash
for id in $(curl -sS -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents" \
  | python3 -c 'import json,sys
for a in json.load(sys.stdin):
    if a["name"].startswith("claude-code-trial"): print(a["id"])'); do
  curl -sS -o /dev/null -w "$id %{http_code}\n" -X DELETE \
    -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents/$id"
done
```

**Expected** — `204` per row, except the one you actually exercised:

```
3422a63e-4ce5-4339-bfac-d6887594651d 409
0b556ec7-8a22-4c3e-bcf5-89f098c18484 204
59d7c9d8-edf9-45b9-b6b3-9d47aaa062ac 204
```

> **The agent this plan just tested cannot be deleted, by design.** Once
> `session-start` has issued a delegation against it, `DELETE` returns `409`
> `store: conflict: agent … is still referenced by a delegation or approval`.
> `delegations.agent_id` and `approvals.agent_id` are both `ON DELETE RESTRICT`
> (`services/migrations/000001_baseline.up.sql:37` and
> `000012_approvals.up.sql:16`), so the database refuses it and the store
> maps the foreign-key violation to a `409` rather than a `500` — see
> `services/internal/store/agent.go:312`. Clear the delegations first, or just
> use `down -v`.
