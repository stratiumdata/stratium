# `stratium-pep hook`

A `PreToolUse` hook for coding agents. The harness invokes it before every tool
call, hands it the call on stdin, and honours what it answers.

The harnesses' hook contracts differ, so the hook is told which one is calling
it: `stratium-pep hook --harness codex`. Without the flag it speaks Claude
Code's.

| Harness | `--harness` | How it is wired | Run in a live session |
|---|---|---|---|
| [Antigravity CLI](harnesses/antigravity.md) | `antigravity` | `PreToolUse` hook | yes, 1.5.14; see its page for what was observed |
| [Claude Code](harnesses/claude-code.md) | (none) | `PreToolUse` hook | yes, 2.1.329; see its page for what was observed |
| [Codex](harnesses/codex.md) | `codex` | `PreToolUse` hook | no: read from source at 0.133.0 |
| [Copilot CLI](harnesses/copilot.md) | `copilot` | `preToolUse` hook | yes, 1.0.114; see its page for what was observed |
| [Cursor](harnesses/cursor.md) | `cursor` | `preToolUse` hook | yes, CLI 2026.11.19; see its page for what was observed |
| [Devin](harnesses/devin.md) | `devin` | `PreToolUse` hook | yes, CLI 3000.14; see its page for what was observed |
| [Goose](harnesses/goose.md) | `goose` | `PreToolUse` hook in a plugin | yes, 1.60.2; see its page for what was observed |
| [Kiro CLI](harnesses/kiro.md) | `kiro` | `PreToolUse` hook | yes, 3.5.0 on the v3 engine; see its page for what was observed |
| [OpenCode 2.x](harnesses/opencode.md) | `opencode` | a plugin that runs the hook | yes, 2.3.2; see its page for what was observed |

---

## Where it sits

```
agent decides to call Read
        │
        ▼
  stratium-pep hook   ◀── reads the session file, fresh, every call
        │
        ├── exit 0, silent            ──▶  the tool runs
        └── exit 2 + deny JSON stdout ──▶  the call is blocked, reason shown to the model
```

It is invoked **per tool call**, as a new process each time. Everything it needs
comes from the environment and the session file.

---

## Configuration

Seven variables. Run it with none and it tells you which — **observed**, and
note the answer is a *deny*, not a crash:

```
$ echo '{}' | stratium-pep hook
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"stratium-pep: missing required configuration:
STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID, STRATIUM_PEP_SUBJECT,
STRATIUM_PEP_SESSION_FILE, STRATIUM_PEP_CONNECT_TIMEOUT,
STRATIUM_PEP_APPROVAL_POLL_INTERVAL, STRATIUM_PEP_APPROVAL_TIMEOUT"}}
$ echo $?
2
```

**A misconfigured hook denies.** It does not fall through, and it does not
crash — fail-closed is the whole design.

| Variable | Example | Notes |
|---|---|---|
| `STRATIUM_PEP_PDP_ADDR` | `localhost:50051` | |
| `STRATIUM_PEP_AGENT_ID` | `0f8f833a-…` | Must match the agent the session file was issued to. |
| `STRATIUM_PEP_SUBJECT` | `you@example.com` | |
| `STRATIUM_PEP_SESSION_FILE` | `/run/stratium/session.json` | Written by [`session-start`](session-start.md). |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | `5s` | gRPC dial only. |
| `STRATIUM_PEP_PDP_CA_FILE` | `/etc/stratium/pdp-ca.pem` | Optional. PEM CA bundle to verify the PDP's TLS certificate with, instead of the system roots. |
| `STRATIUM_PEP_PDP_INSECURE` | `true` | Optional. Plaintext connection to the PDP, for a local development stack only. Default is TLS. Conflicts with `STRATIUM_PEP_PDP_CA_FILE`. |
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | `2s` | How often to re-check a pending approval. |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | `120s` | How long to hold a call open awaiting one. |

> **These seven are not `session-start`'s eight.** They share five. The two
> here that `session-start` does not want are the approval durations; the three
> it wants that this does not are `REQUESTED_TIER`, `REQUESTED_TOOLS` and
> `TTL_SECONDS`. Export both sets (ten in total) in whatever shell launches
> the agent.

**`--config <file>` pins the configuration.** `stratium-pep hook --config
/etc/stratium/pep.env` reads `STRATIUM_PEP_NAME=value` lines from the file and
ignores every `STRATIUM_PEP_*` variable in the environment, including optional
ones the file leaves out. It also drops the proxy and certificate-trust
variables (`HTTPS_PROXY`, `SSL_CERT_FILE` and the like, `GODEBUG`, `GRPC_*`),
so the PDP connection goes where the file says and trusts what the file says. `session-start` takes the same
flag. A file that is missing or malformed is a deny. See
[What the install protects](#what-the-install-protects) for why you would want
it.

**`hook` has no decision cache.** It asks the PDP on every call, so a PDP
outage denies immediately. It ignores `STRATIUM_PEP_CACHE_STALENESS_WINDOW` if
that is set; only [`mcp`](mcp.md) reads it.

---

## Installing in any harness

Each harness has its own hook file and its own install command; its page has
both. Two rules hold for every one of them.

**Use an absolute path.** A bare `stratium-pep` that is not on `PATH` exits
`127`, and a harness treats any non-zero that is not `2` as a *non-blocking*
error — the tool call proceeds unchecked. A hook that cannot run is not a broken
enforcement point, it is **no enforcement point**.

**Set the `PreToolUse` `timeout` above the hook's own time budget.** The
`timeout` is the harness's budget for the hook process, in seconds. A harness
that gives up on a hook treats it as a non-blocking error and **runs the tool
call**, so a `timeout` that expires while the hook is still waiting for an
approval lets the call through.

The hook always answers within

```text
STRATIUM_PEP_APPROVAL_TIMEOUT + 4 × STRATIUM_PEP_CONNECT_TIMEOUT
```

and denies if it reaches that point without a decision. With a 120s approval
timeout and a 5s connect timeout that is 120s + 4 × 5s = 140s, so a `timeout`
of `150` leaves a margin. If you raise either variable, raise the `timeout`
with it. `deploy/stratium install` computes the value from the two variables in
its environment, and `status` and `doctor` report a `timeout` that is too short.

---

## What the install protects

The hook governs an agent that runs as you. Anything you can write, the agent
can write. A per-project or per-user install therefore leaves three things
within the agent's reach:

| What | Where a per-project or per-user install puts it | What changing it does |
|---|---|---|
| The hook entry | the harness's hook file, such as `.claude/settings.json` | Removing it removes enforcement, immediately. |
| The binary | wherever `--bin` points | Replacing it replaces the decision. |
| The configuration | the environment, which a project settings file can set | Pointing `STRATIUM_PEP_PDP_ADDR` elsewhere changes who decides. |

A per-project install is the right choice for trying Stratium out, and for an
agent you trust not to edit its own guard rails. It does not hold against an
agent that is trying to get out. `deploy/stratium status` and `doctor` print a
warning naming each of the three that the current user can change.

**The system install** puts all three where only root can write: the binary in
`/opt/stratium/bin/stratium-pep`, the configuration in `/etc/stratium/pep.env`
(read through `--config`), and the hook entry wherever that harness reads an
administrator's hooks. Where that is, and what it does and does not stop, is
on each harness's page:

- [Claude Code](harnesses/claude-code.md#the-system-install)
- [Codex](harnesses/codex.md#the-system-install)
- [Copilot CLI](harnesses/copilot.md#can-the-agent-remove-it)
- [Cursor](harnesses/cursor.md#can-the-agent-remove-it)
- [OpenCode](harnesses/opencode.md#the-system-install)

Antigravity CLI, Devin, Goose and Kiro CLI have no system install; their pages
say why.

What the system install does not change, for any harness:

- **The session file stays writable by you.** It holds the agent's own
  delegation, which the PDP checks on every call. Deleting or corrupting it
  denies every call; it cannot widen what the agent may do.
- **The configuration is machine-wide.** Every user of the machine gets the
  agent id and subject recorded in `pep.env`.
- **The binary and the configuration are shared** between the harnesses'
  system installs. `uninstall --system` for one harness keeps both while
  another harness's hook file still runs the binary.
- **A user with `sudo` can undo it**, and so can an agent that is given `sudo`.
- **A hook is a guard rail the harness chooses to run.** Launch options that
  skip hooks are the harness's to define, and what each harness page lists is
  what was tested, not a guarantee. A boundary that does not depend on
  the harness needs the thing being protected to be out of the agent's reach:
  run [`proxy`](proxy.md) or [`extauthz`](extauthz.md) as a different user or
  on a different host, in front of a service the agent has no other route to.

---

## Reporting tool calls

`stratium-pep hook` asks the PDP before a tool call. `stratium-pep report`
tells the PDP after one that it ran. It is installed on Claude Code's
`PostToolUse` and `PostToolUseFailure` events (a tool call that fails still
ran) and on Codex's `PostToolUse` event, and needs three of the hook's
variables: `STRATIUM_PEP_PDP_ADDR`,
`STRATIUM_PEP_SESSION_FILE` and `STRATIUM_PEP_CONNECT_TIMEOUT`.

The PDP looks for the ALLOW it recorded for that session, that tool and
exactly that input. If there is one, nothing happens. If there is none, the
tool call ran without being decided, and the PDP:

- appends an audit entry with `event_type` `unmatched_tool_use`, naming the
  delegation, the agent, the tool and the input's fingerprint;
- logs `tool call ran without an ALLOW decision` at error level;
- counts it against the delegation: `GET /v1/delegations` returns
  `unmatched_tool_uses`, and the Delegations screen marks the session
  `N undecided`.

A session that is governed properly produces none. One or more means the
decision hook did not run for a call that went ahead: its entry was removed or
narrowed, the harness gave up on it, or something changed the input after the
decision. [Stop the session](../journeys/stop-an-agent.md), then
[investigate](../journeys/investigate.md).

`report` never blocks and never changes a decision; the call it describes is
over. If it cannot reach the PDP it prints one line to stderr and exits `0`.

What it does not tell you:

- **Nothing, if neither hook runs.** An agent that can remove the decision hook
  can remove this one too. Only an install the agent cannot edit
  ([What the install protects](#what-the-install-protects)) keeps both.
- **A report is lost** if the PDP is unreachable when the tool finishes.
- **Keep the two matchers the same.** A `PostToolUse` matcher wider than the
  `PreToolUse` one reports calls the decision hook was never asked about.
  `deploy/stratium install` writes the same matcher to both.
- **The reporter holds the session's token**, so an agent can file reports for
  calls that never ran. That can only raise the count, never lower it.
- **Codex reports only tool calls that succeeded.** It has no event for a tool
  call that failed, so one that ran undecided and failed is not counted.
- **The [`mcp`](mcp.md) surface does not report.**

---

## What a denial looks like

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"}}
```

Four unrelated causes all exit `2`, so read the reason, never the code:

| Reason contains | Cause |
|---|---|
| `not in delegation approved_tools` | The tool is not in the grant. |
| `exceeds delegation max_action_tier` | The tool's tier is above the ceiling. |
| `exceeds delegation cap` | Classification: the resource is above the cap. |
| `missing required configuration` | Not a policy decision at all — the environment. |

---

## Traps

- **Everything denies until a session exists.** Installing the hook and seeing
  every call refused is usually correct behaviour, not a bug.
- **Installation takes effect in a running session immediately** — so does
  removal, by you or by the agent: see
  [What the install protects](#what-the-install-protects). Installing a `matcher: "*"` hook from inside a session you are using
  gags it on the next call.
- **Fieldless tools deny under any cap.** `Glob`, `Grep`, `WebFetch`,
  `WebSearch` and `TodoWrite` declare no resource field, so nothing can be
  labelled and the cap cannot be evaluated.
- **`Bash` is checked by the paths in its command.** It is catalogued with a
  command field and no resource field, so its tier is derived from the command
  text. Under a classification cap the PDP labels every path-like word in the
  command and applies the strictest label: `Bash(cat /tmp/secret-plans.txt)`
  is refused under a cap that file exceeds, as `Read` of it would be.
- **A command that names no path is refused under any cap.** `ls -la`,
  `git status` and `echo hi` give the PDP nothing to label, so the cap cannot
  be evaluated, as for the fieldless tools above. An agent with a cap can run
  only shell commands that name a file.
- **The command is read as text, not run through a shell.** Variable
  expansion, here-documents and a script piped into `sh` hide a path from the
  label. The delegation's tier ceiling and escalation are what hold there.

---

## See also

- [`session-start.md`](session-start.md) — required first.
- The harness pages, from the table at the top — how each one is installed, what its tools are decided as, and when it runs a tool without a decision.
- [`mcp.md`](mcp.md) — the same enforcement for MCP tool calls.
- [`../pep.md`](../pep.md) § "Reading a denial" — every reason string decoded.
- [`../../example/hook/`](../../example/hook/) — this surface's configuration plus a real, captured Claude Code transcript hitting the deny path.
