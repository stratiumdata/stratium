# `stratium-pep hook`

A `PreToolUse` hook for coding agents. The harness invokes it before every tool
call, hands it the call on stdin, and honours what it answers.

Works with **Claude Code** directly, and with **Codex** through a small shim —
their hook contracts differ in one place, covered below.

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

**`hook` has no decision cache.** It asks the PDP on every call, so a PDP
outage denies immediately. It ignores `STRATIUM_PEP_CACHE_STALENESS_WINDOW` if
that is set; only [`mcp`](mcp.md) reads it.

---

## Installing in Claude Code

`.claude/settings.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [
          { "type": "command", "command": "/opt/stratium/bin/stratium-pep session-start", "timeout": 15 } ] }
    ],
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/opt/stratium/bin/stratium-pep hook", "timeout": 10 } ] }
    ]
  }
}
```

`deploy/stratium install --claude --bin /opt/stratium/bin/stratium-pep` writes
exactly that block, merging into whatever the file already holds.

**Use an absolute path.** A bare `stratium-pep` that is not on `PATH` exits
`127`, and a harness treats any non-zero that is not `2` as a *non-blocking*
error — the tool call proceeds unchecked. A hook that cannot run is not a broken
enforcement point, it is **no enforcement point**.

**Keep the `timeout`,** and keep it comfortably above
`STRATIUM_PEP_CONNECT_TIMEOUT`. It is the harness's own budget for the hook
process; the connect timeout bounds only the PDP dial.

`SessionStart` carries no `matcher` on purpose, so it runs for every session
source — `startup`, `resume`, `clear`, `compact`, `fork`. A resumed session gets
a fresh delegation rather than trusting whatever the file holds.

> Installing `SessionStart` re-issues a delegation on every session start. If you
> are testing a delegation you built by hand, install `--only PreToolUse` — the
> `SessionStart` half will discard your work at the next launch.

---

## Installing in Codex

Same JSON shape, in `~/.codex/hooks.json` — and **only** there. Codex also reads
`<repo>/.codex/hooks.json`, but project-local hooks are disabled until the
project is trusted, and a disabled enforcement hook is not inert, it is
fail-open.

Codex needs a shim, because of one contract difference: on a non-zero exit it
reads the blocking reason from **stderr**, and `stratium-pep hook` writes it to
stdout. Without the shim the call is still denied and the reason is lost.

```sh
#!/bin/sh
# stratium-codex-hook
out=$(stratium-pep hook); rc=$?
[ "$rc" -eq 0 ] && exit 0
printf '%s\n' "${out:-stratium-pep: denied with no output (exit $rc)}" >&2
printf '%s' "$out"
exit 2
```

Point the hook at the shim, with no subcommand — the shim supplies it. Every
non-zero becomes `2`, so a crashed or missing binary denies rather than falling
through: **the allow case is the only one that exits 0.**

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
  removal. Installing a `matcher: "*"` hook from inside a session you are using
  gags it on the next call.
- **Fieldless tools deny under any cap.** `Glob`, `Grep`, `WebFetch`,
  `WebSearch` and `TodoWrite` declare no resource field, so nothing can be
  labelled and the cap cannot be evaluated.
- **`Bash` is not a back door but it is a different check.** It is catalogued
  with a command field and no resource field, so its tier is derived from the
  command text and no resource label is resolved. `Bash(cat secret.txt)` and
  `Read(secret.txt)` are not the same decision.

---

## See also

- [`session-start.md`](session-start.md) — required first.
- [`mcp.md`](mcp.md) — the same enforcement for MCP tool calls.
- [`../pep.md`](../pep.md) § "Reading a denial" — every reason string decoded.
- [`../../example/hook/`](../../example/hook/) — this surface's configuration plus a real, captured Claude Code transcript hitting the deny path.
