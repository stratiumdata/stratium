# example/hook — a configuration, not a program

Every other directory in this suite (`mcp`, `proxy`, `extauthz`) is a Go
program: a real agent, driven by a real local model, that calls a tool
Stratium sits in front of. This directory has no `main.go` and builds nothing.

That is deliberate, not unfinished. `hook` is a **`PreToolUse` hook** — a
configuration contract for a harness that already exists: **Claude Code**
(and, with a small shim, Codex — see `docs/pep/hook.md`). Claude Code decides
for itself when to call a tool, what to put on stdin, and how to interpret
exit code and stdout; `stratium-pep hook` just has to answer correctly when
asked. A hand-written client that pretended to be Claude Code — feeding
`stratium-pep hook` synthetic `tool_name`/`tool_input` JSON on stdin — would
demonstrate the *contract*, not the *product*, and it would drift the moment
Claude Code's own hook payload changed shape. The other three examples get to
write their own client because the harness on the other side (an MCP client
loop, a gRPC client, an HTTP client) is something this suite invents for the
demo. Here, the harness is not this suite's to invent or to fake.

So instead this directory ships three things:

- **`settings.json`** — the hook block, ready to merge into a real
  `.claude/settings.json`.
- **`transcript.md`** — a real, captured Claude Code session hitting the deny
  path, with the actual refusal and the actual model reaction. Not a
  reconstruction.
- This README — why there's no program, how the wiring works, and the traps.

## The two hooks

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
          { "type": "command", "command": "/opt/stratium/bin/stratium-pep hook", "timeout": 150, "onFailure": "block" } ] }
    ],
    "PostToolUse": [
      { "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/opt/stratium/bin/stratium-pep report", "timeout": 15 } ] }
    ],
    "PostToolUseFailure": [
      { "matcher": "*",
        "hooks": [
          { "type": "command", "command": "/opt/stratium/bin/stratium-pep report", "timeout": 15 } ] }
    ]
  }
}
```

`SessionStart` mints a fresh delegation at the start of every session (no
`matcher`, so it fires for `startup`, `resume`, `clear`, `compact` and `fork`
alike — a resumed session gets a fresh delegation rather than trusting
whatever is on disk). `PreToolUse`, matched against every tool (`"*"`), asks
the PDP before each call and either lets it through silently (exit 0) or
blocks it with a reason (exit 2 plus deny JSON on stdout).

Both commands need their `STRATIUM_PEP_*` environment set in the shell that
launches Claude Code — eleven variables in total, five shared between the two
hooks. `docs/pep/session-start.md` and `docs/pep/hook.md` each document their
own half; `deploy/stratium`'s own `pep_env` shows one place that resolves and
exports all eleven together, including the ephemeral Docker Compose ports.

## Why `/opt/stratium/bin/stratium-pep`, not just `stratium-pep`

The `command` above is an absolute path on purpose, and that is not a style
preference. Claude Code invokes a hook command through the shell; if
`stratium-pep` is not on the `PATH` of whatever process launches Claude Code,
the command fails to resolve and the process exits **127**. Claude Code — like
most harnesses — only treats a hook's exit code **2** as a blocking decision;
every other non-zero exit is a **non-blocking error**, logged and then
ignored, and the tool call **proceeds unchecked**.

That is the trap: a hook wired with a bare command name that happens not to be
on `PATH` does not fail loudly. It fails silently, in the direction of letting
everything through. **A hook that cannot run is not a broken enforcement
point — it is no enforcement point at all.** Always wire the absolute path to
the binary, never a bare name you're hoping `PATH` resolves.

## What a denial looks like

From `transcript.md`, the actual `PreToolUse` response for a `Read` call
against a `SECRET`-labelled file under a delegation capped at `CONFIDENTIAL`:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"}}
```

Claude Code surfaces `permissionDecisionReason` back to the model as the tool
result, `is_error: true`. The model in the capture didn't retry, didn't shell
out around it, and explained the refusal correctly in its own next message —
see `transcript.md` for the verbatim exchange. `docs/pep/hook.md`'s "Reading a
denial" table decodes the other reason strings a real session will hit
(missing configuration, an unheld tool, a tier ceiling) — they all exit `2`,
so the reason text is what tells them apart, never the code.

## Installing this for real — read this before you do it

**Installing these hooks takes effect LIVE, in any Claude Code session already
open in that project, on its very next tool call.** `SessionStart` and
`PreToolUse` are not settings that apply only to a fresh launch; Claude Code
re-reads `.claude/settings.json` and the change is live immediately. Installed
into a project you are actively working in, from inside that same session,
the `matcher: "*"` `PreToolUse` hook denies **every** tool call from that
point on — including the ones you would need to remove the hook again. The
session gags itself.

This is exactly why `transcript.md` was **not** captured by installing this
suite's own two hooks into this repository's `.claude/settings.json`. It was
captured from a disposable project directory outside the repo instead, with
its own `.claude/settings.json`, launched non-interactively
(`claude -p ...`) so there was never a live session to strand. If you want to
try this yourself, do the same: a throwaway directory, not the project you are
currently working in.

## Traps

- **Everything denies until a session exists.** Install the hook, ask
  something, and see every call refused — that is very likely correct
  behaviour for a session with no delegation yet, not a bug.
- **A missing environment variable denies, it does not crash.** `hook` fails
  closed with `missing required configuration: …` in the deny reason, which
  reads exactly like a policy denial until you look closely.
- **`Bash` and `Read` are different checks even for the same file.** `Bash` is
  catalogued with a `command_field`, not a `resource_field`, so its tier comes
  from the command text and no resource label is ever resolved for it — a
  `Bash("cat secret.txt")` denial and a `Read("secret.txt")` denial can be the
  same file and completely different reasons. `transcript.md`'s "Setup"
  section records exactly this happening during capture.
- **Narrow the `matcher` while iterating.** `"*"` is right for a real
  installation; `"Read"` (or similar) is safer while you are still finding out
  whether your environment is configured correctly, on a session you actually
  care about keeping responsive.

## See also

- [`docs/pep/hook.md`](../../docs/pep/hook.md) — the full reference: every
  variable, the Codex shim, the complete "Reading a denial" table.
- [`docs/pep/session-start.md`](../../docs/pep/session-start.md) — what
  `SessionStart` actually does and the delegation it produces.
- [`../README.md`](../README.md) — how this directory fits with the three
  runnable examples.
