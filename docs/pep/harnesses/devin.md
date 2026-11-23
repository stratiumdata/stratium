# Devin

Stratium checks the tool calls of Devin's local agent through its hooks:
[`stratium-pep hook --harness devin`](../hook.md) runs on `PreToolUse`, before
every tool call. The Devin CLI and Devin Desktop share one agent and one hook
system.

**The user can remove the hook, and no administrator location for it has been
confirmed.** The agent runs as that user. On this harness Stratium is a guard
rail for a cooperative agent, not a boundary; see
[When the tool runs without a decision](#when-the-tool-runs-without-a-decision).

**How this was verified.** Run in live sessions of the Devin CLI 3000.14
(`devin`, bundled with Devin Desktop 3.14) on macOS, with the hooks in a
scratch project's `.devin/hooks.v1.json`:

- Devin ran all three hooks, and `SessionStart` produced a delegation;
- `read`, `write`, `edit` and `exec` calls were decided and allowed;
- a `write` the delegation did not grant was refused, the model was shown the
  PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions; the refused call
  was not reported;
- in an interactive session, after a Stratium allow Devin still showed its own
  permission prompt, and the file was not written while it waited;
- with the hook only in a Claude Code settings file, Devin ran it and the
  calls were decided as Devin's;
- what Devin does with each kind of hook answer and failure, in the table
  below, was observed with a probe hook.

Not observed: the user-level install path (`~/.config/devin/config.json`),
Devin Desktop's own agent panel, cloud sessions, subagents, MCP tools, and the
tools marked "documented" below.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --devin install --bin ./bin/stratium-pep
```

This adds a `hooks` key to the user's `~/.config/devin/config.json` and leaves
the other settings in the file alone:

```json
{
  "hooks": {
    "SessionStart": [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep session-start", "timeout": 15 } ] } ],
    "PreToolUse":   [ { "matcher": "", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep hook --harness devin",
        "timeout": 150, "fail_closed": true } ] } ],
    "PostToolUse":  [ { "matcher": "", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep report --harness devin", "timeout": 15 } ] } ]
  }
}
```

`deploy/stratium --devin status` checks the install and `uninstall` removes
it. The installer does not write a project's `.devin/`: Devin loads those only
in a workspace it trusts.

- **`"fail_closed": true`** is what makes Devin refuse a call when the hook
  crashes, times out or cannot be started. Devin's documentation does not
  describe this setting; the table below is what it did.
- **Comments.** Devin accepts comments in `config.json`. The installer reads
  plain JSON and stops, without writing, at a file that has them.

## If Stratium is also installed for Claude Code

Devin runs the hooks in Claude Code's settings files too: `~/.claude/settings.json`,
`~/.claude.json` and a project's `.claude/settings.json`. It did so for a
project file in the sessions above. A Stratium hook installed there is called
by Devin with no `--harness`. The hook recognises Devin by the
`DEVIN_PROJECT_DIR` variable Devin sets, and decides the call as Devin's.

Two things follow:

- **That entry does not fail closed in Devin.** Claude Code's entry carries
  Claude Code's own setting for that, which Devin does not read. Install with
  `--devin` as well if Devin is used on the machine.
- **With both installed, each call is decided and reported twice.** A refusal
  from either stops the call.

Setting `read_config_from.claude` to `false` in Devin's configuration stops it
reading Claude Code's files.

## How the hook answers

- **Allow:** exit `0`. Devin then applies its own permission rules, so the user
  is still asked wherever Devin would have asked.
- **Refuse:** the reason on stderr and exit `2`. Devin tells the model
  `Tool rejected: <reason>`.

Devin's payload carries no working directory. It runs the hook in the
session's directory, and the hook passes that on, so a relative path in a tool
call is resolved against it.

## What a tool call is decided as

| Devin tool | Decided as | What the PDP reads |
|---|---|---|
| `exec` | `Bash` | the command, from `command` |
| `read` | `Read` | the file path, from `file_path` |
| `write` | `Write` | the file path, from `file_path` |
| `edit` | `Edit` | the file path, from `file_path` |
| `grep`, `glob` | `Grep`, `Glob` | nothing |
| `webfetch` | `WebFetch` | nothing |
| any other | its own name | nothing |

A path with a `..` segment, or one starting with `~`, is refused. A file tool
with no `file_path` is refused, with "names no resource the PDP can read".

## What is not covered

- **`apply_patch`, `notebook_read` and `notebook_edit`** (documented) are in
  Devin's tool list without their inputs. They are decided under their own
  names and refused unless a delegation grants that name.
- **Other tools are decided under their own names** and refused unless
  granted: `run_subagent`, `get_output`, `write_to_process`, `todo_write`,
  `mcp__<server>__<tool>` and the rest. Nothing is read from their input.
- **A failed call was not reported.** Devin ran no `PostToolUse` hook for a
  read of a file that did not exist, so the audit trail holds the allow and no
  report. The same holds for a call the user declines at Devin's own prompt.
- **Cloud sessions** take hooks from plugins and an organization's settings,
  not from the user's file.

## When the tool runs without a decision

Observed on CLI 3000.14, on a `PreToolUse` hook:

| What the hook did | Without `fail_closed` | With `fail_closed: true` |
|---|---|---|
| exited `0` | **ran the tool** | **ran the tool** |
| exited `2` with a reason on stderr | refused, showing the reason | refused |
| printed a block decision | refused | refused |
| exited `1` | **ran the tool** | refused |
| ran past its timeout | **ran the tool** | refused |
| named a command that does not exist | **ran the tool** | refused |
| exited `0` and printed something that is not a decision | **ran the tool** | not tried |

So a call goes through undecided when:

- **the hook entry is removed or edited**, including dropping `fail_closed`.
  `~/.config/devin/config.json` belongs to the user the agent runs as.
- **the workspace is not trusted**, for a hook in a project file.

There is no system install. Devin's documentation says Devin Desktop reads
system-level hooks from an administrator-owned directory, but not that the CLI
does, and that was not tested. `deploy/stratium --devin install --system`
stops and says so.

For a boundary that does not depend on the harness, put what is being protected
behind [`proxy`](../proxy.md) or [`extauthz`](../extauthz.md).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md).
- `PostToolUse` runs `stratium-pep report --harness devin`, so the PDP can flag
  a call it never allowed.
