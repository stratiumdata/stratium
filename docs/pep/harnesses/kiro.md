# Kiro CLI

Stratium checks Kiro CLI's (`kiro-cli`) tool calls through its hooks:
[`stratium-pep hook --harness kiro`](../hook.md) runs on `PreToolUse`, before
every tool call.

**Only Kiro's v3 engine runs these hooks, and the user can remove them.** The
older v2 engine does not read the hook file at all, and Kiro has no
administrator level for hooks. On this harness Stratium is a guard rail for a
cooperative agent, not a boundary; see
[When the tool runs without a decision](#when-the-tool-runs-without-a-decision).

**How this was verified.** Run in live sessions of Kiro CLI 3.5.0 on macOS, on
the v3 engine (`--v3`), with the hooks in a scratch project's `.kiro/hooks/` and
the workspace trusted for that launch:

- Kiro ran all three hooks, and `SessionStart` produced a delegation;
- `read_file`, `fs_write`, `str_replace` and `execute_bash` calls were decided
  and allowed;
- an `fs_write` the delegation did not grant was refused, the model was shown
  the PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions, including a read
  that then failed; the refused call was not reported;
- in interactive sessions, after a Stratium allow Kiro still showed its own
  approval prompt; approving it ran the tool, declining it did not; a refused
  call showed the PDP's reason and no prompt;
- what Kiro does with each kind of hook answer and failure, in the table
  below, was observed with a probe hook.

Not observed: the user-level install path (`~/.kiro/hooks/`), the Kiro IDE, the
tools marked "documented" in the table below, MCP tools, subagents, and cloud
sessions.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --kiro install --bin ./bin/stratium-pep
```

This writes Stratium's own file, `~/.kiro/hooks/stratium.json`. Kiro reads
every file in that directory and runs their hooks together:

```json
{
  "version": "v1",
  "hooks": [
    { "name": "stratium-SessionStart", "trigger": "SessionStart", "timeout": 15,
      "action": { "type": "command", "command": "/usr/local/bin/stratium-pep session-start" } },
    { "name": "stratium-PreToolUse", "trigger": "PreToolUse", "timeout": 150,
      "action": { "type": "command", "command": "/usr/local/bin/stratium-pep hook --harness kiro" } },
    { "name": "stratium-PostToolUse", "trigger": "PostToolUse", "timeout": 15,
      "action": { "type": "command", "command": "/usr/local/bin/stratium-pep report" } }
  ]
}
```

The hooks carry no matcher, which in Kiro means every tool.
`deploy/stratium --kiro status` checks the install and `uninstall` removes it.
The installer does not write a project's `.kiro/hooks/`: Kiro runs those only
in a workspace it trusts.

**Run the v3 engine.** On 3.5.0 an interactive `kiro-cli` asks whether to move
to v3 and stays on v2 until the user says yes, and `--no-interactive` used v2
unless `--v3` was passed. A v2 session ran every tool call without calling the
hook.

## How the hook answers

- **Allow:** exit `0`. Kiro then applies its own permission rules, so the user
  is still asked wherever Kiro would have asked.
- **Refuse:** the reason on stderr and **exit `2`**. Kiro does not run the tool
  and gives the model the reason.

## What a tool call is decided as

| Kiro tool | Decided as | What the PDP reads |
|---|---|---|
| `execute_bash` | `Bash` | the command, from `command` |
| `read_file` | `Read` | the file path, from `path` |
| `fs_write` | `Write` | the file path, from `path` |
| `str_replace` | `Edit` | the file path, from `path` |
| `web_fetch` | `WebFetch` | nothing |
| `remote_web_search` | `WebSearch` | nothing |
| `fs_append` (documented) | `Edit` | the file path, from `path` |
| `delete_file` (documented) | `delete_file` | the file path, from `path` |
| `list_directory` (documented) | `LS` | the directory, from `path` |
| `file_search`, `grep_search` (documented) | `Glob`, `Grep` | nothing |
| any other | its own name | nothing |

Kiro's documentation does not give the input fields of its tools. For the
documented rows `path` is assumed from the tools that were seen. If a file tool's path is somewhere else the call is refused, with "names
no resource the PDP can read".

A relative path is resolved against the working directory Kiro reports. A path
with a `..` segment, or one starting with `~`, is refused.

A tool catalog entry that happens to share one of these names, such as the MCP
filesystem server's `read_file`, does not change how Kiro's tool is decided.

## What is not covered

- **`tool_load` and `code`.** Kiro loads some of its tools on demand with a
  `tool_load` call, web search and its `code` search tool among them. Both are
  decided under their own names, so they are refused unless a delegation
  grants those names. Without `tool_load` the
  model cannot reach web search even when `WebSearch` is granted.
- **PowerShell.** `execute_pwsh`, Kiro's shell tool on Windows, is decided
  under its own name and not as `Bash`: a PowerShell command is not read the
  way a Bash command is.
- **Other tools are decided under their own names** and refused unless a
  delegation grants that name: `invoke_sub_agent`, `mcp_<server>_<tool>`,
  `knowledge`, `introspect` and the rest. Nothing is read from their input.
- **The v2 engine**, as above.
- **A failed call has no event of its own.** It arrives on `PostToolUse` like a
  successful one. So did a web search that Kiro's own permission check stopped
  before it ran: it was reported as a call that ran.
- **A declined prompt leaves an allow with no call behind it.** If the user
  declines Kiro's own prompt after a Stratium allow, the tool does not run and
  nothing is reported.
- **The Kiro IDE** documents the same hook file format from version 1.4.236. It
  was not run, and it reads a project's `.kiro/hooks/` only.

## When the tool runs without a decision

Observed on 3.5.0, v3 engine:

| What the hook did | What Kiro did |
|---|---|
| exited `0` | **ran the tool**, whatever it printed |
| exited `2` with a reason on stderr | refused, showing the reason |
| exited `2` with nothing on stderr | refused, with no reason |
| exited `0` and printed Claude Code's deny JSON | refused, showing the reason |
| exited `1` | **ran the tool** |
| ran past its `timeout` (seconds; a hook set to 150 was let run for 75) | **ran the tool** |
| named a command that does not exist | **ran the tool** |

So a call goes through undecided when:

- **the hook cannot run or is slow.** `stratium-pep hook` exits `2` on every
  failure of its own, but it cannot answer if it is missing or killed at the
  timeout. The installer refuses a binary that does not resolve.
- **the session is on the v2 engine.**
- **the hook file is removed or edited.** `~/.kiro/hooks/` belongs to the user
  the agent runs as.
- **the workspace is not trusted**, for a hook in a project file.

Kiro's documentation says any non-zero exit from a `PreToolUse` hook blocks the
call. The table is what this version did. Treat it as observed, not promised.

There is no system install. Kiro reads hooks from the user's `.kiro` directory
and the project's, and documents no administrator location.
`deploy/stratium --kiro install --system` stops and says so.

For a boundary that does not depend on the harness, put what is being protected
behind [`proxy`](../proxy.md) or [`extauthz`](../extauthz.md).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md).
- `PostToolUse` runs `stratium-pep report`, so the PDP can flag a call it never
  allowed.
