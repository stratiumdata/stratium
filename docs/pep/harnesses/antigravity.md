# Antigravity CLI

Stratium checks Antigravity CLI's (`agy`) tool calls through its lifecycle
hooks: [`stratium-pep hook --harness antigravity`](../hook.md) runs on
`PreToolUse`, before every tool call.

**Antigravity CLI lets its user switch any hook off, and has no administrator
level for hooks.** The agent runs as that user. On this harness Stratium is a
guard rail for a cooperative agent, not a boundary; see
[Can the agent remove it?](#can-the-agent-remove-it).

**How this was verified.** Run in live sessions of Antigravity CLI 1.5.14 on
macOS (`agy -p`), with the hooks in a scratch project's `.agents/hooks.json` and
Antigravity's own permission checks left on:

- Antigravity ran all three hooks, and `SessionStart` produced a delegation;
- `read_file`, `edit_file`, `write_file` and `run_command` calls were decided
  and allowed;
- a `write_file` the delegation did not grant was refused, the model was shown
  the PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions, including a read
  that then failed; the refused call was not reported;
- what Antigravity does with each kind of hook answer and failure, in
  [When the tool runs without a decision](#when-the-tool-runs-without-a-decision),
  was observed with a probe hook;
- interactive sessions on 2026-11-22, in the default and `auto` modes: after a
  Stratium allow Antigravity still showed its own permission prompt; approving
  it ran the tool and the call was reported; declining it did not run the tool;
  a refused call showed the PDP's reason and no prompt.

Not observed, and described here from Antigravity's documentation as read on
2026-11-21: the user-level install path, the second set of tool names in the table below, MCP and browser tools, subagents, and remote
agents.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --antigravity install --bin ./bin/stratium-pep
```

This adds one named hook, `stratium`, to `~/.gemini/config/hooks.json` and
leaves every other hook in the file alone:

```json
{
  "stratium": {
    "SessionStart": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep session-start", "timeout": 15 } ],
    "PreToolUse":   [ { "matcher": "*", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep hook --harness antigravity", "timeout": 150 } ] } ],
    "PostToolUse":  [ { "matcher": "*", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep report --harness antigravity", "timeout": 15 } ] } ]
  }
}
```

`deploy/stratium --antigravity status` checks the install, including that the
hook has not been switched off in the file, and `uninstall` removes it. The
installer does not write a project's `.agents/hooks.json`: Antigravity runs
those only in a workspace it trusts.

**Keep the file well-formed.** Antigravity ignored a `hooks.json` whose shape it
did not accept, with no warning, and ran every tool call unchecked.

## How the hook answers

- **Allow:** exit `0`, nothing on stdout. Antigravity then goes on with the
  call. The hook does not answer `allow`, which Antigravity documents as an
  automatic approval.
- **Refuse:** `{"decision":"deny","reason":"…"}` on stdout and **exit `0`**. The
  model is told `tool call denied by pre-tool hook: <reason>`. This is the one
  harness where a refusal does not exit `2`: on a non-zero exit Antigravity
  discards stdout and tells the model the hook failed.

The payload Antigravity sends includes the user's prompt. The hook reads the
tool call and the working directory from it and passes nothing else on.

## What a tool call is decided as

Antigravity has two sets of tool names. The first is what the sessions above
sent; the second is what its documentation lists. Both are mapped.

| Antigravity tool | Decided as | What the PDP reads |
|---|---|---|
| `run_command` | `Bash` | the command, from `CommandLine` |
| `read_file` | `Read` | the file path, from `Path` |
| `write_file` | `Write` | the file path, from `Path` |
| `edit_file` | `Edit` | the file path, from `Path` |
| `search_web` | `WebSearch` | nothing |
| `view_file` | `Read` | the file path, from `AbsolutePath` |
| `write_to_file` | `Write` | the file path, from `TargetFile` |
| `replace_file_content`, `multi_replace_file_content` | `Edit` | the file path, from `TargetFile` |
| `list_dir` | `LS` | the directory, from `DirectoryPath` |
| `find_by_name`, `grep_search` | `Glob`, `Grep` | nothing |
| `read_url_content` | `WebFetch` | nothing |
| any other | its own name | nothing |

A relative path is resolved against the working directory Antigravity reports. A
path with a `..` segment, or one starting with `~`, is refused. A file tool
whose path is not where the table says is refused, with "names no resource the
PDP can read".

A tool catalog entry that happens to share one of these names, such as the MCP
filesystem server's `read_file`, does not change how Antigravity's tool is
decided.

## What is not covered

- **Other tools are decided under their own names** and refused unless a
  delegation grants that name: `invoke_subagent`, `manage_task`, `schedule`,
  `call_mcp_tool`, `mcp_<server>_<tool>`, `browser_*`, `generate_image` and the
  rest. Nothing is read from their input.
- **Searching and listing.** In the sessions above Antigravity offered the model
  no search or listing tool, and the model used the shell. Those are decided as
  shell commands.
- **Remote agents** (`--remote-agent`) run elsewhere. Antigravity's
  documentation does not say hooks run there.
- **`/btw` side questions** do not run user or workspace hooks.
- **A Stratium allow does not replace Antigravity's own permission prompt.**
  The hook allows by printing nothing, so the user is still asked wherever
  Antigravity would have asked. If the user declines, the tool does not run
  and nothing is reported: the audit trail then holds an allow for a call that
  never happened.
- **A refused call can read as done on screen.** Antigravity printed "Edited 1
  file" above a write Stratium had refused. The model's reply carried the
  refusal and no file was written.

## When the tool runs without a decision

Observed on 1.5.14, in print mode:

| What the hook did | What Antigravity did |
|---|---|
| exited `0` and printed nothing | **ran the tool** |
| printed a deny | refused, showing the reason |
| printed JSON with no decision | refused |
| printed something that is not JSON | refused |
| exited with any non-zero code | refused, showing stderr inside a "hook failed" message |
| ran past its timeout | refused |

So the cases that let a call through are a hook that says nothing, and no hook:

- **The hook is switched off or removed.** See below.
- **The hook's command is replaced** by something that exits `0` in silence.
- **`hooks.json` is malformed.** Antigravity loads nothing from it.
- **The workspace is not trusted**, for a hook in a project file.

Antigravity's documentation says the opposite about failures: that a non-zero
exit is logged and ignored. The table is what this version did. Treat it as
observed, not promised.

## Can the agent remove it?

Yes. `~/.gemini/config/hooks.json` belongs to the user the agent runs as. Setting
`"enabled": false` on the hook, using the `/hooks` command, or editing the file
turns it off. Removing it also removes the reporting hook, so nothing then
records that tool calls are running undecided.

There is no system install. Antigravity reads hooks from the user's file and the
project's, and documents no administrator location and no setting that protects
a hook. `deploy/stratium --antigravity install --system` stops and says so.

For a boundary that does not depend on the harness, put what is being protected
behind [`proxy`](../proxy.md) or [`extauthz`](../extauthz.md).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md).
- `PostToolUse` runs `stratium-pep report --harness antigravity`, for a call that
  failed as well as one that succeeded, so the PDP can flag a call it never
  allowed.
