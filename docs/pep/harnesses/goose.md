# Goose

Stratium checks Goose's tool calls through its plugin hooks:
[`stratium-pep hook --harness goose`](../hook.md) runs on `PreToolUse`, before
every tool call.

**Goose lets its user disable any plugin, and has no administrator level for
hooks.** The agent runs as that user. On this harness Stratium is a guard rail
for a cooperative agent, not a boundary; see
[When the tool runs without a decision](#when-the-tool-runs-without-a-decision).

**How this was verified.** Run in live sessions of Goose 1.60.2 on macOS, the
CLI bundled with the desktop app, with Goose's whole root in a scratch
directory (`GOOSE_PATH_ROOT`) and the plugin installed there as the installer
writes it:

- Goose ran all four hooks from the user-level plugin directory, and
  `SessionStart` produced a delegation;
- `write`, `edit`, `tree` and `shell` calls were decided and allowed;
- a `write` the delegation did not grant was refused, the model was shown the
  PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions, including a shell
  command that failed; the refused call was not reported;
- in interactive sessions in `approve` mode, after a Stratium allow Goose still
  showed its own approval prompt; approving it ran the tool and the call was
  reported; declining it did not run the tool; a refused call showed the
  PDP's reason and no prompt;
- what Goose does with each kind of hook answer and failure, in the table
  below, was observed with a probe hook, and agrees with its source at
  1.60.0 (commit `36b2911`).

Not observed: `deploy/stratium --goose install` writing into a real
`~/.agents/plugins`, the desktop app, recipes, subagents, ACP, and other
extensions' tools.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --goose install --bin ./bin/stratium-pep
```

This writes a plugin of its own, `~/.agents/plugins/stratium/`, holding one
file, `hooks/hooks.json`:

```json
{
  "hooks": {
    "SessionStart": [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep session-start", "timeout": 15 } ] } ],
    "PreToolUse":   [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep hook --harness goose",
        "timeout": 150, "on_failure": "block" } ] } ],
    "PostToolUse":        [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep report --harness goose", "timeout": 15 } ] } ],
    "PostToolUseFailure": [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep report --harness goose", "timeout": 15 } ] } ]
  }
}
```

`deploy/stratium --goose status` checks the install and `uninstall` removes
the hooks. The installer does not write a project's `.agents/plugins/`.

Two things in that file matter if you edit it by hand:

- **No matcher.** A rule without one runs for every tool. Goose's matcher is a
  regular expression, and it skips a rule whose matcher does not compile, so
  `"*"` switches the hook off. Use `".*"` if you want one.
- **`"on_failure": "block"`.** Without it Goose runs the tool call when the
  hook times out, crashes or cannot be started.

## How the hook answers

- **Allow:** exit `0`, nothing on stdout. Goose counts any other output that is
  not a decision as a failed hook.
- **Refuse:** `{"decision":"block","reason":"…"}` on stdout, the reason on
  stderr, and exit `2`. Goose tells the model
  ``Tool call denied by policy hook `stratium`: <reason>`` and not to retry.

## What a tool call is decided as

| Goose tool | Decided as | What the PDP reads |
|---|---|---|
| `shell` | `Bash` | the command, from `command` |
| `write` | `Write` | the file path, from `path` |
| `edit` | `Edit` | the file path, from `path` |
| `tree` | `LS` | the directory, from `path` |
| any other | its own name | nothing |

These are the developer extension's tools, which carry bare names. A relative
path is resolved against the working directory Goose reports. A path with a
`..` segment, or one starting with `~`, is refused. A file tool with no `path`
is refused, with "names no resource the PDP can read".

## What is not covered

- **Reading a file has no tool of its own.** Goose's model reads text files
  with `shell`, so a read is decided as a shell command. A rule written for
  `Read` on a path does not see it.
- **`read_image`** takes a file path or a URL in one field. It is decided under
  its own name and refused unless a delegation grants that name.
- **Other extensions' tools** arrive as `<extension>__<tool>`, for example
  `todo__todo_write`, and MCP tools likewise. They are decided under those
  names and refused unless granted. Nothing is read from their input.
- **Subagents, recipes, the desktop app and ACP** were not checked.
- **A Stratium allow does not replace Goose's own approval prompt.** In
  `approve` mode the user is still asked. If the user declines, the tool does
  not run and nothing is reported: the audit trail then holds an allow for a
  call that never happened.

## When the tool runs without a decision

Observed on 1.60.2, with the hook installed as above:

| What the hook did | What Goose did |
|---|---|
| exited `0` and printed nothing | **ran the tool** |
| printed a block decision and exited `2` | refused, showing the reason |
| exited `1` | refused: "could not complete" |
| ran past its timeout | refused |
| exited `0` and printed something that is not a decision | refused |
| named a command that does not exist | refused |

The last four are refused only because of `on_failure: block`. Without it, a
hook that exited `1` let the tool run. And with a `"*"` matcher on the rule, a
hook that refused was never called and the tool ran.

So a call goes through undecided when:

- **the plugin is disabled.** A user can list `stratium` under
  `disabledPlugins` in `~/.config/goose/settings.json`, or in a project's
  `.config/goose/settings.json`.
- **the hooks file is removed or edited**, including dropping
  `on_failure: block` or giving the rule a matcher that does not compile.
  `~/.agents/plugins/` belongs to the user the agent runs as.

There is no system install. Goose loads plugins from the user's
`.agents/plugins` and the project's, and has no administrator location.
`deploy/stratium --goose install --system` stops and says so.

For a boundary that does not depend on the harness, put what is being protected
behind [`proxy`](../proxy.md) or [`extauthz`](../extauthz.md).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md).
- `PostToolUse` and `PostToolUseFailure` run
  `stratium-pep report --harness goose`, so the PDP can flag a call it never
  allowed.
