# Gemini CLI

Stratium checks Gemini CLI's tool calls through its hooks:
[`stratium-pep hook --harness gemini`](../hook.md) runs on `BeforeTool`, before
every tool call the agent makes.

**How this was verified.** It has not been run in Gemini CLI: there were no
credentials for it on the machine it was built on. Everything on this page
about Gemini CLI was read from its source and docs at v0.70.0, and the hook's
side is covered by tests fed input built from that source.

**Read [Can the agent remove it?](#can-the-agent-remove-it) before relying on
this.** Gemini CLI lets a user switch off any hook, including one an
administrator installed, and Stratium cannot prevent that.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --gemini install --bin ./bin/stratium-pep
```

This adds three entries to `~/.gemini/settings.json` and leaves the rest of the
file alone. Timeouts are in milliseconds:

```json
{
  "hooks": {
    "SessionStart": [ { "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep session-start", "timeout": 15000 } ] } ],
    "BeforeTool":   [ { "matcher": "*", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep hook --harness gemini", "timeout": 150000 } ] } ],
    "AfterTool":    [ { "matcher": "*", "hooks": [ { "type": "command",
        "command": "/usr/local/bin/stratium-pep report", "timeout": 15000 } ] } ]
  }
}
```

`deploy/stratium --gemini status` checks the install, including that the timeout
is long enough and that hooks are not switched off in the file. `uninstall`
removes the three entries.

## How the hook answers

- **Allow:** exit `0`, nothing on stdout.
- **Refuse:** `{"decision":"deny","reason":"…"}` alone on stdout, the reason on
  stderr, and exit code `2`. Gemini CLI acts on JSON it finds on stdout at any
  exit code, and reads a document with no `decision` as an allow, so stdout
  carries exactly this. The model is told `Tool execution blocked: <reason>`.

## What a tool call is decided as

| Gemini CLI tool | Decided as | What the PDP reads |
|---|---|---|
| `run_shell_command` | `Bash` | the command |
| `read_file` | `Read` | the file path, from `file_path` |
| `write_file` | `Write` | the file path, from `file_path` |
| `replace` | `Edit` | the file path, from `file_path` |
| `list_directory` | `LS` | the directory, from `dir_path` |
| `glob`, `grep_search` | `Glob`, `Grep` | nothing |
| `web_fetch`, `google_web_search` | `WebFetch`, `WebSearch` | nothing |
| any other | its own name | nothing |

A relative path is resolved against the working directory Gemini CLI reports. A
path with a `..` segment, or one starting with `~`, is refused.

## What is not covered

- **`read_many_files` is decided under its own name.** It takes patterns, not a
  path, so there is no file to identify. It is refused unless a delegation
  grants `read_many_files`.
- **`web_fetch` carries no URL.** Gemini CLI puts the URLs inside a free-text
  prompt.
- **MCP tools arrive as `mcp_<server>_<tool>`** and are decided under that name.
- **What you type yourself.** `!command` and `@file` at the prompt are not tool
  calls and no hook sees them.
- **ACP mode** (`--experimental-acp`, used by editor integrations) runs tools
  without running hooks at all.

## When the tool runs without a decision

Gemini CLI runs the tool call in almost every case where a hook fails:

- **The hook passes its timeout.** The installer sets it above the longest the
  hook can take, and `status` fails when it is too short.
- **The hook is killed by a signal**, or the shell that would run it cannot be
  started.
- **The hook exits non-zero and prints nothing.** The hook never does: every
  refusal and every failure of its own prints a deny.
- **The folder is not trusted.** Gemini CLI then registers no hooks from any
  settings file, the system one included.

A missing binary is a refusal: the shell's "not found" message is read as the
reason.

## Can the agent remove it?

Yes, and the system install below narrows that without closing it.

With the install above, `~/.gemini/settings.json`, the binary and the hook's
environment are all the agent's own user's to change.

```sh
sudo -E deploy/stratium --gemini install --system --bin ./bin/stratium-pep
```

The system install puts the binary in `/opt/stratium/bin`, the configuration in
`/etc/stratium/pep.env`, and the entries in Gemini CLI's system settings
(`/Library/Application Support/GeminiCli/settings.json` on macOS,
`/etc/gemini-cli/settings.json` on Linux), added to whatever that file holds. It
also sets `hooksConfig.enabled` to `true` there, which overrides a user's
`false`. A user file cannot remove the entries.

What it does not stop, all from Gemini CLI's own design:

- **Disabling by name.** `/hooks disable-all`, `/hooks disable`, or a
  `hooksConfig.disabled` list in the user's own settings switches off any hook,
  wherever it was defined. The system file cannot undo it.
- **Environment variables.** `GEMINI_CLI_TRUST_WORKSPACE=false` or
  `GEMINI_RESTRICTED_MODE=true` turns off every hook, and
  `GEMINI_CLI_SYSTEM_SETTINGS_PATH` points Gemini CLI at a different system
  file.
- **ACP mode**, as above.

So on Gemini CLI a hook is a guard rail for a cooperative agent. For a boundary
that does not depend on the harness, put what is being protected behind
[`proxy`](../proxy.md) or [`extauthz`](../extauthz.md).

`uninstall --system` removes the entries and leaves the rest of the system file,
including the `hooksConfig.enabled` switch if other settings remain.

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md). It
  cannot hold a session back; a tool call that arrives before it finishes is
  refused for want of a session.
- `AfterTool` runs `stratium-pep report`, so the PDP can flag a call it never
  allowed.
