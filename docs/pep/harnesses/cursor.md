# Cursor

Stratium checks Cursor's tool calls through Cursor's own hooks, in the desktop
app and the `agent` CLI: [`stratium-pep hook --harness cursor`](../hook.md) runs
on `preToolUse`, before every tool call.

**How this was verified.** Run in live sessions of Cursor's CLI
(`agent -p`, version 2026.11.19, macOS), with the hooks in a trusted project's
`.cursor/hooks.json`:

- Cursor ran all four hooks, and `sessionStart` produced a delegation;
- `Read`, `Write` and `Shell` calls were decided and allowed; an edit of an
  existing file arrived as `Write`;
- a `Write` the delegation did not grant was refused, the model was shown the
  PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions, including a `Read`
  that then failed; the refused call was not reported;
- the tool names and inputs in the table below are the ones Cursor sent.

Not observed, and described here from Cursor's documentation as read on
2026-11-20: the desktop app, the user-level and system installs, `Task`, MCP
tools, `WebFetch`, `WebSearch`, and what Cursor does when the hook fails.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --cursor install --bin ./bin/stratium-pep
```

This adds four entries to `~/.cursor/hooks.json` and leaves any other hooks in
the file alone:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart":       [ { "command": "/usr/local/bin/stratium-pep session-start", "timeout": 15 } ],
    "preToolUse":         [ { "command": "/usr/local/bin/stratium-pep hook --harness cursor",
                              "matcher": "*", "timeout": 150, "failClosed": true } ],
    "postToolUse":        [ { "command": "/usr/local/bin/stratium-pep report", "matcher": "*", "timeout": 15 } ],
    "postToolUseFailure": [ { "command": "/usr/local/bin/stratium-pep report", "matcher": "*", "timeout": 15 } ]
  }
}
```

The installer writes the user file only. Cursor also reads
`<project>/.cursor/hooks.json`, but runs project hooks only in a workspace the
user has trusted, and an enforcement hook that does not run lets every call
through.

`deploy/stratium --cursor status` checks the install, including that
`failClosed` is set, and `uninstall` removes the four entries.

## How the hook answers

- **Allow:** `{"permission":"allow"}` on stdout. Cursor treats a hook that
  prints nothing as a failed hook, so an allow has to say so.
- **Refuse:** `{"permission":"deny", ...}` on stdout with the reason as both the
  user and the agent message, the reason on stderr, and exit code `2`, which
  Cursor documents as a deny in its own right. Every failure of the hook itself
  is a refusal in this form. In the sessions above the model was shown the
  reason.

## What a tool call is decided as

| Cursor tool | Decided as | What the PDP reads |
|---|---|---|
| `Shell` | `Bash` | the command |
| `Read`, `Write` | `Read`, `Write` | the file path, from `file_path` |
| `Delete` | `Delete` | the file path, from `file_path` |
| `Grep`, `WebFetch`, `WebSearch` | the same names | nothing |
| `Task`, `MCP:<tool>` and any other | its own name | nothing |

Cursor sent absolute paths in every call observed. A relative path could not be
resolved, because Cursor reports no working directory for file tools, and is
refused; so is a path with a `..` segment or one starting with `~`.

## What is not covered

- **Cursor documents the input of `Shell` only.** The other inputs here are the
  ones it sent in the sessions above. If a later version sends a file path
  under another name, the PDP finds no file and **refuses the call**, with
  "names no resource the PDP can read". It does not let it through unidentified.
- **Edits arrive as `Write`**, carrying the whole new file. A rule for `Edit`
  does not apply to Cursor.
- **`Delete` has no equivalent in the shared tool names.** It is decided as
  `Delete`, with the file it names, and is refused unless a delegation grants
  `Delete` and the tool catalog gives it a tier.
- **`Grep` is also Cursor's file finder** and names no file, so path rules and
  classification labels cannot apply to a search.
- **`Task` is decided under its own name**; nothing is read from its input.
- **MCP tools arrive as `MCP:<tool>`**, without the server's name.
- **Inline completions (Tab) are not tool calls** and no hook can refuse them.
- **Cloud agents** do not load user hooks at all.
- **A request for approval.** Cursor does not act on "ask" from this hook, so a
  decision that needs approval waits inside the hook, as it does elsewhere.

## When the tool runs without a decision

Cursor runs the tool call when a hook crashes, exits with a code other than `0`
or `2`, times out or prints nothing. `"failClosed": true` on the entry reverses
that, and the installer sets it. What remains:

- **The entry is removed or edited**, or `failClosed` is taken off. See
  [Can the agent remove it?](#can-the-agent-remove-it).
- **The first prompt after Cursor starts** can be sent before hooks have loaded.
  Cursor has a team setting, "Block until hooks are ready", that closes this.
- **`sessionStart` does not hold a session back.** It runs
  [`stratium-pep session-start`](../session-start.md) alongside the session; a
  tool call that arrives before it finishes is refused for want of a session.
- Whether the CLI's `--force` skips hooks is not stated in Cursor's
  documentation.

## Can the agent remove it?

With the install above, yes: `~/.cursor/hooks.json`, the binary and the hook's
environment are all the agent's own user's to change. `status` prints a warning
for each.

```sh
sudo -E deploy/stratium --cursor install --system --bin ./bin/stratium-pep
```

The system install puts the binary in `/opt/stratium/bin`, the configuration in
`/etc/stratium/pep.env`, and the entries in Cursor's administrator file
(`/Library/Application Support/Cursor/hooks.json` on macOS,
`/etc/cursor/hooks.json` on Linux), added to whatever that file already holds.
Cursor runs every matching hook from every level and a deny from any of them
wins, so a user or project file cannot cancel it.

- **Cursor's documentation says administrator hooks need an Enterprise plan.**
  Whether the file is read without one is not known. Check that a tool call is
  refused before relying on it.
- The binary and configuration are shared with the other harnesses' system
  installs; `uninstall --system` keeps them while another install uses them.

## Reporting

After a tool call, `stratium-pep report` tells the PDP it ran, so the PDP can
flag a call it never allowed. Cursor also fires its failure hook for a call that
was refused; that one is not reported, because it did not run.

## If you also use Claude Code

Cursor can load hooks from Claude Code's settings files (Settings → Agents →
Third-Party Imports, on by default). A Stratium hook installed for Claude Code
in a project would then run in Cursor too, without `--harness cursor`. What it
would decide there has not been tested. Turn the import off, or install for
Claude Code at a level Cursor does not read.
