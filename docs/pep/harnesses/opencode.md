# OpenCode

Stratium checks every OpenCode 2.x tool call through a small plugin. OpenCode
has no command hooks, so the plugin is the hook: before each tool call it runs
[`stratium-pep hook --harness opencode`](../hook.md) and rejects the call unless
that allows it.

**How this was verified.** Everything on this page about OpenCode was read from
its source and docs at version 2.3.2. The plugin's own logic is tested with a
stand-in for OpenCode's plugin interface. **It has not been run inside
OpenCode.** OpenCode 1.x has a different plugin interface and is not supported.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --opencode install --bin ./bin/stratium-pep
```

This writes, in `~/.config/opencode` (or `$OPENCODE_CONFIG_DIR`):

| What | Where |
|---|---|
| The plugin | `stratium-guard/index.js` and `package.json` |
| The plugin's settings | `stratium-guard/stratium.json`: the binary's path and how long to wait for it |
| The entry that loads it | the plugin's path, added to `plugins` in `opencode.json` |

The plugin reads `STRATIUM_PEP_*` from the environment OpenCode was started in,
so export them in that shell. `deploy/stratium --opencode status` checks the
install and `uninstall` removes it.

If the directory has an `opencode.jsonc`, the installer stops and changes
nothing: it does not rewrite a file with comments. `--dry-run` prints what to
add by hand.

## What a tool call is decided as

OpenCode's tool names are mapped to the names Stratium rules are written
against. The audit trail keeps the name OpenCode sent and notes, for example,
`[shell decided as Bash]`.

| OpenCode tool | Decided as | What the PDP reads |
|---|---|---|
| `shell` | `Bash` | the command |
| `read`, `write`, `edit` | `Read`, `Write`, `Edit` | the file path |
| `patch` | `Edit` | every file the patch names, each checked as its own `Edit` |
| `glob`, `grep` | `Glob`, `Grep` | nothing |
| `webfetch`, `websearch` | `WebFetch`, `WebSearch` | nothing |

OpenCode sends file paths relative to the directory it runs in. The PDP resolves
them against that directory, so a path constraint or a classification label
applies to the file actually touched. It refuses a file call when it cannot do
that from the text alone:

- a path with a `..` segment;
- a path starting with `~`, which OpenCode expands to a home directory the PDP
  does not know.

Symbolic links are not followed.

## What is not covered

- **Every other tool is decided under its own name.** `todo`, `question`,
  `skill`, `subagent`, MCP tools and the rest are refused unless a delegation
  grants that exact name. MCP tools appear as `<server>_<tool>`.
- **Code Mode.** The model can call a tool named `execute` whose input is a
  program. That outer call is decided as `execute`; each tool call the program
  then makes is decided separately, as above.
- **A shell command's working directory.** `shell` can name a `workdir`. Paths
  inside the command are read as written, as they are for Claude Code.

## When the tool runs without a decision

Once the plugin is loaded, every failure refuses the call: the binary is
missing, it does not answer in time, the settings file is unreadable, the PDP is
down. The cases below are the ones where the plugin is not there to refuse:

- **The plugin fails to load.** OpenCode logs "failed to load plugin" and carries
  on without it. A broken or deleted `index.js` therefore removes enforcement
  with only a log line.
- **The plugin is switched off.** A `"-stratium.guard"` or `"-*"` entry in any
  `plugins` list removes it, and so does another plugin that loads first with
  the same id. The [system install](#the-system-install) closes both.
- **A different OpenCode.** A 1.x install, or one embedded through the SDK with
  system configuration switched off, does not load it.

## Can the agent remove it?

With the install above, yes: the plugin, its settings, `opencode.json` and the
binary are all files the agent's own user can change.
`deploy/stratium --opencode status` prints a warning for each.

### The system install

```sh
sudo -E deploy/stratium --opencode install --system --bin ./bin/stratium-pep
```

It puts the binary in `/opt/stratium/bin`, the hook's configuration in
`/etc/stratium/pep.env`, and the plugin in OpenCode's system directory
(`/Library/Application Support/opencode` on macOS, `/etc/opencode` on Linux),
all writable by root alone. In that directory's `opencode.json` it adds:

- the plugin to `plugins`. OpenCode applies the system file last, so a user's
  `"-stratium.guard"` does not remove it;
- two `plugin.use` policies: deny every plugin, then allow this one.
  **This switches off every other OpenCode plugin on the machine.** It is what
  stops a user plugin taking this plugin's id and loading in its place. If the
  file already denies every plugin, that statement is left as it is, and
  `uninstall --system` leaves it too.

What it does not change:

- macOS managed preferences outrank the system file.
- A plugin that fails to load is still skipped. Root-owned files make that
  unlikely, not impossible.
- The binary and configuration are shared with the Claude Code and Codex system
  installs. `uninstall --system` keeps them while another install uses them.
- A user with `sudo` can undo it.

## Sessions and reporting

- **There is no session-start hook in OpenCode.** The plugin runs
  [`stratium-pep session-start`](../session-start.md) when it is loaded. When
  that delegation expires, tool calls are refused until OpenCode is restarted.
- **Reporting.** After a tool call, successful or not, the plugin runs
  `stratium-pep report`, so the PDP can flag a call it never allowed. A call the
  plugin refused is not reported, because it did not run.
