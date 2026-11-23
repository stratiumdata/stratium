# Claude Code

Stratium checks Claude Code's tool calls through its hooks:
[`stratium-pep hook`](../hook.md) runs on `PreToolUse`, before every tool call.
Claude Code's hook contract is the hook's default, so it takes no `--harness`
flag.

**How this was verified.** Run in live sessions of Claude Code. On 2.1.329
(macOS):

- `"onFailure": "block"` blocked a tool call when the hook timed out or could
  not run;
- with the [system install](#the-system-install) in place, the hook still
  decided the call under each of the attempts to switch it off listed there.

The [example](../../../example/hook/) holds a captured Claude Code transcript
that hits the deny path.

Not observed: `--bare`, and a system install alongside a device-management
profile or server-managed settings.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium install --claude --bin /opt/stratium/bin/stratium-pep
```

This writes the block below into `.claude/settings.json`, merging into whatever
the file already holds:

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

`deploy/stratium status` checks the install and `uninstall` removes it.

The command must be an absolute path, and the `PreToolUse` `timeout` must be
above the hook's own time budget. Both rules, and the arithmetic behind `150`,
are in [Installing in any harness](../hook.md#installing-in-any-harness).

**Keep `"onFailure": "block"`.** With it, Claude Code blocks the tool call when
the hook times out or fails to run, instead of letting it through. It is a
second line behind the two rules above, not a replacement for them.

> Installing `SessionStart` re-issues a delegation on every session start. If you
> are testing a delegation you built by hand, install `--only PreToolUse` — the
> `SessionStart` half will discard your work at the next launch.

## How the hook answers

- **Allow:** exit `0`, silent. Claude Code then applies its own permission
  rules, so the user is still asked wherever Claude Code would have asked.
- **Refuse:** **exit `2`** with Claude Code's deny JSON on stdout. Claude Code
  does not run the tool and shows the model the reason:

```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"}}
```

## What a tool call is decided as

Claude Code's tool names are the canonical ones the PDP's default tool catalog
is written in (`Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` and
the rest), so each tool is decided under its own name and nothing is
translated. The other harnesses' pages map their tools onto these names, so a
policy, tool list or tier override written for `Edit` covers every harness.

`Bash` is catalogued with a command field and no resource field, and `Glob`,
`Grep`, `WebFetch`, `WebSearch` and `TodoWrite` declare no resource field at
all. See [Traps](../hook.md#traps) for what that means under a classification
cap.

## Can the agent remove it?

With the install above, yes. The agent runs as you, and three things sit where
you can write:

- the hook entry in `.claude/settings.json`: removing it removes enforcement,
  immediately;
- the binary: replacing it replaces the decision;
- the configuration, in the environment, which a project settings file can set:
  pointing `STRATIUM_PEP_PDP_ADDR` elsewhere changes who decides.

`deploy/stratium status` and `doctor` print a warning for each one the current
user can change. See [What the install protects](../hook.md#what-the-install-protects).

### The system install

```sh
# with the STRATIUM_PEP_* variables exported, as for a per-project install
sudo -E deploy/stratium --claude install --system --bin ./bin/stratium-pep
```

| What | Where |
|---|---|
| The binary | `/opt/stratium/bin/stratium-pep` |
| The configuration | `/etc/stratium/pep.env`, read through `--config` |
| The hook entry | Claude Code's managed settings: `/Library/Application Support/ClaudeCode/managed-settings.d/50-stratium.json` on macOS, `/etc/claude-code/managed-settings.d/50-stratium.json` on Linux |

Claude Code merges hooks from managed settings with every other scope, and a
user or project settings file cannot remove or disable them. **Observed** on
Claude Code 2.1.329 (macOS), with the system install in place the hook still
decided the call when:

- a project `.claude/settings.json` set `"disableAllHooks": true` and its own
  `STRATIUM_PEP_PDP_ADDR`;
- the session was launched with `--settings '{"disableAllHooks": true}'`;
- the session was launched with `--setting-sources ""`;
- the session was launched with `--safe-mode`.

`--bare` was not tested. `sudo deploy/stratium --claude uninstall --system`
removes the three files, and `deploy/stratium --claude status --system` reports
on them.

- **Another policy source can displace the file.** When a device-management
  profile or server-managed settings are also present, Claude Code may use that
  source and ignore the file. Run `/status` in a session and check that the
  managed settings are listed.
- **The binary and the configuration are shared** with the other harnesses'
  system installs; `uninstall --system` keeps them while another install uses
  them.
- What the system install does not change, for any harness, is under
  [What the install protects](../hook.md#what-the-install-protects).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md). It
  carries no `matcher` on purpose, so it runs for every session source —
  `startup`, `resume`, `clear`, `compact`, `fork`. A resumed session gets a
  fresh delegation rather than trusting whatever the file holds.
- `PostToolUse` and `PostToolUseFailure` run `stratium-pep report` (a tool call
  that fails still ran), so the PDP can flag a call it never allowed. See
  [Reporting tool calls](../hook.md#reporting-tool-calls).
