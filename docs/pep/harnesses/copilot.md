# GitHub Copilot CLI

Stratium checks Copilot CLI's tool calls through Copilot's own hooks:
[`stratium-pep hook --harness copilot`](../hook.md) runs on `preToolUse`, before
every tool call.

**How this was verified.** Run in live sessions of Copilot CLI 1.0.114 on macOS
(`copilot -p`), with the hooks in a scratch repository's `.github/hooks/`:

- Copilot ran all four hooks, and `sessionStart` produced a delegation;
- `view`, `apply_patch` and `bash` calls were decided and allowed, including a
  patch that edited one file and created another;
- an `apply_patch` the delegation did not grant was refused, the model was shown
  the PDP's reason, and the file was not created;
- allowed calls were reported and matched their decisions; the refused call was
  not reported;
- the inputs of `view`, `apply_patch`, `rg`, `glob` and `bash` in the table
  below are the ones Copilot sent.

Not observed, and described here from GitHub's documentation as read on
2026-11-20: the user-level and policy installs, the `create`, `edit` and
`str_replace_editor` tools, the web tools, subagents, MCP tools, what Copilot
does when the hook times out, and Copilot in VS Code or the cloud agent.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --copilot install --bin ./bin/stratium-pep
```

This writes `~/.copilot/hooks/stratium.json`, a file of its own in the directory
Copilot reads user hooks from:

```json
{
  "version": 1,
  "hooks": {
    "sessionStart":       [ { "type": "command", "bash": "/usr/local/bin/stratium-pep session-start", "timeoutSec": 15 } ],
    "preToolUse":         [ { "type": "command", "bash": "/usr/local/bin/stratium-pep hook --harness copilot", "timeoutSec": 150 } ],
    "postToolUse":        [ { "type": "command", "bash": "/usr/local/bin/stratium-pep report --harness copilot", "timeoutSec": 15 } ],
    "postToolUseFailure": [ { "type": "command", "bash": "/usr/local/bin/stratium-pep report --harness copilot", "timeoutSec": 15 } ]
  }
}
```

Copilot reads hooks when it starts, so restart it after installing.
`deploy/stratium --copilot status` checks the install and `uninstall` removes
it. The installer does not write a repository's `.github/hooks/`: Copilot runs
those only once the folder is trusted.

## How the hook answers

- **Allow:** nothing on stdout. Copilot then carries on with its own permission
  checks, so a Stratium allow does not skip a prompt Copilot would have shown.
- **Refuse:** `{"permissionDecision":"deny","permissionDecisionReason":"…"}` on
  stdout, the reason on stderr, and exit code `2`, which Copilot treats as a
  deny whatever stdout holds. In the sessions above the model was shown the
  reason.

`--harness copilot` is on `report` as well. Copilot's payload uses its own field
names, and the report has to be read the same way the decision was.

## What a tool call is decided as

| Copilot tool | Decided as | What the PDP reads |
|---|---|---|
| `bash` | `Bash` | the command |
| `view` | `Read` | the file path, from `path` |
| `apply_patch` | `Edit` | every file the patch names, each checked as its own `Edit` |
| `create` | `Write` | the file path, from `path` (assumed) |
| `edit`, `str_replace_editor` | `Edit` | the file path, from `path` (assumed) |
| `grep`, `rg`, `glob` | `Grep`, `Grep`, `Glob` | nothing |
| `web_fetch`, `web_search` | `WebFetch`, `WebSearch` | nothing |
| any other | its own name | nothing |

Which file tools a session has depends on its model. The sessions above used
`apply_patch` for every edit and every new file, so **a rule for `Write` did not
apply to them: a new file was an `Edit`.**

A relative path is resolved against the working directory Copilot reports. A
path with a `..` segment, or one starting with `~`, is refused.

## What is not covered

- **The inputs of `create`, `edit` and `str_replace_editor` are assumed.** If
  Copilot sends the path under another name, the PDP finds no file and
  **refuses the call**, with "names no resource the PDP can read". It does not
  let it through unidentified.
- **Other tools are decided under their own names**: `task`, `powershell`, the
  shell-session tools (`read_bash`, `write_bash`, `stop_bash`), `skill` and the
  rest are refused unless a delegation grants that name.
- **MCP tools.** GitHub's documentation does not say whether they reach this
  hook or under what name.
- **Copilot in VS Code and the cloud agent** are different surfaces and have not
  been looked at.

## When the tool runs without a decision

- **The hook passes its timeout.** Copilot then runs the tool call, and its
  documentation says this holds for every hook, policy hooks included. The
  installer sets the timeout above the longest the hook can take; `status`
  fails when it is too short.
- **The hook prints something that is not JSON and exits `0`.** Copilot treats
  that as no decision. The hook never does this on purpose: every refusal and
  every failure of its own exits `2`.
- **The hook file is broken or gone.** A file Copilot cannot parse is dropped
  and the session runs with no hook.
- **The session sandbox** can block the hook from reaching the PDP when the hook
  is a user or repository hook. That is a refusal, not a run, but it refuses
  everything. Policy hooks run outside the sandbox.

A hook that crashes or exits with any other non-zero code is a refusal in
Copilot, with a fixed message.

## Can the agent remove it?

With the install above, yes. `~/.copilot/hooks/stratium.json`, the binary and
the hook's environment are the agent's own user's to change, and a repository
`settings.json` with `"disableAllHooks": true` switches off user hooks for
sessions in that repository. `status` prints a warning for each writable file.

```sh
sudo -E deploy/stratium --copilot install --system --bin ./bin/stratium-pep
```

The system install puts the binary in `/opt/stratium/bin`, the configuration in
`/etc/stratium/pep.env`, and the hooks in
`/etc/github-copilot/policy.d/50-stratium.json`. Copilot reads that directory as
policy hooks: they run whatever folder trust says, and `disableAllHooks` does
not switch them off.

- It does not stop a user adding hooks of their own. Copilot has a managed
  setting for that (`allowManagedHooksOnly`), which this installer does not
  set.
- The timeout rule above applies to policy hooks too.
- The binary and configuration are shared with the other harnesses' system
  installs; `uninstall --system` keeps them while another install uses them.
- A user with `sudo` can undo it.

## Reporting

After a tool call, `stratium-pep report --harness copilot` tells the PDP it ran,
so the PDP can flag a call it never allowed.
