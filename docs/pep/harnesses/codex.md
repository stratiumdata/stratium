# Codex

Stratium checks Codex's tool calls through its hooks:
[`stratium-pep hook --harness codex`](../hook.md) runs on `PreToolUse`, before
every tool call.

**How this was verified.** It was not run in a live Codex session. The facts on
this page were read from Codex's source at version 0.133.0.

---

## Installing

```sh
# with the STRATIUM_PEP_* variables exported, as for any hook install
deploy/stratium --codex install --bin ./bin/stratium-pep
```

This writes three events into `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep session-start",
                     "timeout": 15 } ] }
    ],
    "PreToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep hook --harness codex",
                     "timeout": 330 } ] }
    ],
    "PostToolUse": [
      { "matcher": "*",
        "hooks": [ { "type": "command",
                     "command": "/usr/local/bin/stratium-pep report",
                     "timeout": 15 } ] }
    ]
  }
}
```

**Only `~/.codex/hooks.json`.** Codex also reads `<repo>/.codex/hooks.json`,
but project-local hooks are disabled until the project is trusted, and a
disabled enforcement hook is not inert, it is fail-open.

**Approve the hooks.** Codex will not run a hook in this file until you have
reviewed it. A freshly installed hook, or one whose command changed, is listed
as untrusted and **is not enforcing**. Approve all three in the `/hooks`
browser, or use the [system install](#the-system-install), whose hooks need no
review.

The command must be an absolute path, and the `PreToolUse` `timeout` must be
above the hook's own time budget; the installer computes it. See
[Installing in any harness](../hook.md#installing-in-any-harness).

An older install runs a `stratium-codex-hook` shell script instead. It still
works, but the PDP is not told the harness, so `apply_patch` is decided under
its own name. Re-run `deploy/stratium --codex install` to replace it.

## How the hook answers

- **Allow:** exit `0`.
- **Refuse:** the reason on stderr and **exit `2`**. Codex does not run the tool
  and shows the model whatever is on stderr.

With `--harness codex`, every outcome that is not a clean allow exits `2` with
the reason on stderr, including a failure of the hook itself.

## What a tool call is decided as

`--harness codex` tells the PDP whose tool names these are. Codex reports its
shell tool as `Bash`, as Claude Code does, but edits files with a tool called
`apply_patch`.

| Codex tool | Decided as | What the PDP reads |
|---|---|---|
| `Bash` | `Bash` | the command |
| `apply_patch` | `Edit` of every file the patch names | the paths of the files it adds, updates, deletes and moves to |
| any other | its own name | what the tool catalog's entry for that name declares, if there is one |

The audit entry keeps the name Codex sent and notes
`[apply_patch decided as Edit]`.

### A patch is an `Edit` of every file it names

The PDP reads the paths out of the patch text, resolves relative ones against
the working directory Codex reported, and then:

- a delegation's path constraint must hold for every file;
- the strictest classification label among the files applies to the call;
- policies are asked about each file in turn, as an `Edit` of that file. One
  refusal refuses the whole patch; failing that, one file that needs approval
  puts the whole patch up for approval.

What follows from that:

- **Write rules against `Edit`.** A rule that names `apply_patch` does not
  match a call from Codex. A tier override on `apply_patch` is still honoured
  when it is higher than `Edit`'s tier.
- **A patch that deletes a file** has `Edit`'s tier (`INTERNAL_MODIFY`), the
  same tier as a plain `rm` of one file.
- **A patch the PDP can read no file from is refused.** So is one that names a
  relative path when no working directory was reported, and one with a `..`
  segment in any path.
- **Paths are compared as written.** Symbolic links are not followed, as for
  any other tool.
- **A tool catalog entry for `apply_patch` does not change this:** when the hook
  names its harness, the harness's tool is decided as the shared tool. A higher
  tier on such an entry is still honoured.

## When the tool runs without a decision

Codex decides when a hook runs and what a failed hook means. These cases run the
tool call without a decision, and nothing in the hook file changes them:

- **The hook is not trusted yet, or is switched off** in the `/hooks` browser.
- **The hook runs past its `timeout`.**
- **The hook exits with a code other than `0` or `2`**, for example because the
  binary is missing. `--harness codex` turns every refusal and every failure of
  the hook itself into exit `2`; a command that cannot start is outside its
  reach.
- **Hooks are turned off** in the user's Codex configuration.
- **A subagent** started inside a session does not run `SessionStart`. It uses
  the delegation of the session that started it.

The [system install](#the-system-install) removes the first and the fourth. The
others hold under it too.

## Can the agent remove it?

With the install above, yes. `~/.codex/hooks.json`, the binary and the hook's
environment are the agent's own user's to change. See
[What the install protects](../hook.md#what-the-install-protects).

### The system install

```sh
# with the STRATIUM_PEP_* variables exported, as for a per-user install
sudo -E deploy/stratium --codex install --system --bin ./bin/stratium-pep
```

It puts the binary in `/opt/stratium/bin` and the configuration in
`/etc/stratium/pep.env`, as the other harnesses' system installs do, and the
hook entries in `/etc/codex/requirements.toml`, which Codex reads as an
administrator's requirements:

- the three hooks above, as managed hooks. Codex runs a managed hook without
  asking the user to review it, and the `/hooks` browser cannot switch one off;
- `allow_managed_hooks_only = true`. Codex then ignores every hook that is not
  in this file: the ones in `~/.codex/hooks.json`, in a project, and in plugins.
  **This switches off hooks you may rely on for other things;**
- `hooks = true` under `[features]`, so a user configuration cannot turn hooks
  off.

What to know before running it:

- **Codex has one such file.** If `/etc/codex/requirements.toml` exists and this
  installer did not write it, the installer stops and changes nothing.
  `--dry-run` prints the entries to add by hand. `uninstall --system` likewise
  leaves a file it did not write.
- **Another requirements source can displace the hooks.** Codex reads
  cloud-managed requirements and device-management preferences before this
  file, and for each setting the first source that sets it wins. If one of them
  sets hooks, the hooks in this file are not used.
- **The binary and the configuration are shared** with the other harnesses'
  system installs. `uninstall --system` for one harness keeps both while another
  harness's hook file still runs the binary.
- What the system install does not change, for any harness, is under
  [What the install protects](../hook.md#what-the-install-protects).

## Sessions and reporting

- `SessionStart` runs [`stratium-pep session-start`](../session-start.md).
  A subagent does not run it; see above.
- `PostToolUse` runs `stratium-pep report`, so the PDP can flag a call it never
  allowed. See [Reporting tool calls](../hook.md#reporting-tool-calls).
- **Codex reports only tool calls that succeeded.** It has no event for a tool
  call that failed, so one that ran undecided and failed is not counted.
