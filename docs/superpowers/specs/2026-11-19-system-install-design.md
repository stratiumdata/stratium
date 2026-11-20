# System-level hook install — design

Status: approved 2026-11-19 · built

Outcome notes: with `--config` the file is the whole configuration (every
`STRATIUM_PEP_*` environment variable is ignored), which is stricter than
"values in the file win" below. `"onFailure": "block"` was confirmed on Claude
Code 2.1.329 and is in both install kinds. Codex is not covered: no real run
was available to confirm its system hook file.

## Intent

A per-project install puts the hook entry, the PEP binary and the PEP's
configuration where the governed agent can write. An agent that edits any of
them is no longer governed. This change adds an opt-in install that puts all
three where only an administrator can write, makes the tooling say which kind
of install it is looking at, and makes the docs state what each kind protects.

## Goals

- `deploy/stratium install --system` produces an install the agent's own OS
  user cannot alter.
- `status` and `doctor` flag an install whose hook entry, binary or
  configuration is writable by the current user.
- The docs say plainly what a per-project install does and does not protect.

## Non-goals

- Making the quickstart require sudo. The per-project install stays the default.
- A PDP-side "session went quiet" signal. Separate change.
- Defending against a user who has sudo, or an agent running as root.
- Windows.

## Anti-goal

Claiming more than the harness guarantees. Both harnesses describe hooks as a
guardrail; where their docs are silent (for example whether `claude --bare`
skips managed hooks) the docs here say "untested" or report what we measured.

## Approaches

1. **Opt-in `--system` install (chosen).** Quickstart unchanged; hardening is
   one command with sudo; tooling and docs make the difference visible.
2. **System install by default.** Safer out of the box, but the first five
   minutes and CI both need root. Rejected by the maintainer.
3. **Integrity check only** (the hook verifies its own binary/settings hash).
   Rejected: the checker lives where the agent can write, so it proves nothing.

## Design

`install --system` must run as root (it refuses otherwise, except with
`--dry-run`) and does three things:

1. **Binary.** Copies the PEP binary to `/opt/stratium/bin/stratium-pep`,
   owned by root, mode 0755, creating `/opt/stratium` root-owned. Refuses if
   any directory on that path is writable by a non-root user.
2. **Configuration.** Writes the `STRATIUM_PEP_*` values the hook needs to
   `/etc/stratium/pep.env` (root-owned, 0644, `KEY=value` lines). The binary
   gains one flag, `--config <file>`: values in the file win over the
   environment, so a project settings file that sets `STRATIUM_PEP_PDP_ADDR`
   cannot redirect the hook. Without the flag nothing changes.
3. **Hook entry.** Claude Code: writes
   `managed-settings.d/50-stratium.json` in the managed settings directory
   (`/Library/Application Support/ClaudeCode` on macOS, `/etc/claude-code` on
   Linux) with the SessionStart and PreToolUse hooks, the absolute binary
   path, `--config /etc/stratium/pep.env`, and `"onFailure": "block"` on
   PreToolUse. Codex: writes the hook to `/etc/codex/hooks.json`.

`uninstall --system` removes exactly what `install --system` wrote.

The session file stays user-writable: it holds the agent's own delegation,
the PDP verifies it, and a missing or corrupt one already denies. Its path is
pinned in `pep.env`.

`status` and `doctor` gain one check, for every install: is the settings
file, the binary, or the config file (or a directory above any of them)
writable by the current user? If so they print a warning naming the file and
pointing at `install --system`. It is a warning, not a failure, so the
quickstart still reports healthy.

Docs: a "What the hook install protects" section in `docs/pep/hook.md`
(linked from `docs/pep.md` and the user guide's install and uninstall
sections) covering the two install kinds, the residual limits, and that the
MCP and proxy modes are the stronger boundary because the agent never holds
the credential there.

## Calls made by the author (not decided by the maintainer)

- Config file read by the binary, rather than an `env` block in managed
  settings: works the same for both harnesses and does not depend on a
  harness's precedence rules.
- `/opt/stratium/bin` rather than `/usr/local/bin`, which Homebrew often
  makes user-writable.
- `"onFailure": "block"` is also added to the per-project PreToolUse entry if
  testing confirms the installed Claude Code honours it.
- One machine-wide config; no per-user configs.
- Codex ships in this change only if a real run confirms a system
  `hooks.json` is honoured and cannot be switched off from user config;
  otherwise the docs say the system install covers Claude Code only.

## Verification

- `selftest`: `install --system` / `uninstall --system` round trip against a
  temporary root directory; the writable-path check against a temp tree.
- Go tests for `--config`: file wins over environment, missing file is an
  error (deny), absent flag is unchanged behaviour.
- One real run on a Mac, with sudo, by the maintainer: confirm the managed
  hook fires, that a project settings file cannot remove or redirect it, and
  record what `claude --bare` and a hook timeout do. Results go in the docs.

## Left to the builder

Exact warning wording, the `pep.env` parser (reuse an existing one if the
repo has it), and how the temporary root is passed in tests.
