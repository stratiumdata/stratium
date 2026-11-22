# Antigravity CLI support — implementation design

Status: approved 2026-11-22, with the recommendations in "Open questions" taken as written
(refusal by exit 0, allow by silence, no system install, the name `antigravity`)

Antigravity CLI (`agy`) replaced Gemini CLI for individual and Google AI plan
users on 2026-06-18. It is a different program with its own hook contract.
This document says how Stratium should support it. It follows the template in
`2026-11-20-harness-integrations-design.md` §5, with the differences called
out.

Outcome notes (built):

- **A tenant catalog row no longer beats an alias.** The live sessions hit a
  name collision: the seeded MCP filesystem catalog has `read_file`,
  `write_file` and `edit_file`, and under the old rule Antigravity's tools
  were decided as those, with another tool's field names and no file
  identity. A caller that names its harness has said whose tool it is, so
  the alias now applies whatever the catalog holds. A higher tier on a
  same-named row is still honoured. This reverses "a tenant's own row for a
  native name beats the alias" in `2026-11-20-harness-integrations-design.md`
  and applies to every harness.
- **A malformed `hooks.json` is ignored without a warning** and every call
  runs. Found by getting the shape wrong in a test driver. The docs page says
  so.
- `session-start` printing nothing is accepted on `SessionStart`.
- **Interactive check done, 2026-11-22.** With a Stratium allow (silence)
  Antigravity still shows its own prompt in the default mode. Approving runs
  the tool and `PostToolUse` fires; declining runs nothing and no
  `PostToolUse` fires, leaving an allow with no call behind it. A deny shows
  the reason with no prompt, in the default and `auto` modes.
- No report was filed for a call the hook refused, so `report` needs no skip
  rule here.

## Intent

`stratium-pep hook --harness antigravity` decides every Antigravity CLI tool
call before it runs, the same way it does for the other harnesses: rules
written for `Bash`, `Read`, `Write`, `Edit` and the rest apply, a refusal
reaches the model with the PDP's reason, and the docs say plainly what is not
covered.

## What was established, and how

Three sources. Where they disagree, the live result is what the design uses.

| Source | What it is |
|---|---|
| **Live** | `agy` 1.5.14 on macOS, print mode (`agy -p`), a recording hook and a probe hook in a scratch project's `.agents/hooks.json`. Four sessions. Antigravity's own permission system was left on. |
| **Bundled guide** | `agy-customizations/docs/hooks.md`, shipped inside the 1.5.14 install. |
| **Docs** | antigravity.google/docs (`/hooks`, `/build-plugins`, `/plugins`, `/settings`, `/permissions`, `/customization-discovery`, `/mcp`, `/cli/reference`, `/cli/headless`, `/remote-agents`, `/changelog`), read 2026-11-21. |

### The hook

- Command hooks only. JSON on stdin, JSON on stdout, camelCase keys. (Docs, bundled guide, live.)
- Events: `SessionStart`, `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`. (Docs.)
- File: `hooks.json`. User level `~/.gemini/config/hooks.json`; project level `.agents/hooks.json`, read from the working directory up to the repository root; or inside a plugin. Hooks in `settings.json` are not loaded. (Docs.)
- **No administrator level is documented.** The only scopes are workspace and personal. (Docs.)
- Shape: the top-level key is a hook *name*; each name holds events. `PreToolUse` and `PostToolUse` take groups with a `matcher` and a `hooks` list; `SessionStart` takes a flat list. `timeout` is in seconds, default 30. `"enabled": false` on a name switches it off. (Bundled guide.)

```json
{
  "stratium": {
    "SessionStart": [ { "type": "command", "command": "…", "timeout": 15 } ],
    "PreToolUse":   [ { "matcher": "*", "hooks": [ { "type": "command", "command": "…", "timeout": 150 } ] } ],
    "PostToolUse":  [ { "matcher": "*", "hooks": [ { "type": "command", "command": "…", "timeout": 15 } ] } ]
  }
}
```

### The payload (live)

```json
{ "toolCall": { "id": "call_…", "name": "read_file", "args": { "Path": "/proj/notes.txt" } },
  "stepIdx": 3, "hookEventName": "PreToolUse", "cwd": "/proj", "workspacePaths": ["/proj"],
  "conversationId": "…", "modelName": "…", "lastUserInput": "<the user's prompt>",
  "transcriptPath": "…", "artifactDirectoryPath": "…" }
```

`PostToolUse` sends the same `toolCall`, byte for byte in the sessions seen,
plus `error` (empty on success, the error text on failure). It fires for a
call that failed as well as one that succeeded.

`lastUserInput` is the user's prompt. The hook must not send it anywhere.

### Tool names: the docs and the live sessions disagree

| Purpose | Live (1.5.14) | Docs |
|---|---|---|
| Shell | `run_command` `{CommandLine, WaitMsBeforeAsync, toolSummary}` | `run_command` `{CommandLine, Cwd, …}` |
| Read | `read_file` `{Path}` | `view_file` `{AbsolutePath, …}` |
| Write | `write_file` `{Path, Content}` | `write_to_file` `{TargetFile, CodeContent, …}` |
| Edit | `edit_file` `{Path, Target, Replacement}` | `replace_file_content`, `multi_replace_file_content` `{TargetFile, …}` |
| List directory | none offered; the model used `read_file` on the directory, or the shell | `list_dir` `{DirectoryPath}` |
| Search contents | none offered; the model used the shell | `grep_search` `{SearchPath, Query, …}` |
| Find files | none offered; the model used the shell | `find_by_name` `{SearchDirectory, Pattern, …}` |
| Web search | `search_web` `{query}` | `search_web` `{query, domain}` |
| Web fetch | not seen | `read_url_content` `{Url}` |
| Subagent | `invoke_subagent` `{Prompt, Role, TypeName}` | `invoke_subagent` `{Subagents[]…}` |
| Other | `manage_task` | `manage_task`, `schedule`, `ask_permission`, `generate_image`, `call_mcp_tool`, `browser_*`, … |
| MCP | not seen | `mcp_<server>_<tool>`, or through `call_mcp_tool` |

Paths were absolute in every live call but one, which sent
`{"Path": "notes.txt"}`. Which tool set a session gets appears to depend on
the model or product surface. Both sets have to be mapped.

### What a hook answer does (live, print mode, a read tool)

| Hook answer | Result |
|---|---|
| exit 0, `{"decision":"allow"}` | tool ran |
| exit 0, `{"decision":"deny","reason":"R"}` | refused; model told `tool call denied by pre-tool hook: R` |
| exit 0, `{"decision":""}` or `{}` | refused, no reason |
| exit 0, `{"decision":"ask",…}` | tool ran (no prompt is possible in print mode) |
| **exit 0, nothing on stdout** | **tool ran** |
| exit 0, text that is not JSON | refused, with a parse error |
| exit 1, no output | refused: `JSON hook … failed: command failed: exit status 1` |
| exit 2, deny JSON on stdout, reason on stderr | refused; the model is shown the **stderr** text inside a "hook failed" message; stdout is ignored |
| hook passes its timeout | refused: `signal: killed` |

**This contradicts the docs**, which say "Any non-zero exit code is logged as a
hook execution error and ignored (failing open)". On 1.5.14 every failure
refused the call. The one way a call got through without a decision was a hook
that exits 0 and prints nothing.

Not established: what `allow`, `ask` and silence each do for a tool that would
normally prompt the user. In print mode three writes, one answered each way,
all ran. The bundled guide says `allow` means "Automatically allow the tool
execution" and `ask` means "Prompt the user for permission".

### Switching hooks off (docs)

- `"enabled": false` on the hook's name, or the `/hooks` command, turns any hook off.
- No managed or enterprise setting restricts or protects hooks.
- Project hooks need the workspace to be trusted.
- `/btw` side questions do not run user or workspace hooks.
- Remote agents (`--remote-agent`): hooks are not mentioned; local plugins, skills and MCP servers are not available there.
- Subagents inherit hooks unless a custom agent sets `inheritCustomizations: false`.
- `--dangerously-skip-permissions`: whether a hook's deny survives it is not documented and was not tested.

The contract is still moving: the changelog adds or changes hook fields in
1.4.7, 1.4.11, 1.5.4 and 1.5.6.

## Approaches

1. **A command hook in the user's `hooks.json`** (recommended). The same shape
   as every other harness: the installer writes one named hook, `stratium`,
   into `~/.gemini/config/hooks.json`. Nothing new to distribute.
2. **An Antigravity plugin** (`plugin.json` plus `hooks.json`), installed with
   `agy plugin install`. Easier to hand out, but it runs the same hook with
   the same weaknesses, adds `agy plugin disable` as another off switch, and
   needs the binary path and settings baked into a packaged file. Worth doing
   later as packaging, not as the first integration.
3. **Static `permissions.deny` rules** in Antigravity's settings. No external
   decision, so no delegations, no audit, no approvals. Not Stratium.

Approach 1.

## Design

### Adapter (`services/cmd/stratium-pep/harness.go`)

- **Name**: `antigravity`.
- **parse**: `toolCall.name` → `tool_name`, `toolCall.args` → `tool_input`
  (whole, untouched), `cwd` → `cwd`. Nothing else is read; `lastUserInput` is
  dropped. A payload with no `toolCall.name` is refused.
- **allow**: exit 0, nothing on stdout. It is the only answer observed that
  lets the call proceed without telling Antigravity to skip its own checks.
  `allow` is documented as an automatic approval, which would let a Stratium
  allow override a prompt the user would otherwise have seen.
- **deny**: `{"decision":"deny","reason":R}` on stdout, the reason on stderr
  too, **exit 0**. This is the one harness where a refusal does not exit 2:
  with exit 2 Antigravity discards stdout and shows the model a "hook failed"
  message. Every failure of the hook itself is turned into this same answer,
  as for the other harnesses. A crash that gets past that exits non-zero,
  which Antigravity refused in every case tested.
- **report**: `report --harness antigravity` on `PostToolUse`, reading the
  payload the same way. It prints `{}`, which is what Antigravity expects from
  that event.
- **session start**: `session-start` on `SessionStart`. It prints nothing;
  whether Antigravity accepts silence there is to be checked when building.

### Tool names (`internal/authz/alias.go`, harness `antigravity`)

Both vocabularies, since either may arrive.

| Antigravity tool | Decided as | Field |
|---|---|---|
| `run_command` | `Bash` | command: `CommandLine` |
| `read_file` | `Read` | path: `Path` |
| `view_file` | `Read` | path: `AbsolutePath` |
| `write_file` | `Write` | path: `Path` |
| `write_to_file` | `Write` | path: `TargetFile` |
| `edit_file` | `Edit` | path: `Path` |
| `replace_file_content`, `multi_replace_file_content` | `Edit` | path: `TargetFile` |
| `list_dir` | `LS` | path: `DirectoryPath` |
| `find_by_name` | `Glob` | none |
| `grep_search` | `Grep` | none |
| `read_url_content` | `WebFetch` | none |
| `search_web` | `WebSearch` | none |

Everything else keeps its own name and is refused unless a delegation grants
it: `invoke_subagent`, `manage_task`, `schedule`, `call_mcp_tool`,
`mcp_<server>_<tool>`, `browser_*`, `generate_image` and the rest.

A file tool whose path is missing, relative with no working directory, has a
`..` segment or starts with `~` is refused, as for the other harnesses. A
documented tool whose real field name turns out to differ is therefore
refused, not let through unidentified.

### Installer (`deploy/stratium --antigravity`)

- `install` writes the `stratium` key in `~/.gemini/config/hooks.json` and
  leaves every other key alone. `uninstall` removes that key.
- Timeouts in seconds; the decision hook's is set above the hook's own budget.
- `status` fails when the entry is missing, `"enabled": false`, the binary is
  not runnable, the configuration is incomplete, or the timeout is too short.
- User level only. A project `.agents/hooks.json` runs only in a trusted
  workspace.
- **No `--system`.** Antigravity has no administrator location for hooks, so
  there is nothing to write. `--antigravity install --system` stops with that
  explanation.

### Docs

`docs/pep/harnesses/antigravity.md`, with the usual four statements, and a row
in the harness table. The page opens with the limit below.

## What it cannot do

- **The user, and so the agent, can turn it off.** `"enabled": false`, the
  `/hooks` command, or editing the file. There is no install that prevents
  this. For a boundary that holds, the docs point to `proxy` and `extauthz`.
- **A hook replaced by something that prints nothing lets everything through.**
- **Remote agents** and `/btw` side questions are outside the hook.
- **Tools decided under their own names** carry no file or command identity.
- **The fail-closed behaviour is observed, not promised.** Antigravity's docs
  say the opposite, so the page will say what was seen on which version and
  not claim more.

## Verification

- Go: adapter tests fed the captured payloads; alias tests for both tool
  vocabularies, marked captured or documented; a test that `lastUserInput`
  never reaches the request.
- Installer self-tests: install beside another named hook, reinstall,
  `status` on each failure, uninstall, `--system` refused.
- Live, `agy -p` against a quickstart PDP, hooks in the user file or a trusted
  scratch project: allowed read, write, edit and shell; a refused write with
  the PDP's reason shown; reporting matched, including a failed call; no
  report for a refused call.
- Interactive check, by a person: with a Stratium allow, does Antigravity
  still show its own permission prompt?

## Open questions for the maintainer

1. **Refusal by exit 0.** It gives the model a clean reason, but it is the one
   harness that breaks the "a refusal exits 2" habit, and it relies on stdout
   being written. Exit 2 is also refused, with an uglier message. Recommended:
   exit 0.
2. **Allow by silence.** It is also the only fail-open answer. The alternative
   is an explicit `allow`, which may skip the user's own prompts. Recommended:
   silence, confirmed by the interactive check above before the docs claim it.
3. **No system install.** Acceptable for a first version, given Antigravity
   offers nowhere to put one?
4. **Plugin packaging.** Wanted later, or not at all?
5. **The harness name.** `antigravity`, or `agy` to match the binary?
