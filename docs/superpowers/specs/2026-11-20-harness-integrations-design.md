# Support for more agent harnesses — design

Status: approved 2026-11-20 (including the patch-path reader after PR B)

Outcome notes, PR A (built): `--harness` is on `hook` only; `report` gets it
when a harness's after-the-call payload differs from Claude Code's (Codex's
does not). The audit row has no free-form field, so the canonical name is
appended to its reason text (`[apply_patch decided as Edit]`) and the
harness name is not recorded. An aliased call with no resource identity is
refused outright, not only under a path constraint: once aliased it is
matched by rules written for calls that name their resource.

Outcome notes, patch-path reader (built before PR B, because without it a
Codex file edit is always refused): an alias can name a `PatchField`; the PDP
reads the file headers out of the patch (`Add File`, `Update File`,
`Delete File`, `Move to`). Calls made while building it:

- Relative paths are resolved by the PDP against a new `DecideRequest.cwd`
  (field 16), which the hook passes through from the harness's payload. A
  relative path with no absolute cwd refuses the patch, and so does a `..`
  segment in any path.
- Path constraints and labels see every file, as they do for a shell command.
  Policies are asked once per file, each as an `Edit` of that file, and the
  strictest answer stands (deny, then escalate, then allow).
- A patch that deletes a file keeps `Edit`'s tier. A plain `rm` of one file is
  the same tier today.
- A tenant tier override keyed on the native name still raises the tier.
- A policy that names the native tool does not match an aliased call. This is
  documented, not detected.

Outcome notes, PR B (built): Codex gets `SessionStart` and `PostToolUse`
(`report` needs no `--harness`). Codex has no event for a failed tool call,
so those are not reported. `--codex install --system` writes
`/etc/codex/requirements.toml` whole, marked on its first line, and refuses
a file it did not write. Reading it back (`status --system`) uses a reader
for the installer's own output, not a TOML parser, because the oldest
supported Python has none.

Outcome notes, OpenCode (built): aliases gained a `PathField`, a file path
the PDP resolves against `cwd`, because OpenCode sends relative paths. The
rule that refuses an aliased call with no resource now covers file tools
only (a path or a patch that could not be resolved); search and web aliases
carry no resource, as their canonical tools do. The plugin lives in
`deploy/opencode/stratium-guard` and runs `session-start` when it loads,
OpenCode having no session-start hook. Run in live OpenCode 2.3.2 sessions
with the per-user install: allow, refuse and reporting observed for read,
edit, write and shell.

Outcome notes, Cursor (built): the adapter gained an `allow` output, because
Cursor reads silence as a failed hook. An alias may now map a harness tool
to the canonical tool of the same name; such an alias is not displaced by
the tenant's catalog row for that name, so the path field is the harness's
and a call without it is refused. `report` skips a call Cursor says was
denied. `Delete` has no canonical tool: it keeps its name and is given its
file's identity. Run in live sessions of Cursor's CLI (2026.11.19), which
confirmed `file_path`, that edits arrive as `Write`, and that the model is
shown the reason on a refusal.

Outcome notes, Copilot CLI (built): the adapter gained a `parse` step, for a
harness whose stdin is not Claude Code's, and `report` takes `--harness` so
it reads the payload the same way. The camelCase events are used, because
they carry Copilot's own tool names. Its `apply_patch` sends the patch text
as the whole input, so `PatchField` can be `WholeInput`. Run in live
sessions of Copilot CLI 1.0.114.

Outcome notes, Gemini CLI (built): no adapter changes beyond a deny format.
Its stdout must hold Gemini's decision JSON alone, since Gemini acts on
stdout JSON at any exit code and reads one with no decision as an allow.
The system install cannot stop a user disabling hooks by name, and the docs
page says so first. Not run in Gemini CLI: no credentials here.

## Intent

Stratium decides tool calls for Claude Code and, partly, Codex. The
maintainer wants it to work with the other agent harnesses people use, so
one set of policies governs an agent whichever harness runs it.

This is a programme of about a dozen pull requests. This document specifies
the first two in full (the shared foundation, then finishing Codex) and
fixes the template and the facts for the rest.

## Goals

- `stratium-pep hook` works as the pre-tool-call hook of each harness
  listed below, speaking that harness's input and deny format.
- A policy, a delegation tool list or a tier override written for `Bash`,
  `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch` or `WebSearch` applies
  to the equivalent tool of every supported harness. (Decided by the
  maintainer: one shared vocabulary, not per-harness names.)
- Every failure of the hook that the hook can control is a deny in the
  harness's own terms.
- Each harness's docs page says plainly what is not covered, when the
  harness runs the tool despite a failed hook, whether the agent can remove
  the hook, and how the integration was verified.

## Non-goals

- Agent frameworks (Claude Agent SDK, OpenAI Agents SDK, LangGraph, Google
  ADK, CrewAI, Pydantic AI, Microsoft Agent Framework). They are served by
  the Python SDK and get their own design.
- A TypeScript SDK (Vercel AI SDK would need one).
- Roo Code (archived), Continue (frozen; its hook code is never called),
  Aider (no hook, no MCP).
- Targeting the AGENT-HOOKS-0.1 contract. It is real but young; revisit if
  harnesses adopt it.
- One vocabulary for MCP tool names across harnesses (see "Known limits").

## Anti-goals

- An integration that looks like enforcement and is not: a harness whose
  hook cannot block, or that runs the tool when the hook fails, presented
  without saying so.
- The hook relabelling a call. `hook.go` forwards the tool name and the
  input bytes untouched so that a dishonest hook gains nothing; that stays
  true. Translation of names happens in the PDP.

## Constraints

- Only Claude Code can be run end to end on the maintainer's machine today.
  OpenCode can be (free, signed-out). Cursor and Kiro are installed but need
  a login for a model turn. The rest need paid accounts. What cannot be run
  is verified from source or official docs and labelled so.
- The research behind the tables below was read from source or docs on
  2026-11-20, not run. Each harness PR re-checks its own row before building.

## Approaches

**Where the per-harness format lives**

1. **A `--harness` flag on the existing binary (chosen).** One Go table of
   adapters, unit-tested with recorded payloads, works on Windows, and
   every failure path is already a deny in Go.
2. A shell shim per harness, as Codex has today. Needs `jq` to reshape
   payloads, cannot be unit-tested, no Windows.
3. A separate binary per harness. Same code, more artefacts to install.

**Where tool names are unified**

1. **In the PDP, by a built-in alias table (chosen by the maintainer).**
2. Native names, with catalog rows and policies per harness. A rule written
   for `Bash` would silently not apply to another harness.
3. In the hook. Ruled out by the anti-goal above.

## Design

### 1. Adapters in `stratium-pep`

`stratium-pep hook --harness <name>` and `stratium-pep report --harness
<name>`. Default `claude`, so existing installs are unchanged.

An adapter is two functions:

- **parse**: the harness's stdin bytes → tool name and input bytes. It may
  choose which sub-object of the payload is the input (some harnesses nest
  it, some send it as a JSON string). It never rewrites inside the input and
  never renames the tool.
- **deny**: a reason → that harness's blocking output (stdout JSON, stderr
  text, exit code).

An unknown `--harness` value writes the reason to stderr and exits 2, which
blocks in every harness researched. It is not a usage error that exits 1.

In-process harnesses (OpenCode, Amp) get a small plugin, shipped in the
repo, that spawns `stratium-pep hook --harness <name>` with the call as JSON
on stdin and rejects the call on any non-zero exit, spawn failure or
timeout.

### 2. Shared tool vocabulary in the PDP

**The hook says which harness it is.** `DecideRequest` gains a `harness`
string. `stratium-pep hook --harness <name>` sets it; `mcp`, `proxy` and
`extauthz` never do, and an older `stratium-pep` sends it empty. Empty
means no aliasing at all, so nothing changes for any existing caller.

This is a claim from the caller, and it is safe to take: all it does is
turn on a renaming the same caller could have done itself by sending
`Bash`. What it protects is the honest callers that forward names somebody
else chose. `stratium-pep mcp` passes on whatever an upstream MCP server
calls its tools; without the field, a third-party tool that happened to be
named `read` or `shell` would be decided as `Read` or `Bash`.

**The table.** Built into `internal/authz`, next to `DefaultCatalog`:

    (harness, native tool name) → { canonical name, command field, resource field }

`claude` has no rows: its names are the canonical ones. Keying on the
harness also means two harnesses may use one short name (`read`, `edit`)
with different input fields.

**Resolution**, at the point `Decide` builds the action:

1. `harness` empty, or no row for (harness, name): unchanged.
2. The tenant's `tool_catalog` has a row for the exact native name: that
   row is used and no alias applies. A tenant can always override.
3. Otherwise the action's tool becomes the canonical name for everything
   downstream: catalog lookup, tier, delegation and agent tool lists, tier
   overrides, policy evaluation.

**Fields.** An alias that names a command or resource field is a complete
extraction rule on its own: the PDP reads that field from the raw input
whether or not the tenant has a catalog row for the canonical tool. The
verb comes from the canonical tool's tenant row when there is one. An alias
with no fields extracts nothing.

**Rules written against a native name.** Once a name is aliased, a policy,
tool list or override that names the native tool no longer matches calls
from that harness; rules are written against the canonical name. A tenant
that wants the native name back adds a catalog row for it (step 2). The
docs say this on each harness page.

**What is recorded.** The decision, audit and approval rows keep the native
name, as received, so `ReportToolUse` (which matches on tool name and input
digest) and approval verification are unchanged. The audit entry also
records the harness and, when an alias applied, the canonical name.

### 3. PR A — foundation

- The adapter table with two entries: `claude` (today's behaviour) and
  `codex`. Codex's payload has the same `tool_name` / `tool_input` fields;
  its deny is the reason on stderr and exit 2, which is what the
  `stratium-codex-hook` shell shim does today (every non-zero outcome
  becomes exit 2; the reason goes to both stderr and stdout).
- The `harness` field, the alias table and its resolution, with Codex's one
  non-Claude name: `apply_patch` → `Edit`, no fields. (Codex already
  reports its shell tool as `Bash` with a `command` field.)
- Consequence of "no fields": a Codex file edit carries no resource
  identity. Under a delegation with a path constraint it is denied
  ("request identifies no resource"), and path-based labels and policies do
  not see the files. That is the fail-closed result and it is what PR A
  ships. Reading the file paths out of a patch is a separate, later PR (see
  "Open question").
- Installer: `--codex install` writes `stratium-pep hook --harness codex`.
  The old shim keeps working and is still recognised by `status` and
  `uninstall`. Docs drop the shim.

### 4. PR B — Codex completed

- `--codex install` also wires `PostToolUse` → `report --harness codex` and
  `SessionStart` → `session-start`. The installer comment saying Codex has
  no `SessionStart` is out of date as of Codex 0.133.0.
- `--codex install --system`: the hook in `/etc/codex/requirements.toml`
  with managed hooks only and the hooks feature pinned on, reusing the
  root-owned binary and `/etc/stratium/pep.env` from the Claude Code system
  install. If the file exists and was not written by this tool, the
  installer prints the block to add and exits non-zero; it does not merge
  into an administrator's file.
- Docs: Codex runs the tool when a hook times out or exits with anything
  but 2 (`codex-rs/hooks/src/events/pre_tool_use.rs`, 0.133.0).

### 5. Template for each later harness PR

1. Adapter entry, with table-driven Go tests fed the harness's payloads
   (captured from a run where possible, otherwise built from source/docs
   and marked so).
2. Alias rows for its shell, read, write, edit, search and web tools.
3. Installer entry: user-level install; system install where the harness
   has an administrator location; the harness's fail-closed option set
   wherever it offers one; a hook timeout above the approval wait.
4. `docs/pep/harnesses/<name>.md` with the four statements from Goals, and
   a row in a support matrix in `docs/pep/hook.md`.

A harness PR that follows this template does not come back for design
approval. One that cannot (a contract that differs from the table below in
a way that changes what can be blocked) does.

### 6. Order and facts

| # | Harness | Hook | Blocks every tool | Administrator lock | Tool runs despite a failed hook | Notes |
|---|---|---|---|---|---|---|
| 1 | OpenCode 2.x | JS plugin, `tool.hook("execute.before")` | Yes | Managed `plugin.use` policy | Only if the plugin fails to load | Runnable here. 1.x is not supported |
| 2 | Cursor | `preToolUse` in `hooks.json` | Yes, per docs | Root-owned `hooks.json` (may need Enterprise) | Yes, unless `failClosed: true` | Input shapes beyond `Shell` to be captured |
| 3 | Copilot CLI | `preToolUse` in `~/.copilot/hooks/` | Yes, per docs | `/etc/github-copilot/policy.d/`, managed-hooks-only | On timeout, always | `toolArgs` may be a JSON string |
| 4 | Gemini CLI | `BeforeTool` in `settings.json` | Yes, except ACP mode | System file, but a user can disable hooks | Yes: timeout, exit 1, bad output | No free tier |
| 5 | Kiro (CLI, IDE) | `PreToolUse` in `.kiro/hooks/` | Yes | None | Yes, except exit 2 | IDE docs conflict on non-zero exits |
| 6 | Goose | `PreToolUse`, Open Plugins format | Yes | None found | Yes, unless `on_failure: block` | Matcher `"*"` silently skips; use a regex |
| 7 | Devin Local (new Windsurf) | Claude-style `PreToolUse` | Yes | Not confirmed | Yes; `fail_closed` exists, barely documented | |
| 8 | Amp | TypeScript plugin, `tool.call` | Yes | Managed settings | Not confirmed | |
| 9 | Windsurf Cascade (legacy) | `pre_run_command`, `pre_write_code`, `pre_read_code`, `pre_mcp_tool_use` | No: web and search have no hook | Root-owned `hooks.json` | Yes, no option | Several events, one adapter |
| 10 | Cline | `PreToolUse` script | Only by cancelling the whole task | None | Always | Two payload shapes (extension, CLI) |
| 11 | Zed, JetBrains Junie | None | — | — | — | Docs only: `stratium-pep mcp`, and what stays ungoverned |

## Known limits

- **MCP tool names.** Each harness names an MCP tool differently in its hook
  (`mcp__server__tool`, `mcp_server_tool`, `server_tool`, `MCP:tool`). The
  alias table cannot cover names it does not know. An MCP tool reached
  through a non-Claude harness's hook arrives under that harness's spelling
  and needs its own catalog row. The docs recommend `stratium-pep mcp` for
  MCP tools, which is the same for every harness.
- **Patch-style edits.** `apply_patch` (Codex, and later Cline, Devin
  Local, OpenCode's `patch`) names its files inside a patch text, not in a
  field. Until the PDP can read them, such edits have no resource identity
  and are refused.

## Open question for the maintainer

Should reading file paths out of a patch be built now, right after PR A, or
left until a user of path constraints asks for it? It is a small parser but
it interprets input on the security path, like the shell path reader, so it
wants its own PR and tests. Recommended: right after PR B, before the first
new harness, because four of the harnesses use patch edits.

## Calls made by the author (not decided by the maintainer)

- The hook names its harness on the wire, and aliases are keyed on it
  (changed after review: keyed on the name alone, an MCP server's own tool
  names would have been aliased too).
- Once aliased, rules match the canonical name only.
- An alias with fields extracts without a tenant row for the canonical tool.
- A tenant's own catalog row for a native name beats the alias.
- The audit trail keeps the native name and adds the harness and the
  canonical name.
- `apply_patch` maps to `Edit`.
- The system installer refuses to merge into an existing administrator file.
- MCP tool names are left per harness.
- Two foundation PRs, not one.
- Later harness PRs skip design approval if they fit the template.

## Verification

- Go: adapter tests per harness; alias resolution tests (alias applies;
  empty harness is unchanged, including for a name that has an alias;
  tenant row wins; unknown name unchanged; an alias with a command field
  classifies a shell command with and without a tenant `Bash` row; a
  delegation listing `Bash` covers an aliased shell tool; a Codex
  `apply_patch` is denied for want of a resource identity; the audit row carries
  both names).
- The installer's built-in self-tests, extended for the Codex changes.
- `make integration`.
- A live Claude Code session against the quickstart stack after PR A, since
  the default path is touched.
- Codex: not run live (no account). Stated in the PR and the docs.

## Left to the builder

Identifier names; file layout; the exact `requirements.toml` keys (to be
taken from the Codex source at the installed version); whether Codex's
`SessionStart` and `PostToolUse` payloads need anything from the adapter;
how the audit entry carries the canonical name.
