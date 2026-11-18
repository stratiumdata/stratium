# Installing `stratium-pep`

`stratium-pep` is the client-side enforcement binary: it sits in front of a
real agent and asks the PDP (`stratium-pdp`) to decide every tool call over
gRPC before that tool call runs. It classifies nothing itself — see the
package doc in `services/cmd/stratium-pep/hook.go` for why that boundary is
load-bearing, not incidental.

It has two enforcement-surface subcommands today, both covered below: `hook`
(a Claude Code `PreToolUse` hook) and `mcp` (a stdio proxy that stands in for
an MCP server). Both are gated by the same `session-start` subcommand and the
same PDP call; they differ only in *how* a harness invokes them and how each
reports a denial back to it.

**Every tool call is denied until a session is started and a policy permits
it.** This holds for both `hook` and `mcp` — if you install either and see
every tool call denied, that is very likely correct, working behavior for an
agent that has no session yet, not a bug. Run `stratium-pep session-start`
first (below), and confirm a policy actually grants the agent the tool it's
asking for. See "Reading a denial" at the bottom for how to tell that apart
from a real misconfiguration or outage before filing one.

## Build

    cd services && go build -o /usr/local/bin/stratium-pep ./cmd/stratium-pep

Or place the binary anywhere on `PATH` — the examples below just invoke
`stratium-pep`.

## Environment variables

Every variable below is required, with no default (except where marked
optional): the same rule `internal/config.Load` uses for the PDP itself. A
surface that starts against a guessed PDP address, or that waits forever (or
not at all) for a reply, fails at the first tool call in a way that looks
like a policy denial rather than a misconfiguration. Set the same shared
values across every subcommand you run — they must agree on which PDP,
agent, and subject a session belongs to.

Shared by all three subcommands (`session-start`, `hook`, `mcp`):

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_PDP_ADDR` | `host:port` of the PDP, e.g. `localhost:50051`. |
| `STRATIUM_PEP_AGENT_ID` | The acting agent's registry UUID. |
| `STRATIUM_PEP_SUBJECT` | The principal the agent acts on behalf of (e.g. an email). |
| `STRATIUM_PEP_SESSION_FILE` | Path to the session file. `session-start` writes it; `hook` and `mcp` read it fresh on every single tool call, so a revocation or a fresh session takes effect on the very next one. |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | How long to wait for one PDP call before failing closed, e.g. `5s`. |
| `STRATIUM_PEP_PDP_CA_FILE` (optional) | PEM CA bundle to verify the PDP's TLS certificate with, instead of the system roots. Use it when a private CA issued the PDP's certificate. |
| `STRATIUM_PEP_PDP_INSECURE` (optional) | `true` connects to the PDP in plaintext, for a local development stack only. The default is TLS. Setting it alongside `STRATIUM_PEP_PDP_CA_FILE` is an error, and the PEP denies. |

`hook` and `mcp` only, in addition to the five above (`session-start` never
polls, so it has no use for either):

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | How often to re-check a pending escalation, e.g. `2s`. |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | How long to wait for a human to resolve an escalation before failing closed, e.g. `5m`. Bounds the *whole* wait, independent of `STRATIUM_PEP_CONNECT_TIMEOUT`, which bounds only one RPC round trip. |

`mcp` only:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_CACHE_STALENESS_WINDOW` | How long `mcp` may serve a decision from its in-memory cache without a fresh PDP round trip re-confirming it, e.g. `30s`. See "The decision cache" below before picking a value. There is no default. `hook` has no cache and ignores this variable. |

`session-start` only, in addition to the five shared above:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_REQUESTED_TIER` | Action-tier ceiling to request: `0` REASONING, `1` READ_ONLY, `2` INTERNAL_MODIFY, `3` EXTERNAL_COMMS, `4` DESTRUCTIVE. The PDP may grant less than this — the session file records what was actually granted, not what was requested. |
| `STRATIUM_PEP_REQUESTED_TOOLS` | Comma-separated tool names to request, e.g. `Read,Grep,Bash`. Must not be empty. Include discovery tools — see below. |
| `STRATIUM_PEP_TTL_SECONDS` | How long the new delegation is valid for, in seconds. |
| `STRATIUM_PEP_PURPOSE` (optional) | Free-text reason for the delegation, for audit legibility. |
| `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE` (optional) | Path to a file holding the principal's OIDC token, sent to the PDP as `principal_token`. Needed whenever the PDP verifies principals, which is the default; a PDP running with `STRATIUM_PRINCIPAL_AUTH_INSECURE=true` (the local stack) ignores it. An unreadable or empty file fails `session-start`. |
| `STRATIUM_PEP_ESCALATE_AT` (optional) | A lower escalation threshold than the agent's own, `0`–`4`. It can only make the session stricter, so leaving it unset changes nothing. |

`mcp` only, in addition to the seven shared by `hook` and `mcp` above:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_MCP_UPSTREAM_COMMAND` | The real MCP server's executable — whatever your harness would otherwise have launched directly. Must not be empty or all whitespace. |
| `STRATIUM_PEP_MCP_UPSTREAM_ARGS` (optional) | Comma-separated arguments to the upstream command, e.g. `--stdio,--verbose`. Empty is a legitimate value — many MCP servers take no arguments at all. |

## Starting a session

Before any tool call can be allowed, something has to run
`stratium-pep session-start` to create a delegation and cache the *granted*
scope (which may be narrower than what was requested) to
`STRATIUM_PEP_SESSION_FILE`:

    STRATIUM_PEP_PDP_ADDR=localhost:50051 \
    STRATIUM_PEP_PDP_INSECURE=true \
    STRATIUM_PEP_AGENT_ID=<agent-uuid> \
    STRATIUM_PEP_SUBJECT=alice@example.com \
    STRATIUM_PEP_SESSION_FILE=/tmp/stratium-pep-session.json \
    STRATIUM_PEP_CONNECT_TIMEOUT=5s \
    STRATIUM_PEP_REQUESTED_TIER=2 \
    STRATIUM_PEP_REQUESTED_TOOLS=Read,Grep,Bash \
    STRATIUM_PEP_TTL_SECONDS=28800 \
    stratium-pep session-start

Exit 0 means a session file now exists at that path. A non-zero exit means
it does not (and any stale file at that path was removed) — check stderr
for why before starting the agent: PDP unreachable, the requested scope
denied outright, etc.

The example above targets the local stack, whose PDPs do not verify
principals. A PDP verifies them by default: add
`STRATIUM_PEP_PRINCIPAL_TOKEN_FILE=/run/secrets/principal.jwt`, a file holding
the person's OIDC token from your identity provider. The PDP reads the
principal from that token, and `STRATIUM_PEP_SUBJECT` must equal it. The token
is needed only at session start; its expiry does not shorten the session. See
[`pep/session-start.md`](pep/session-start.md).

### The session file is bearer authority, not a label

Say this plainly, because it changed under this file without changing shape:
`STRATIUM_PEP_SESSION_FILE` used to cache a delegation *id* — a reference,
useless without also reaching the PDP as this session's own trusted local
process. As of Phase 9 it caches a signed **token** instead (`hook` and `mcp`
both read it and send the token, never the id, to `Decide` — spec §4.7.1
K4). A token is a bearer credential: whoever presents it authenticates as
this delegation, full stop, with no second factor and no check that the
presenter is the process session-start was run for. **Anyone who can read
this file can act as this session's agent — with its exact granted scope,
against the real PDP, from anywhere with network access to it — until the
token expires**, not merely until someone notices.

This was already true in the narrower sense that a leaked delegation id
plus network access to the PDP was also a problem — but a bare id was never
enough by itself before Phase 9 (K4 removed exactly the fallback that would
have let one work), and after this file's Task 4 there is no other
credential in play: the token IS the whole of what authenticates a call.
Treat a copy of this file exactly as you would a copy of the token it
contains, because that is what it is.

What this means for where it may be written:

- **Local disk only, on the machine actually running the agent.** Never a
  shared or network filesystem, never a location another user or another
  agent's session on the same host can read — `sessionFileMode` (0600) stops
  a different *user*, never a different process running as the *same* user,
  and a multi-tenant host runs agents as the same user more often than the
  0600 mode alone would suggest is safe.
- **Never committed, logged, or attached anywhere.** Not to source control,
  not to a bug report, not to a support ticket — the same rule this project
  already holds for `raw_input` and an approval id (hook.go's package doc)
  applies to this file's entire contents with more force, because unlike
  those two, this file is bytes sitting at rest on disk between tool calls,
  not a value that only ever exists in memory for one request.
- **Scoped to one session's lifetime.** A stale file left behind after an
  agent's work is done is a live credential with nobody watching it; remove
  it (or let a fresh `session-start` overwrite it — see "Fail closed on
  creation failure" in that command's own behavior) rather than leaving it
  sitting on disk once the session that needed it has ended.
- **The token's own expiry is the real bound, re-issuance included.** A
  captured token stops working once it expires — but a captured session
  *file* keeps handing out fresh ones for as long as the delegation itself
  is alive: `hook`/`mcp` reissue automatically when the cached token has
  expired (see "Re-issue on expiry" below), and so would anyone else holding
  a copy of this file. The token's expiry bounds one credential; the file's
  own exposure window is bounded only by the delegation's `ttl_seconds` and
  by however long the file sits somewhere it should not.

None of this is new caution about a new class of file — it is the same
"treat this like a password" instinct most people already apply to an SSH
private key or an API token in an env file, applied here because, as of this
task, that is exactly what this file is.

### Re-issue on expiry

A short-lived token can (and, over a long enough agent session, will)
expire before the delegation behind it does. `hook` and `mcp` handle this
themselves: when `Decide` denies a call, each surface asks the PDP for one
fresh token (`IssueToken`, naming the delegation this session's file already
recorded and presenting the token being replaced) and retries the SAME call
exactly once before deciding anything. The PDP does not re-issue for a
delegation id alone, since ids appear in audit entries and admin listings: it
needs a token it previously issued for that delegation. It checks that
token's signature and delegation but not its expiry, and it re-issues a
DPoP-bound token only for the same key.
A re-issue that fails — the delegation was itself revoked or has expired,
or the PDP could not be reached — denies the call; nothing here retries a
second time or waits indefinitely, the same bounded-wait discipline this
project already applies to an escalation (`STRATIUM_PEP_APPROVAL_TIMEOUT`).
The reissued token is used for that one call and discarded — it is never
written back to `STRATIUM_PEP_SESSION_FILE` — so a session whose cached
token keeps expiring keeps paying the same re-issue cost on every
subsequent call rather than silently caching a fresher credential in a
process's memory. Run `session-start` again for a session expected to run
long past its current token's lifetime rather than relying on this path to
carry it indefinitely.

### Grant discovery tools, not just access tools

`Grep` and `Glob` are in the example above deliberately. A scope of
`Read,Write` looks complete and is not: it lets an agent open a file it can
already name, and gives it no way to find out what exists. Observed against a
real agent under exactly that scope — it guessed ten plausible filenames, was
denied or found nothing on all ten, and gave up without reading anything.
Nothing was misconfigured and no denial was wrong; the grant was simply
unusable.

The failure is quiet in a way worth planning around. The agent is not denied
at a discovery tool — it never gets to call one — so the audit chain records a
run that did very little and no denial explaining why. A scope that omits
discovery reads as a working grant right up until someone asks why the agent
accomplished nothing.

Least privilege still applies; discovery tools are not an exception to it.
They are read-only, and a delegation capped at `READ_ONLY` bounds them exactly
as it bounds `Read`. Grant the ones the agent's task actually needs:

- **Finding files by name or path** — `Glob`
- **Finding files by content** — `Grep`
- **Listing a directory** — `LS`, or `Bash` if the tier permits it

If a scope must stay narrow enough to exclude discovery, expect to name every
resource up front, and treat "the agent did nothing" as the predicted outcome
rather than a bug.

## The decision cache

The decision cache is in memory only. Nothing is ever read from a cache file,
so the only decisions a PEP replays are ones that same process received from
the PDP.

- **`mcp` has a cache.** It is one long-running process, and it keeps one cache
  for the life of that process. A repeated `tools/call` inside the staleness
  window is answered from memory. The cache starts empty every time `mcp`
  starts.
- **`hook` has no cache.** It is a new process for each tool call, so it asks
  the PDP on every call. If the PDP is unreachable, `hook` denies immediately.
- **`extauthz` and `proxy` have no cache** and never did.

Earlier versions kept a cache file beside the session file
(`<session file>.cache.json`). No mode reads it any more, and `session-start`
removes a leftover one when it writes a new session file.

An escalation is never cached, pending or resolved.

### Choosing a decision cache staleness window

This applies to `mcp` only. The cache is an *outage-tolerance* feature, not a
latency optimization (spec §4.8): most tool calls are not repeats of one
already seen, so the cache's real job is letting a session keep working through
a brief PDP outage, not making individual calls faster.
`STRATIUM_PEP_CACHE_STALENESS_WINDOW` is what bounds that tolerance, and it is
required config for `mcp` with **no default, on purpose**. No single value is
right for every deployment, and getting it wrong is not a startup-time
inconvenience but an ongoing, silent cost:

- **Too long**, and the cache quietly becomes a revocation-tolerance
  feature instead of an outage-tolerance one: a policy change or a revoked
  delegation that should deny the very next tool call can instead keep
  being served the OLD, now-wrong verdict for as long as the window
  allows, on top of however long the PDP was already unreachable.
- **Too short**, and the cache is barely worth having: an outage shorter
  than the window is the only kind it will ever cover, so most of what the
  cache exists to buy is lost before it can matter.

Pick a window against how long an outage this deployment actually needs to
tolerate, and how stale a decision is acceptable to keep serving during
one — not against request latency, which this cache was never built to
improve.

**The window runs from each cached entry's OWN caching time, not from the
last moment this process successfully reached the PDP for any reason** —
a deliberate choice (`services/cmd/stratium-pep/cache.go`'s own package
doc has the full reasoning), and its consequence is visible during a real
outage: the cache does not hold together and then invalidate all at once
when the window elapses since the outage began. Each entry ages out on its
own schedule, so calls whose cached answers happen to be older start
denying sooner than calls whose answers are newer, even though the PDP
became unreachable for all of them at the same instant — **the cache empties
out gradually over the course of the window, rather than dropping in one
step.** An operator watching denials climb during an outage is seeing this
gradual drain, not a second, separate failure.

## `.claude/settings.json`

Wire `session-start` to run once at the start of every Claude Code session,
and `hook` to run before every single tool call:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "stratium-pep session-start",
            "timeout": 15
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "stratium-pep hook",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

The seven environment variables `hook` requires (the five shared above, plus
`STRATIUM_PEP_APPROVAL_POLL_INTERVAL`/`STRATIUM_PEP_APPROVAL_TIMEOUT`) need to
be set in the environment `claude` itself runs in, so both hook invocations
inherit them. `session-start`'s own four additional variables only need to
reach the `SessionStart` hook.

`SessionStart`'s `matcher` is deliberately omitted so this runs for every
session source (`startup`, `resume`, `clear`, `compact`, `fork`) — a
resumed or cleared session gets a fresh delegation too, rather than trusting
whatever `hook` happens to find left over from before. `PreToolUse`'s
`matcher` is `"*"` so every tool, not a chosen few, goes through the PDP —
the entire point of this system is that the PEP itself never decides which
tools are "obviously safe" enough to skip.

`timeout` here is Claude Code's own hook-execution timeout, in seconds —
distinct from `STRATIUM_PEP_CONNECT_TIMEOUT`, which bounds only the gRPC
call to the PDP. Keep Claude Code's `timeout` comfortably larger than
`STRATIUM_PEP_CONNECT_TIMEOUT` so a slow-but-still-answering PDP gets to
finish before Claude Code gives up on the hook process itself.

## Installing the `mcp` proxy

`mcp` is a stdio JSON-RPC proxy: it launches the *real* MCP server as a child
process and sits between it and the agent, relaying every frame in both
directions and asking the PDP to authorize each `tools/call` before it
reaches the real server. Nothing else about how your harness talks MCP
changes — `mcp` speaks the same stdio JSON-RPC framing on both sides.

**Every tool call is denied until a session is started and a policy permits
it — the same rule as `hook`, no exception for `mcp`.** Run
`stratium-pep session-start` first (above); `mcp` reads
`STRATIUM_PEP_SESSION_FILE` fresh on every single `tools/call`, so starting,
ending, or revoking a session takes effect on the very next tool call, not
just the next proxy restart.

### Launching it in place of the upstream server

Wherever your MCP client's configuration would otherwise launch the real
server directly, launch `stratium-pep mcp` instead, and move the real
server's own command and arguments into `STRATIUM_PEP_MCP_UPSTREAM_COMMAND`
and `STRATIUM_PEP_MCP_UPSTREAM_ARGS` so `stratium-pep` can launch it itself,
as its child. Many MCP clients configure a local server with a
command/args/environment block resembling this (the exact key names and file
location are your client's own, not something this project defines):

```json
{
  "mcpServers": {
    "my-server": {
      "command": "stratium-pep",
      "args": ["mcp"],
      "env": {
        "STRATIUM_PEP_PDP_ADDR": "localhost:50051",
        "STRATIUM_PEP_PDP_INSECURE": "true",
        "STRATIUM_PEP_AGENT_ID": "<agent-uuid>",
        "STRATIUM_PEP_SUBJECT": "alice@example.com",
        "STRATIUM_PEP_SESSION_FILE": "/tmp/stratium-pep-session.json",
        "STRATIUM_PEP_CONNECT_TIMEOUT": "5s",
        "STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "2s",
        "STRATIUM_PEP_APPROVAL_TIMEOUT": "5m",
        "STRATIUM_PEP_MCP_UPSTREAM_COMMAND": "/usr/local/bin/my-real-mcp-server",
        "STRATIUM_PEP_MCP_UPSTREAM_ARGS": "--flag-one,--flag-two"
      }
    }
  }
}
```

Before this change, `command`/`args` above named the real server directly.
After it, they name `stratium-pep`, and what used to be `command`/`args`
moves into the two `STRATIUM_PEP_MCP_UPSTREAM_*` variables — the real server
still runs, as `stratium-pep mcp`'s own child, just no longer reachable
except through the proxy in front of it.

There is no per-call analogue of Claude Code's hook `timeout` here: `mcp` is
launched once and stays running for the whole session, rather than being
invoked fresh per tool call. `STRATIUM_PEP_CONNECT_TIMEOUT` still bounds each
individual PDP call, and `STRATIUM_PEP_APPROVAL_TIMEOUT` still bounds each
escalation wait — configure both the same way you would for `hook`.

### Why `tools/list` is not filtered

`mcp` gates `tools/call` only. It relays `tools/list` — and every other MCP
method — unchanged, exactly as the real server would have answered it, even
when the list includes a tool the agent would go on to be denied for at call
time. This is deliberate, not a gap, and worth stating plainly because the
UX case for filtering is obvious enough that you will want to ask for it:
*why show the agent a tool it cannot actually use?*

Filtering the list would mean one of two things, and neither is acceptable:

- **`stratium-pep` decides locally which tools are "permitted enough" to
  advertise.** That is a second, informal authorization decision made by the
  component this whole system exists to keep from deciding anything —
  exactly the defect (client-side classification, trusted at face value)
  this project replaced. A tier can only be derived from a real call's
  arguments (`internal/authz.BuiltinTier` needs `raw_input`, not a bare tool
  name), so "permitted enough to list" could only ever be a guess dressed up
  as a filter.
- **`stratium-pep` asks the PDP to authorize every listed tool, on every
  `tools/list`.** This trades the UX nicety for a PDP round trip multiplied
  by however many tools the upstream server advertises, on a method that
  authorization was never meant to gate in the first place.

Enforcement happens at call time, where a real `tools/call` with real
arguments exists to evaluate. An agent that lists a tool it cannot call finds
out when it calls it — the same place, and the same way, it finds out
anything else about what it may or may not do under this system: a real,
PDP-attributed denial reason, not a tool quietly missing from a list for
reasons the agent was never told.

## Seeding the tool catalog

Neither `hook` nor `mcp` classifies a tool call anymore — see the package
docs at the top of `hook.go` and `mcp_authorize.go`. The PDP derives a
call's action tier and resource identity itself, server-side, from the
tenant's own `tool_catalog` table (`services/migrations/000013_tool_catalog`,
`000014_tool_catalog_nullable_tier`). **A tool with no catalog row still
works** — it falls back to `internal/authz.DefaultCatalog`'s built-in
tiers for Claude Code's own tool names, or, failing that, to the raw-input
classifier — but a third-party tool (an MCP server's own tool names, which
`DefaultCatalog` was never able to know about) gets no fallback at all: it
derives `INTERNAL_MODIFY` by default, reads included, and a `READ_ONLY`
delegation denies every single one of its calls. Catalog it to fix that.

A row expresses one of three things:

- **A fixed tier.** Most tools: the call always means the same thing,
  regardless of its arguments (`Read` is always a read).
- **No fixed tier, only a `command_field`.** Shell-shaped tools only —
  `Bash`, and an MCP equivalent, if your server has one. The PDP extracts
  that raw_input field and classifies the command itself (`rm -rf /` still
  `DESTRUCTIVE`, `ls -la` still `READ_ONLY`). A row must supply one or the
  other; the schema itself rejects a row with neither.
- **No row at all.** The built-in/raw-input fallback above.

Independently of tier, a row may also name a `resource_field`: the
raw_input field (e.g. `"path"`) holding the call's resource identity. This
is what lets a delegation's `ResourceConstraints` scope that tool at all —
without it, the PDP has no way to know which argument identifies the
resource being acted on, and any constraint on that tool just denies every
call outright (the constrained key is never present). Most tools have no
resource field (an array argument, a pattern, no arguments at all); leave
it out rather than guessing.

**Guessing this field wrong now decides more than it used to.** Cataloging
the wrong field as a tool's resource id was previously a scoping mistake: the
PDP compared `ResourceConstraints` against the wrong string, and a constraint
either denied calls it should have allowed or allowed ones it should have
denied. Since resource labelling shipped (below), the same wrong field also
picks which of your prefix rules classifies the call — so a tool whose
`resource_field` names, say, a destination argument instead of the file being
read gets a *confident* classification of the wrong resource, and an
authorization decision on top of it. Nothing reports this: the rule matched,
a level was resolved, and the decision looks exactly like a correct one. If a
tool's arguments do not contain one unambiguous field holding the thing the
call acts on, leave `resource_field` out — an unlabelled resource under a cap
denies loudly, which is the failure you want.

### Seed material for the two servers this project has run against

`deploy/seed/tool-catalog-claude-code.sql` and
`deploy/seed/tool-catalog-mcp-filesystem.sql` are data, not code: plain SQL,
safe to re-run (`ON CONFLICT` upserts), one for Claude Code's own built-in
tools and one for `@modelcontextprotocol/server-filesystem`. Read either
file's own header comment before running it — in particular, both
deliberately leave a few tools (`Glob`, `Grep`, `WebFetch`, `WebSearch`)
with no `resource_field`, and say why.

Run as `stratium_migrate` (the table owner — the serving role has `SELECT`
only, by design; see `000013_tool_catalog`'s own `GRANT` comment: writing
this table is always a control-plane action, never something the PDP does
to itself):

    psql "$STRATIUM_MIGRATION_DATABASE_URL" -v tenant_id='your-tenant-id' \
        -f deploy/seed/tool-catalog-claude-code.sql
    psql "$STRATIUM_MIGRATION_DATABASE_URL" -v tenant_id='your-tenant-id' \
        -f deploy/seed/tool-catalog-mcp-filesystem.sql

### Adding a tool of your own

One row, following the same shape:

    SELECT set_config('app.tenant_id', 'your-tenant-id', false);
    INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb, resource_field, command_field)
    VALUES ('your-tenant-id', 'your_tool_name', 1, 'read', 'path', NULL)
    ON CONFLICT (tenant_id, tool_name) DO UPDATE SET
        action_tier = EXCLUDED.action_tier, verb = EXCLUDED.verb,
        resource_field = EXCLUDED.resource_field, command_field = EXCLUDED.command_field;

`action_tier`: `0` REASONING, `1` READ_ONLY, `2` INTERNAL_MODIFY,
`3` EXTERNAL_COMMS, `4` DESTRUCTIVE — or `NULL`, paired with a
`command_field`, for a shell-shaped tool (see above). `tool_name` is
matched exactly and case-sensitively — `"read_file"` and `"Read_File"` are
different rows, never merged or deduplicated case-insensitively.

**The `set_config` line is not optional, and skipping it does not fail the
same way twice.** `tool_catalog` has `FORCE ROW LEVEL SECURITY`
(`000013_tool_catalog`), which applies even to the table's own owner. Skip
it before an `INSERT` and the write fails loudly (`new row violates
row-level security policy`) — annoying, but safe. Skip it before a `DELETE`
or `UPDATE` and it fails silently: zero rows match `tenant_id =
current_tenant()` (`NULL`), so the statement "succeeds" having touched
nothing. A prior task lost time this way on exactly this table; set the
tenant first, every time, for every write.

## Labelling resources for classification caps

A delegation can carry a classification cap — for example `nato:
CONFIDENTIAL` — meaning "resources above this level are refused." A cap needs
two things to mean anything: a level to compare against, and something that
says what the resource's level *is*. This release supplies the second. Your
tenant's own **resource label rules** (spec §3.9.1) map a resource-id prefix
to a hierarchy and a level, and the PDP resolves them on every decision.

Two rules govern the result, and the second is the one that surprises people:

- **The longest matching prefix wins.** Several rules may match one id, since
  every prefix of it matches; the one with the *longest* prefix decides, and
  the others are ignored — so a rule on a subtree overrides an enclosing one,
  in either direction (see "Write the trailing separator" below for what
  "prefix" does and does not mean here). The PDP resolves your rules against
  the resource id *it* extracted from the tool call itself — never one the
  client sent, and never a classification the client claims. A PEP that
  decided a resource's sensitivity would be making exactly the security
  decision this system exists to keep out of the untrusted client (spec §3.9,
  R1), so `stratium-pep` sends resource *identity* only, and even that is
  re-derived server-side from the tenant's own `tool_catalog` row. **No
  `resource_field` on the tool's row means no id, which means no label** —
  see "Seeding the tool catalog" above.
- **A cap that cannot be checked denies** (spec §3.9, R2). A resource matching
  no rule is *unlabelled*, and a configured cap over an unlabelled resource
  denies. There is no default level and no fallback, deliberately:
  `UNCLASSIFIED` is a real level that a cap can be *satisfied by*, so
  defaulting to it would be this system answering a question your rules did
  not — and quietly allowing, which is the direction that costs you.

The hierarchies and their levels are fixed, ordered low to high
(`services/pkg/classification/classification.go`):

    nato        UNCLASSIFIED  RESTRICTED  CONFIDENTIAL  SECRET  TOP-SECRET
    commercial  PUBLIC  INTERNAL  CONFIDENTIAL-COMMERCIAL  RESTRICTED-COMMERCIAL  HIGHLY-CONFIDENTIAL

A cap says nothing about a hierarchy it does not name: a `nato` cap never
constrains a resource labelled `commercial`, and that is by design (spec §3.9,
R9) — but see "A carve-out that changes hierarchy" below, because it is also
how a cap stops applying by accident.

**A delegation with no classification cap configured at all is unaffected by
any of this.** Labelling changes what a *configured* cap means; it does not
start capping delegations that never had one.

### A cap is set on the agent, and applies at the next issuance

Read this before planning a remedy, because it rules several out. A
*delegation's* caps are still fixed at creation and inherited unchanged by
every child — nothing edits a delegation's cap map in place, and the issuance
RPC carries no field for one.

What changed: **the ceiling is now set on the agent**, and a root delegation
copies it at issuance.

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/classification-caps" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"classification_caps": {"nato": "CONFIDENTIAL"}}'
```

`RoleAdmin` on the write, because a classification ceiling is not ordinary
agent configuration. `DELETE` on the same route clears it; `PUT` will not,
because turning enforcement off must be a deliberate verb rather than an
omitted field. See [`../docs/user-guide.md`](user-guide.md) § 5.7.

The consequence that still bites: **a delegation already issued keeps the caps
it was minted with.** Setting a cap does not reach into live sessions. To make
one take effect now, revoke the delegation and let the agent re-issue.

Two consequences to have in advance:

- **The lever for "this cap is wrong for this resource" is the label, not the
  cap.** Correcting the resource label rule changes what the cap is compared
  against. It is the only adjustment this API offers — recreating the
  delegation is not a second one, because a new delegation is created with no
  cap at all.
- **Revoking and re-issuing does not get you a different cap — it gets you no
  cap.** `stratium-pep session-start` issues a *root* delegation, and a root
  is created with an empty cap map. An empty map is not a low cap: a cap check
  allows immediately when no cap is configured, so the replacement session has
  classification enforcement switched **off entirely, on every hierarchy**.
  Nothing warns you, and the audit log records allows rather than denials. So
  revoking is a way to stop a capped delegation, never a way to adjust one — if
  you need a different cap, you need whatever process created the original.

### Enabling a cap without a catch-all denies every unmatched resource

**Read this before you configure your first cap, not after the tickets
arrive.** The moment a delegation carries a cap, every resource your rules do
not cover starts denying — not the ones above the cap, *all* of them. If you
have no rules at all, that is every resource the delegation can reach.

This is correct behaviour and it will read as an outage. The reason text is
what tells the two apart:

    resource declares no classification; the delegation's classification
    cap cannot be evaluated and therefore denies

is deliberately distinct from an ordinary cap violation:

    resource classification X exceeds delegation cap Y in hierarchy "H"

so your audit log can tell "we could not check" from "we checked, and it was
over the line." The first means your rules have a gap. The second means the
cap worked.

**The fix is a catch-all, and it costs no new mechanism.** The empty prefix is
a prefix of every string, so one rule with `"prefix": ""` labels every
resource the PDP can *identify*. Register it *before* you enable the cap:

    curl -sS -X POST http://<stratium-pap>/v1/resource-label-rules \
        -H "Authorization: Bearer $OPERATOR_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"prefix": "", "hierarchy": "nato", "level": "UNCLASSIFIED"}'

The catch-all's level is your answer to "what should a resource no rule
describes be treated as?" `UNCLASSIFIED` restores the pre-cap behaviour for
everything you have not classified yet and lets you tighten subtree by
subtree; a higher level fails closed and keeps denying until you carve out
what is genuinely safe. Either is defensible — a catch-all you did not choose
is not.

**A catch-all does not cover a tool with no `resource_field`, and that is the
other half of this cliff.** A rule labels an *id*; a tool whose `tool_catalog`
row names no resource field produces no id, so **no** rule matches it — not
even the empty-prefix one — and those calls keep denying with the very reason
you just fixed. This is not a corner case: most tools have no resource field
(see "Seeding the tool catalog" above), and the shipped seed leaves `Glob`,
`Grep`, `WebFetch` and `WebSearch` fieldless on purpose.

So before you conclude the cliff is closed, go through the tools this
delegation approves and check each one's catalog row. For every fieldless one,
you have two honest options: give it a `resource_field` if it genuinely has a
single unambiguous argument naming what it acts on, or accept that it cannot
be used while this cap is configured — drop the tool from the delegation's
approved set, or the cap from the delegation. Nothing labels a resource nobody
identified, deliberately: a label invented for an unidentified resource would
be exactly the bypass this design refuses.

**With the catch-all in place, narrow one prefix at a time** — the same `POST`
with a longer prefix. A longer prefix overrides a shorter one in both
directions: it can raise a subtree above the catch-all, or lower one below an
enclosing rule (a genuinely public directory inside a secret tree).

    curl -sS -X POST http://<stratium-pap>/v1/resource-label-rules \
        -H "Authorization: Bearer $OPERATOR_TOKEN" \
        -H 'Content-Type: application/json' \
        -d '{"prefix": "/exports/quarterly/", "hierarchy": "nato", "level": "SECRET"}'

An unknown `hierarchy`, or a `level` that is not one of that hierarchy's
levels, is refused at write time with a 400 naming the known values — so a
typo in either costs you a failed request rather than a stored rule.

**`prefix` is the one field nothing validates, and it cannot be.** Any string
is a legal prefix — that is what makes `""` the catch-all — so a mistyped
prefix is accepted, stored, and silently matches nothing (or, worse, matches
more than you meant; see "Write the trailing separator" below). Nothing will
tell you. After writing a rule, confirm it does what you think by checking a
real decision, or by reading the set back with `GET`.

The full set of routes under `/v1/resource-label-rules` is the same CRUD shape
as every other admin resource, gated by operator role:

| Route | Role |
|---|---|
| `GET /v1/resource-label-rules` | viewer |
| `GET /v1/resource-label-rules/{id}` | viewer |
| `POST /v1/resource-label-rules` | editor |
| `PUT /v1/resource-label-rules/{id}` | editor |
| `DELETE /v1/resource-label-rules/{id}` | admin |

Write them through `stratium-pap`, not with `psql`, for two reasons. The PAP
writes an audit entry in the same transaction as the row, so a direct SQL
write produces a rule change nothing recorded. And the write path is the only
thing that validates `hierarchy` and `level` at all — the schema does not —
so a `psql` insert can store a rule naming a level that cannot be ranked,
which is precisely what the "cannot be evaluated"-family denials in "Reading a
denial" below are reporting when they appear.

**A rule takes effect on the next decision.** The PDP reads the tenant's whole
rule set on every `Decide` rather than caching it, and every write to the
table also bumps the tenant's revocation epoch, which invalidates cached
decisions made under the old rules. There is no TTL to wait out and no PDP
restart to schedule.

### Write the trailing separator

**`/data` matches `/database/x`.** Matching is plain string prefix, exactly as
written, and `/data` is literally a prefix of `/database/x`. An operator who
means the directory writes the separator:

    "prefix": "/data/"

This is not a bug to be fixed later; it is a ruling with a reason. A
boundary-aware matcher would need a separator vocabulary the resource id does
not carry — an id is whatever field you catalogued as `resource_field`, which
is as often a bucket key, a URL, or a dotted table name as it is a POSIX path
— so the matcher would be guessing at syntax. It would also put a second,
invisible rule between what you wrote and what it does, and it would break the
empty-prefix catch-all above, which works only because `""` is a prefix of
every string.

The direction that costs you is a boundary-less rule that **lowers**: `/data`
at `UNCLASSIFIED`, meant for one directory, also declassifies `/database/`,
`/datastore/`, and anything else sharing those five characters. Write the
separator on every rule where you mean a subtree.

### A carve-out that changes hierarchy leaves the cap behind

If the longer, winning rule names a *different* hierarchy from the rule it
overrides, resources under it escape the outer hierarchy's cap entirely —
they did not drop within an ordering, they left it. A `commercial: PUBLIC`
carve-out beneath a `nato: TOP-SECRET` rule allows under a `nato` cap, because
a `nato` cap says nothing about `commercial`.

That is the designed behaviour of per-hierarchy caps, and it is also what one
mistyped `hierarchy` value looks like.

**It is a privilege boundary as well as an accident, and that is the half
worth planning for.** Writing a label rule is an *editor* action; there is no
route at any role that edits a live delegation's cap. So an editor who adds a
`commercial` rule over a `nato`-capped subtree neutralises, for everything
beneath it, a cap they have no way to modify directly — **rule-write authority
is effectively cap-write authority, in the permissive direction.** Grant the
editor role on that understanding, and if the two need to be separated,
separate them at the operator-role level, because nothing below it does.

The PDP logs the switch on every such decision:

    resource label carve-out changes hierarchy: a cap naming only the
    hierarchy it left does not apply to the one it entered

Three kinds of line are emitted, and grepping `carve-out` finds all three —
all three *that are emitted*, which is not the same as all overrides; see the
end of this section. The other two are the lowering signal, which fires when a
carve-out lowers a level *within* one hierarchy:

    resource label carve-out lowers the classification it overrides

and the inert-rule signal, which fires when the rule being overridden names a
level this system cannot rank — a typo in the *level* column of the outer
rule, which would otherwise be invisible because the carve-out covers every id
it would have decided:

    resource label carve-out covers a rule whose level this system cannot
    rank: that rule is inert

All three name the winning rule and the rule it overrode, each by prefix,
hierarchy, and level, so you can find both rows. None names the resource id —
a rule is your configuration, an id is derived from client-supplied input.

**Only some overrides are logged, and the workflow above writes one that is
not.** A line appears when the winning rule *lowers* a level within one
hierarchy, *switches* hierarchy, or *covers an unrankable* rule. An override
that RAISES within one hierarchy — the `/exports/quarterly/` example above,
`SECRET` over the catch-all's `UNCLASSIFIED` — is deliberately silent: it
tightens, and logging every tightening would bury the three cases above in
noise.

So grepping after a raise finds nothing, and finding nothing is not evidence
your rule is inert. Two further reasons a grep can come back empty even for a
logged override: the line is emitted **per decision, not per write**, so
nothing appears until real traffic hits an id under that prefix; and it names
only the two rules, so there is nothing request-specific to search for.

When you have written a *lowering*, a *hierarchy switch*, or a rule covering
one whose level cannot be ranked, grep your PDP's log for `carve-out` once
traffic has reached the prefix, and confirm the pair it reports is the pair
you meant. To check a raise, or to check any rule before traffic arrives, read
the rule set back with `GET /v1/resource-label-rules` instead.

### Deleting the empty-prefix rule un-labels the tenant

`DELETE /v1/resource-label-rules/{id}` takes no confirmation flag, by design —
a flag would obstruct the one legitimate use of a delete. Deleting the
catch-all is the largest blast radius available in this table: every resource
that only it covered becomes unlabelled, and under any configured cap, denies.

**`PUT` reaches the same place, from a lower role.** The update is a full
replace of prefix, hierarchy and level, and editing the prefix is the ordinary
correction, not a corner case — so PUTting a different prefix onto the
catch-all un-labels the tenant exactly as deleting it would, and PUTting a
higher level onto it denies the tenant wholesale. Note the asymmetry: `DELETE`
is admin-only, `PUT` is editor. Read this section as covering both verbs — the
pre-flight below applies to any edit of a rule that other resources fall back
to, whichever verb makes it.

**Your pre-flight view is the list.** `GET /v1/resource-label-rules` returns
the whole rule set — it is small and operator-authored — so "what else covers
this prefix?" is answerable by reading it before you press the button:

    curl -sS http://<stratium-pap>/v1/resource-label-rules \
        -H "Authorization: Bearer $OPERATOR_TOKEN"

The delete does record what it cost, in the audit entry it writes in the same
transaction: either what the deleted prefix now resolves to, or that nothing
labels it any more. That is a durable record rather than a warning that
scrolls past — but it is written *after* the fact, which is why the list is
the thing to read first. Note the record's claim is narrow on purpose: a rule
at a longer prefix still covers its own subtree, so "nothing labels this
prefix" does not mean everything beneath it went dark.

## The `proxy` surface's limits

`proxy` (`services/cmd/stratium-pep/proxy.go`) authorizes a real gRPC
connection through the same PDP call `hook` and `mcp` use, but it sits
somewhere neither of them does: in front of a wire protocol it does not own,
with no `.proto` for anything it forwards. That position is what makes it
transparent — no agent rewrite, unlike the predecessor's own envelope — and
it is also where three permanent limits come from, each a direct consequence
of the same position, not a gap a later release closes. Know these before
this surface is asked to do something they would change the answer to.

### A stream is authorized once, at open

The method is known the moment a stream opens; nothing that crosses it
afterward is, because `proxy` never parses a message — there is no schema to
parse it against (see "Do not feed the message body into `raw_input`" below
for why that stays true on purpose). One `Decide` call happens when the
stream opens, and every message the stream ever carries — one, or however
many a long-lived streaming RPC sends over however long it stays open —
rides that single decision.

**Say the consequence plainly: revoking the delegation behind an open
stream, or a policy change that would now deny it, does not end that
stream.** It keeps forwarding until the caller or the target closes it, or
its token expires — whichever comes first. There is no mid-stream check to
add here without parsing a protocol this surface deliberately does not
parse; a short-lived token is the actual control for anything that must stop
promptly — the same `ttl_seconds`/`STRATIUM_PEP_APPROVAL_TIMEOUT` bound that
already governs how long any other surface's decision can outlive a change
nobody can take back once it has been made.

**One stream, one proof.** `proxy` requires a sender-constrained token (RFC
9449 DPoP — see "Sender-constrained tokens on `proxy`" below), and the same
"once, at open" rule governs it: one stream gets one `Decide` call carrying
one proof, whose single-use `jti` is spent once. (The one place a *second*
proof is genuinely needed is an escalation, which is why `proxy` hands an
escalating call back to the client instead of blocking — see "An escalation on
`proxy` does not block" below.) **A long-lived stream rides
that one proof for its entire life** — hours, thousands of messages, all on a
single proof of possession made at the instant the stream opened. Assume
per-message binding and you will be wrong about what a captured stream costs
you.

This is not a gap awaiting an implementation. Binding a per-message proof
would need something per-message to bind it *to*, and there is nothing:
`htu` is a method path, identical for every message of one stream, so a
second proof would be a second signature over the same statement rather than
a fresh assertion about a new request. A short stream is the control here,
exactly as a short-lived token is the control for revocation above.

### Authorization cannot see message contents

`raw_input` here is the called method and the caller's own gRPC metadata,
JSON-encoded, credential headers stripped — never the message body. Be
precise about what this does and does not cost, since it is the detail most
likely to be misread:

- **Resource constraints and classification caps still bind, on the method
  and metadata.** A tenant can catalog `resource_field: "method"` for a gRPC
  tool and constrain a delegation to, say, `{method:
  "/inv.Inventory/GetItem"}` exactly as it would catalog a path for `Read`.
  Coarse, but real: "may call `GetItem`, may not call `DeleteItem`" is
  expressible and enforced.
- **What cannot be expressed is a distinction *within* one call** — "may
  read item 7 but not item 9," where 7 and 9 are both arguments inside the
  same `GetItem` call's message body. Nothing on this surface can see far
  enough into the call to tell those two apart.

"Caps do not work on the proxy" would be the wrong conclusion — they work at
the granularity this surface can actually see. Design a delegation around
that granularity (method-level, not argument-level) rather than assuming it
gets `hook`'s field-level reach for free.

### The evidence rule has nothing to scan here

On `hook` and `mcp`, a destructive-looking command sitting in `raw_input`
raises the action tier regardless of what the tool catalog says (spec
§4.4.1) — the rule that stops a mislabeled or lying client from hiding
`rm -rf /` behind a tool name the catalog calls harmless. `raw_input` on
`proxy` never carries anything shaped like a command: it is a method name
and ordinary metadata, and the rule has no shell or SQL syntax there to
match against — not even a method name that reads as alarming in English.
`/inv.Inventory/DeleteEverything` is still just a name to it.

**A method with no catalog row is classified by the built-in classifier's
own default alone** (`INTERNAL_MODIFY` — see "Seeding the tool catalog"
above), the same fallback every uncatalogued third-party tool already gets
on `mcp`. **Catalog this surface's methods deliberately; do not rely on a
safety net that is not here.** An uncatalogued method that actually deletes
something will not be caught by anything reading its `raw_input` — there is
nothing in it to read.

**Do not feed the message body into `raw_input` to give the evidence rule
something to scan.** This was considered and rejected, not overlooked:
opaque protobuf bytes matching a shell pattern by pure coincidence would
produce a false denial with a reason no operator could explain, against an
audit digest that commits to `raw_input` and would then be hashing bytes
nobody could ever usefully re-derive the meaning of. The fix for an
under-classified method is the same as for any uncatalogued tool: add a
catalog row, not a scan of something this surface cannot make sense of.

### Sender-constrained tokens on `proxy`

`proxy` and `extauthz` are the two surfaces where the request arrives from
the party being policed, so a token that leaks — from a log, a sidecar, a
captured connection — is fully usable by whoever picked it up. Both
therefore require **proof of possession** (RFC 9449 DPoP, spec §4.7.2). Two
consequences an operator meets immediately:

- **A bearer token is refused here, even when policy would allow the
  call.** Mint tokens for this surface with `dpop_jwk` set on `IssueToken`
  (which also needs `token`: the bearer token `CreateDelegation` returned),
  and send a proof on every call, in `dpop` gRPC metadata alongside
  `authorization`. A token minted without `dpop_jwk` is refused with a
  reason that says so; it is not a policy denial and no policy change fixes
  it. Bearer tokens stay legitimate on `hook` and `mcp`, where the caller
  already holds the session file the token lives in.
- **Sign the proof's `htu` against the address you *addressed*, not the one
  you dialled, and never the target's.** `htu` here is
  `STRATIUM_PEP_PROXY_PUBLIC_URI` plus the full method path
  (`https://proxy.example:9292/pkg.Svc/Method`), with `htm` as `POST` — gRPC
  is HTTP/2 POST. That variable is required, has no default, and the process
  refuses to start without it, because it is the one component of the
  binding that separates this proxy from any other. The proxy never reads it
  from the request: not from the caller's `:authority`, and not from
  `STRATIUM_PEP_PROXY_TARGET_ADDR` — binding to the target's address would
  make a proof minted for one target replayable at another behind the same
  proxy.

The proof itself never reaches `raw_input` and so never reaches the audit
chain, exactly like `authorization` — a credential hashed into an
append-only chain cannot be edited back out of it.

### An escalation never blocks on `proxy` — and this is where §4.6 has its exception

`proxy` used to be a blocking surface (spec §4.6): it held the caller's stream
open across a human approval, unlike `extauthz`, which cannot. **It no longer
does, for either kind of token**, and the rule that replaced the old split is
worth knowing before you design around either surface:

> **A surface can block only while the credential it would wait with outlives
> the wait.** A DPoP proof does not: it is single-use and short-lived, and a
> human approval is neither.

Since both network surfaces now *require* a sender-constrained token, neither
has a credential that survives a wait, so neither waits:

- **A bound token degrades**, on both surfaces — a denial naming the pending
  approval, which you retry (see below).
- **An unbound token is refused outright**, on both surfaces, with the
  "get a bound token" message rather than an approval id. An approval cannot
  rescue it: the retry would resolve to an ALLOW that the surface refuses
  anyway, so pointing you at an approval would send you to fix something that
  was never the problem.

`hook` and `mcp` still block, and should: a bearer token is legitimate there
(you already hold the session file it lives in), and a bearer token outlives a
human.

So when an escalating call presents a bound token, `proxy` returns
`PERMISSION_DENIED` immediately, carrying the pending approval's id in two
places:

- **trailing metadata** under `stratium-approval-id` — the key a retry tool
  reads deterministically, and the same name `extauthz` uses for its own
  response header;
- **the status message** — for a human who captured only the error.

**Once the approval lands, retry the call with a *fresh* proof**, sending the
approval id back in `stratium-approval-id` request metadata. Both halves
matter and the failure modes differ:

- Retrying with the **same** proof is refused as a replay — the original call
  already spent its `jti`. This is why the denial's text says *fresh* rather
  than "retry after approval".
- Retrying **without** the approval id does not fail; it escalates again and
  creates a *second* pending approval. Nothing is broken, but a human is asked
  to approve the same action twice and the first approval is left unused.

Do not add anything else to the retry's metadata. Both surfaces strip
`stratium-approval-id` before building `raw_input` precisely so the retry
hashes identically to the escalating call — an approval is bound to that hash,
so any *other* difference between the two calls makes the approval unusable and
the retry denies.

One difference is not yours to control and is worth knowing about: if your gRPC
client retries transparently, grpc-go adds `grpc-previous-rpc-attempts` on
attempts after the first, and that *does* reach `raw_input`. It is ordinary
request metadata rather than something to strip — an auditor should see that a
call was a retry — but it means a transparently-retried attempt hashes
differently from the original and cannot use an approval created for it. Send
the approved retry as a fresh call.

The same recipe works on `extauthz`, which reads the id from a
`stratium-approval-id` **request header** and strips it identically. The two
surfaces behave the same way on an escalation — degrade a bound token, refuse
an unbound one — for different underlying reasons: `proxy` *could* hold a call
open and no longer does because the credential would not survive the wait,
while `extauthz` never could (Envoy's `ext_authz` budget is milliseconds).

## Reading a denial

Both `hook` and `mcp` reach a denial through the same PDP call and the same
fail-closed checks (an unreadable session file, an unreachable PDP, an
escalation that timed out, ...), so the *reason text* below reads identically
either way — only the shape wrapping it differs.

`hook` exits 2 and prints JSON on stdout:
`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"..."}}`.

`mcp` never exits per call — it is one long-lived process for the whole
session — so a denial instead comes back as a JSON-RPC error response
correlated to the `tools/call` request's own `id`:
`{"jsonrpc":"2.0","id":<the request's id>,"error":{"code":-31003,"message":"..."}}`.
Code `-31003` covers every reason one `tools/call` did not reach the real
server — an explicit policy denial, a failed or timed-out escalation, *and*
a fail-closed check like an unreachable PDP or a missing session file — with
the message text (below) saying which; it is never a different code per
failure mode. It is reserved for exactly that: a frame this proxy cannot
even parse enough to correlate a response to (no usable `id`) is dropped and
reported on stderr instead, never answered with a fabricated JSON-RPC
response — see `services/cmd/stratium-pep/mcp_authorize.go`'s package doc
for the full reasoning, including why this specific code and not a standard
JSON-RPC one.

Either way, the *message*/`permissionDecisionReason` text says which of these
you're looking at — the distinction between "you are not allowed" and "we
could not ask" matters, because the fix is different:

| Reason says... | Means | Fix |
|---|---|---|
| `no session file at ... -- run 'stratium-pep session-start' first` | No session was ever started, or one ended. | Run `session-start`. |
| `session file ... is malformed` | The file exists but is not valid JSON. | Delete it and run `session-start` again. |
| `session file ... has no token -- run 'stratium-pep session-start' again` | The file exists and parses, but its token field is empty — a hand-edited file, or one written by a build that predates Phase 9 Task 4. | Run `session-start` again. |
| `PDP says the delegation or agent this request names is unknown to it` | The session names a delegation (or agent) the PDP has never heard of — expired, revoked, or copied from elsewhere. | Run `session-start` again. |
| `re-issue token: ...` | The cached token was rejected, and the automatic re-issue attempt (see "Re-issue on expiry" above) also failed — the delegation itself is revoked or expired, or the PDP could not be reached for the re-issue call. | If the delegation is dead, run `session-start` again; otherwise treat the wrapped reason like `could not reach PDP`/`PDP returned an error` above. |
| `retry after re-issuing token: ...` | Re-issuance itself succeeded, but the retried `Decide` call with the fresh token failed at the transport level (unreachable PDP, timeout). | Treat the wrapped reason like `could not reach PDP`/`PDP did not respond in time` above. |
| `could not reach PDP` | Transport failure — the PDP process may be down or the address wrong. | Check the PDP is running and `STRATIUM_PEP_PDP_ADDR` is correct. |
| `could not reach PDP` with a TLS error such as `tls: first record does not look like a TLS handshake` | The PEP speaks TLS (the default) and the PDP serves plaintext. | For a local stack, set `STRATIUM_PEP_PDP_INSECURE=true`; otherwise give the PDP a certificate (`STRATIUM_TLS_CERT_FILE`, `STRATIUM_TLS_KEY_FILE`). |
| `PDP did not respond in time` | The PDP is reachable but did not answer inside `STRATIUM_PEP_CONNECT_TIMEOUT`. | Check PDP health/load, or raise the timeout. |
| `PDP returned an error` | The PDP is up and answered, but the call itself failed server-side. | Check the PDP's own logs. |
| `approval ... did not resolve within the escalation timeout` | The action required human approval, and nobody resolved it inside `STRATIUM_PEP_APPROVAL_TIMEOUT`. | Approve escalations faster, or raise the timeout — see "Grant discovery tools" above for the same "the grant is real but unusable" shape applied to timing instead of scope. |
| `approval ... was denied` | The action required human approval, and a human explicitly denied it. | Not a bug — this is the intended outcome of a reviewed escalation. |
| `approval ... is unknown to the PDP` | The PDP no longer recognizes the approval this session was waiting on. | Unusual; retry the tool call (a fresh escalation will be created) and check the PDP's own logs if it recurs. |
| `resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies` | The delegation has a classification cap configured and **the resource ended up unlabelled**, so the cap could not be checked and it denies (spec §3.9, R2). Three different causes produce this one text: (a) no rule covers the resource; (b) the tool's `tool_catalog` row names no `resource_field`, so the PDP had no id to resolve rules against; (c) the row *does* name one, but this call's `raw_input` omitted that field, spelled it differently, or carried it as a non-string or an empty string — all of which read as no id. | Fixable, but not by retrying — retrying reproduces it exactly. The three causes have three different fixes: (a) register a rule, or an empty-prefix catch-all; (b) give the tool a `resource_field`, or accept it is unusable under a cap; (c) fix the **call** or the catalogued field *name* — the rule set is not the problem, and editing it will not help. Distinguish them by checking the tool's catalog row first, then a sample `raw_input` against it. See "Labelling resources for classification caps" above. |
| `resource classification X exceeds delegation cap Y in hierarchy "H"` | The resource **was** labelled, and its level is above this delegation's cap. The cap did its job. | Not a bug. Two adjustments are available. The **label**: correct the rule if the resource is mislabelled (`GET /v1/resource-label-rules` shows which rules exist). Or the **ceiling**: `PUT /v1/agents/{id}/classification-caps` raises it for delegations issued from then on — revoke this one so a replacement picks the new value up. Revoking alone no longer returns an uncapped session: the replacement inherits whatever the agent now carries. |
| `unknown classification hierarchy ...`, `unknown classification level ...` | The **resource label rule** that matched names a hierarchy or level outside the fixed set — a rule written around the API's validation (a direct SQL write, or a read that raced a migration). Unreachable before labelling. | A rule fix, not a policy grant. Compare the value against the hierarchy table in "Labelling resources for classification caps" above, and rewrite the rule through `stratium-pap` so the validator sees it. |
| `delegation cap "..." is not a known level ...`, `conflicting caps for hierarchy ...` | The **delegation's own cap map** is malformed — a cap naming a non-level, or two keys differing only by case carrying different levels. Nothing is wrong with your label rules, and looking there will find nothing. Unreachable before labelling. | Not fixable in place: nothing edits a delegation's cap map. Fix the ceiling on the agent (`PUT /v1/agents/{id}/classification-caps`), then revoke this delegation so its replacement is issued with the corrected cap. |
| Anything else | An actual policy decision: a policy was evaluated and does not permit this tool for this principal. | Whoever manages policy for this tenant needs to grant it. |

`proxy` and `extauthz` are later enforcement surfaces over the same PDP call.
`session-start`, `hook`, and `mcp` are installed as described above. `proxy`
and `extauthz` carry no session file and answer a denial as a gRPC status,
not either JSON shape this table covers; both now have worked installation
examples of their own in [`pep/proxy.md`](pep/proxy.md) and
[`pep/extauthz.md`](pep/extauthz.md).
