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

`hook` and `mcp` only, in addition to the five above (`session-start` never
polls, so it has no use for either):

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_APPROVAL_POLL_INTERVAL` | How often to re-check a pending escalation, e.g. `2s`. |
| `STRATIUM_PEP_APPROVAL_TIMEOUT` | How long to wait for a human to resolve an escalation before failing closed, e.g. `5m`. Bounds the *whole* wait, independent of `STRATIUM_PEP_CONNECT_TIMEOUT`, which bounds only one RPC round trip. |

`session-start` only, in addition to the five shared above:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_REQUESTED_TIER` | Action-tier ceiling to request: `0` REASONING, `1` READ_ONLY, `2` INTERNAL_MODIFY, `3` EXTERNAL_COMMS, `4` DESTRUCTIVE. The PDP may grant less than this — the session file records what was actually granted, not what was requested. |
| `STRATIUM_PEP_REQUESTED_TOOLS` | Comma-separated tool names to request, e.g. `Read,Grep,Bash`. Must not be empty. Include discovery tools — see below. |
| `STRATIUM_PEP_TTL_SECONDS` | How long the new delegation is valid for, in seconds. |
| `STRATIUM_PEP_PURPOSE` (optional) | Free-text reason for the delegation, for audit legibility. |

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

## Classification caps have no labelling source

A delegation can carry a classification cap — for example `nato:
CONFIDENTIAL` — meant to refuse access to anything above that level. As of
this release, a configured cap **denies** when the resource being accessed
carries no classification, rather than treating an unlabelled resource as
compliant (spec §3.9, R2). If your tenant has any classification cap
configured, on any hierarchy, **you will start seeing denials you have not
seen before.**

**This is correct, not a regression.** A cap's semantics were always
"resources above this level are refused." Nothing in this system today — not
`stratium-pep`, not the PDP, not any policy engine — has a source for a
resource's actual classification. `stratium-pep` sends resource *identity*
only (a path or an id extracted from the tool call's own arguments — see
`cmd/stratium-pep/resource.go`'s package doc), deliberately never a
classification: a PEP that decided a resource's sensitivity would be making
exactly the security decision this whole system exists to keep out of the
untrusted client (spec §3.9, R1). So before this change, every resource a
configured cap was ever compared against looked unlabelled, and the cap
silently allowed everything through. It was never enforcing anything; it
just never told you.

The reason text this produces reads:

    resource declares no classification; the delegation's classification
    cap cannot be evaluated and therefore denies

— distinct, deliberately, from an ordinary cap violation (`resource
classification X exceeds delegation cap Y in hierarchy "H"`), so your audit
log can tell "we could not check" apart from "we checked, and it was over
the line." Both are denials, for different reasons an operator acts on
differently.

**A delegation with no classification cap configured at all is unaffected.**
This tightens what a *configured* cap means; it does not start capping
delegations that never had one.

**What to do about it.** There is currently no source of resource
classification for this system to check against, so the honest options are
narrow:

- **If this hierarchy's cap was not actually protecting anything** — the
  common case, since it could never have fired before now — remove it from
  the delegation. This makes today's real behavior (unrestricted on this
  axis) a visible, deliberate choice instead of an accidental one.
- **If classification enforcement is a real requirement, this system cannot
  deliver it yet.** Do not work around the gap by standing up something
  outside this system that reports "everything is UNCLASSIFIED" (or any
  other fixed value) just to quiet the denials — that satisfies the cap
  exactly as badly as the old silent allow did, only more deliberately.
  Track the tenant-configured labelling source this needs (spec §8, "Resource
  classification source") and hold off on configuring the cap until one
  exists.

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
| `PDP says the delegation or agent this request names is unknown to it` | The session names a delegation (or agent) the PDP has never heard of — expired, revoked, or copied from elsewhere. | Run `session-start` again. |
| `could not reach PDP` | Transport failure — the PDP process may be down or the address wrong. | Check the PDP is running and `STRATIUM_PEP_PDP_ADDR` is correct. |
| `PDP did not respond in time` | The PDP is reachable but did not answer inside `STRATIUM_PEP_CONNECT_TIMEOUT`. | Check PDP health/load, or raise the timeout. |
| `PDP returned an error` | The PDP is up and answered, but the call itself failed server-side. | Check the PDP's own logs. |
| `approval ... did not resolve within the escalation timeout` | The action required human approval, and nobody resolved it inside `STRATIUM_PEP_APPROVAL_TIMEOUT`. | Approve escalations faster, or raise the timeout — see "Grant discovery tools" above for the same "the grant is real but unusable" shape applied to timing instead of scope. |
| `approval ... was denied` | The action required human approval, and a human explicitly denied it. | Not a bug — this is the intended outcome of a reviewed escalation. |
| `approval ... is unknown to the PDP` | The PDP no longer recognizes the approval this session was waiting on. | Unusual; retry the tool call (a fresh escalation will be created) and check the PDP's own logs if it recurs. |
| `resource declares no classification; the delegation's classification cap cannot be evaluated and therefore denies` | The delegation has a classification cap configured, and nothing told the PDP what the resource's classification is — expected, since nothing in this system supplies one yet. | Not a bug, and not fixable by retrying. See "Classification caps have no labelling source" above. |
| Anything else | An actual policy decision: a policy was evaluated and does not permit this tool for this principal. | Whoever manages policy for this tenant needs to grant it. |

`proxy` and `extauthz` are later enforcement surfaces over the same PDP call;
`session-start`, `hook`, and `mcp` exist today.
