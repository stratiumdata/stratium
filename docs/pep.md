# Installing the `stratium-pep` hook

`stratium-pep` is the client-side enforcement binary: it sits in front of a
real agent and asks the PDP (`stratium-pdp`) to decide every tool call over
gRPC before that tool call runs. It classifies nothing itself — see the
package doc in `services/cmd/stratium-pep/hook.go` for why that boundary is
load-bearing, not incidental.

**Every tool call is denied until a session is started and a policy permits
it.** If you install this hook and see every tool call denied, that is very
likely correct, working behavior for an agent that has no session yet — not
a bug. Run `stratium-pep session-start` first (below), and confirm a policy
actually grants the agent the tool it's asking for. See "Reading a denial"
at the bottom for how to tell that apart from a real misconfiguration or
outage before filing one.

## Build

    cd services && go build -o /usr/local/bin/stratium-pep ./cmd/stratium-pep

Or place the binary anywhere on `PATH` — the examples below just invoke
`stratium-pep`.

## Environment variables

Every variable below is required, with no default: the same rule
`internal/config.Load` uses for the PDP itself. A hook that starts against a
guessed PDP address, or that waits forever (or not at all) for a reply,
fails at the first tool call in a way that looks like a policy denial
rather than a misconfiguration. Set the same five values for both
`session-start` and `hook` — they must agree on which PDP, agent, and
subject a session belongs to.

Shared by both subcommands:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_PDP_ADDR` | `host:port` of the PDP, e.g. `localhost:50051`. |
| `STRATIUM_PEP_AGENT_ID` | The acting agent's registry UUID. |
| `STRATIUM_PEP_SUBJECT` | The principal the agent acts on behalf of (e.g. an email). |
| `STRATIUM_PEP_SESSION_FILE` | Path to the session file. `session-start` writes it; `hook` reads it fresh on every single tool call, so a revocation or a fresh session takes effect on the very next call. |
| `STRATIUM_PEP_CONNECT_TIMEOUT` | How long to wait for the PDP before failing closed, e.g. `5s`. |

`session-start` only, in addition to the five above:

| Variable | Meaning |
|---|---|
| `STRATIUM_PEP_REQUESTED_TIER` | Action-tier ceiling to request: `0` REASONING, `1` READ_ONLY, `2` INTERNAL_MODIFY, `3` EXTERNAL_COMMS, `4` DESTRUCTIVE. The PDP may grant less than this — the session file records what was actually granted, not what was requested. |
| `STRATIUM_PEP_REQUESTED_TOOLS` | Comma-separated tool names to request, e.g. `Read,Grep,Bash`. Must not be empty. |
| `STRATIUM_PEP_TTL_SECONDS` | How long the new delegation is valid for, in seconds. |
| `STRATIUM_PEP_PURPOSE` (optional) | Free-text reason for the delegation, for audit legibility. |

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

The five shared environment variables (above) need to be set in the
environment `claude` itself runs in, so both hook invocations inherit them.

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

## Reading a denial

Every denial exits 2 and prints JSON on stdout:
`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"..."}}`.
The reason text says which of these you're looking at — the distinction
between "you are not allowed" and "we could not ask" matters, because the
fix is different:

| Reason says... | Means | Fix |
|---|---|---|
| `no session file at ... -- run 'stratium-pep session-start' first` | No session was ever started, or one ended. | Run `session-start`. |
| `session file ... is malformed` | The file exists but is not valid JSON. | Delete it and run `session-start` again. |
| `PDP says the delegation or agent this request names is unknown to it` | The session names a delegation (or agent) the PDP has never heard of — expired, revoked, or copied from elsewhere. | Run `session-start` again. |
| `could not reach PDP` | Transport failure — the PDP process may be down or the address wrong. | Check the PDP is running and `STRATIUM_PEP_PDP_ADDR` is correct. |
| `PDP did not respond in time` | The PDP is reachable but did not answer inside `STRATIUM_PEP_CONNECT_TIMEOUT`. | Check PDP health/load, or raise the timeout. |
| `PDP returned an error` | The PDP is up and answered, but the call itself failed server-side. | Check the PDP's own logs. |
| Anything else | An actual policy decision: a policy was evaluated and does not permit this tool for this principal (or the action requires human approval, not yet implemented). | Whoever manages policy for this tenant needs to grant it. |

`mcp`, `proxy`, and `extauthz` are later enforcement surfaces over the same
PDP call; only `hook` (a Claude Code `PreToolUse` hook) and `session-start`
exist today.
