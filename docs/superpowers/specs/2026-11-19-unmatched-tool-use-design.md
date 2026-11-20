# Reporting tool calls that ran without a decision — design

Status: approved 2026-11-19 · built

## Intent

The PDP only hears from a session when the session asks. If the asking stops
(the hook entry is narrowed, the hook fails open, the harness skips it) the
PDP sees nothing, and silence looks the same as an idle session. This change
gives the PDP a second, independent report from the harness, so it can say
"this tool call ran and I never allowed it" and put that in front of an
operator.

## Goals

- A tool call that ran in a governed session without a matching ALLOW
  decision produces an audit entry and an error-level PDP log line.
- The Delegations screen and API show, per session, how many such calls there
  were.
- No extra write on the decision path, and no write at all for a tool call
  that was properly decided.

## Non-goals

- Blocking anything. This is detection; the tool call has already run.
- Detecting a session whose hooks were all removed. The system install is
  what addresses that; this change does not.
- Codex.
- Notifications, webhooks, metrics.

## Anti-goal

An alarm that fires for ordinary use. A properly governed session must
produce zero reports, or operators will learn to ignore the signal.

## Approaches

1. **Report prompts** (the maintainer's first pick). A `UserPromptSubmit`
   hook tells the PDP a prompt arrived; the PDP flags sessions with several
   prompts and no decisions. A hint: a prompt that needs no tools looks the
   same as one whose tool calls went ungoverned, so it needs a threshold and
   still misfires.
2. **Report completed tool calls (proposed).** A `PostToolUse` hook tells the
   PDP which tool ran with which input; the PDP looks for the ALLOW it gave
   for exactly that. No threshold, no guessing: a miss means that call was
   not decided. Costs one PDP read per tool call.
3. **Quiet-session timer.** Flags any live session with no recent decisions.
   Cannot tell lunch from tampering. Rejected.

Approach 2 is proposed over 1 because it turns a hint into evidence at
similar build cost. Both share one limit: an agent that removes the
decision hook can remove the reporting hook too.

Tested on Claude Code 2.1.329: the `tool_input` a `PostToolUse` (or
`PostToolUseFailure`) hook receives is byte-identical to the one
`PreToolUse` received for the same call, across Write, Bash and Read,
including non-ASCII and escaped characters. That is what makes an exact
match possible: the PDP already stores a SHA-256 of the input with every
decision.

## Design

**PEP.** New subcommand `stratium-pep report`. It reads the hook payload,
loads the session file, and calls the new RPC with the token, tool name and
raw `tool_input`. It never blocks or alters anything: on any failure it
prints one line to stderr and exits 0. It refreshes an expired token once,
the way `hook` does. It accepts `--config` like every other subcommand.

**Wire.** `rpc ReportToolUse(ReportToolUseRequest) returns
(ReportToolUseResponse)`; request carries `token`, `tool`, `raw_input`;
response carries `matched`.

**PDP.** Authenticate the token to get the delegation (no proof of
possession: the call authorizes nothing). Look in `audit_chain` for a row
with that delegation, `event_type = 'decision'`, `decision = 'ALLOW'`, the
same tool name and the same input digest. Found: reply `matched = true` and
write nothing. Not found: append an audit row with
`event_type = 'unmatched_tool_use'` (tool name, input digest, delegation,
agent, subject) and log at error level. One ALLOW can match any number of
reports; that is fine for detection.

**Installer.** `deploy/stratium install` for Claude Code adds `PostToolUse`
and `PostToolUseFailure` entries running `stratium-pep report`, with the
same matcher as `PreToolUse` (a wider reporting matcher would report calls
the decision hook was never asked about). Both install kinds. `--only`
accepts the new events; `status` and `doctor` cover them.

**Operator surface.** `GET /v1/delegations` gains `unmatched_tool_uses`
(count of those audit rows for the delegation). The Delegations screen shows
the count and marks a row where it is not zero. The rows themselves are
readable through the existing `GET /v1/audit?event_type=unmatched_tool_use`.

**Docs.** `docs/pep/hook.md` (install block, what the report means, its
limits), the stop-an-agent and investigate journeys (what to do when the
count is not zero), `docs/pep.md`.

## Calls made by the author (not decided by the maintainer)

- Approach 2 in place of approach 1. This is the main thing to approve.
- No new table and no "last seen" column: everything is read from, or
  appended to, the audit log.
- A report with a bad or unknown token is rejected and not audited.
- The agent holds the token and so can send false reports about itself.
  Accepted: they can only raise an alarm, never clear one.
- The `mcp` surface is out of scope (its tool calls do not pass through
  these hooks).

## Known limits (to be documented)

- A report is lost if the PDP is unreachable when the tool finishes.
- Another hook that rewrites a tool's input after the decision makes the
  call report as unmatched. That is accurate: the input that ran was not the
  input that was decided.
- Hand-written settings with a wider reporting matcher than decision matcher
  produce reports for calls nobody asked about.

## Verification

- Go tests: matched report writes nothing; unmatched report writes one audit
  row and logs; a DENY or ESCALATE decision does not count as a match; a
  different input or tool does not match; bad token is rejected; `report`
  exits 0 on every failure path.
- Store test for the delegation count; PAP handler test for the new field.
- `deploy/stratium selftest` for the new entries.
- Real run against the quickstart stack: a governed session produces zero
  unmatched rows; a session with the `PreToolUse` entry removed and
  `PostToolUse` kept produces one per tool call.
- `make integration`.

## Left to the builder

Names of Go identifiers, the exact log wording, UI styling of the marked
row, and whether the count query is folded into the existing list query.
