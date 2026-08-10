# Phase 3a — The first enforcement surface: a hook PEP

Four tasks. Puts the system in front of a real agent for the first time.

**Why now, out of spec order.** Everything verified so far has been tests I
specified. Two of the last three phases found defects visible only when
something actually ran — a missing `SELECT` grant on `policies`, then a missing
`INSERT` grant on `delegations` — both invisible to every mocked test because
mocks mock the database. A real agent making real tool calls surfaces a class
of reality nothing else here will.

**Tokens are not required.** Under decision A1 every surface is a network
client of one remote PDP, which loads the delegation from the database. The
hook carries a delegation ID. Signed tokens buy offline verification and
sender-constraining; neither is needed to enforce.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP classifies nothing.** It sends `tool`, `verb`, and `raw_input`; the
  PDP derives the action tier. This is the entire point. The predecessor's hook
  ran regex locally and sent the server its own verdict — spec defect D1, the
  hole that made every enforcement path bypassable, because the component being
  policed declared its own sensitivity. Any tier logic, allowlist, or
  "obviously safe" shortcut in the PEP reintroduces it.
- **Fail closed, always** (A7). PDP unreachable, delegation missing, malformed
  stdin, ambiguous response — every one denies. A hook that fails open is worse
  than no hook, because it looks like enforcement.
- **`ESCALATE` denies for now**, with a reason saying approval is required and
  not yet implemented. The approval subsystem is a later plan. Do not invent a
  local approval prompt.
- **Never log `raw_input` locally.** It reaches the PDP because server-side
  derivation requires it, and lands in the audit chain as a digest. A hook that
  also writes it to a file on a developer's laptop has created a second, worse
  copy with none of the audit chain's protections.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — `stratium-pep hook`

**Files:** `services/cmd/stratium-pep/` (new binary), and tests.

Subcommand structure from the start — `hook` now, `mcp`, `proxy`, and
`extauthz` later — so adding a mode does not restructure the binary.

**The contract**, taken from the Claude Code PreToolUse hook:
- stdin: JSON with `tool_name` and `tool_input`
- exit 0: allow, no output required
- exit 2: deny, with JSON on stdout carrying
  `hookSpecificOutput.permissionDecision` and `permissionDecisionReason`

**Flow:** read stdin → extract tool name and input → build a `DecideRequest`
with `tool`, a `verb` derived from the tool name only (not the input), and
`raw_input` → call the PDP → map the effect to an exit code.

**Deriving `verb` from the tool name is not classification.** It is a label
for which the PDP's own table is authoritative; the PDP re-derives the tier
from `raw_input` regardless and ignores any tier the client suggests. Do **not**
send `declared_tier` at all — the field exists for clients that have one, and
sending a guess only creates an opportunity to be wrong.

**Tests:** an allow exits 0 silently; a deny exits 2 with well-formed JSON and
the PDP's reason; an escalate exits 2 saying approval is unimplemented;
malformed stdin exits 2; an unreachable PDP exits 2; and — assert this
explicitly — the request carries `raw_input` and **no** `declared_tier`.

---

## Task 2 — `stratium-pep session-start`

**Files:** the same binary, plus tests.

Creates a delegation for the session via `CreateDelegation` and caches the
returned ID and **granted** scope to a session file.

**Cache the granted scope, not the requested one.** The gate clamps; a session
file recording what was asked for rather than what was given would make every
later denial look inexplicable.

**Fail closed on creation failure.** If the delegation cannot be created, write
no session file. The hook then finds none and denies everything — correct, and
the failure surfaces at the first tool call rather than silently granting.

**Tests:** a successful creation writes the ID and granted scope; a clamped
creation writes the clamp, not the request; a failed creation writes nothing;
and the file is created with restrictive permissions (0600) since it names a
live delegation.

---

## Task 3 — Configuration, fail-closed hardening, and install docs

**Files:** the binary's config, a README section, and tests.

Configuration: PDP address, agent ID, subject, session-file path, and a
connect timeout. Required values have no defaults — the same rule as the PDP.

**Prove the fail-closed paths, one test each**, and report the exit code and
reason for every one: no session file; a malformed session file; a session file
naming a delegation that no longer exists; PDP unreachable; PDP returns an
error; PDP times out; and a response whose effect is unset.

That last one matters: the proto's `Effect` enum makes `EFFECT_DENY = 0`
deliberately, so an unset field deserializes as deny rather than as an
ambiguous state. Assert it rather than assuming the wire format holds the
invariant.

**Install docs** covering the `.claude/settings.json` hook entry, environment
variables, and a plain statement that every tool call will be denied until a
session is started and a policy permits it.

---

## Task 4 — Against a real agent

This is the task the plan exists for.

**Do not install the hook into the session running this work.** Fail-closed
plus any PDP problem would wedge that session with no way to remove the hook.

Instead, in a scratch directory outside the repository: bring up the compose
stack, seed a tenant, an agent, a Cedar policy, and a delegation; write a
`.claude/settings.json` installing the hook; and run a real `claude -p` session
that performs a few tool calls — some the policy permits, at least one it does
not.

If the `claude` CLI is unavailable, say so plainly rather than simulating it,
and fall back to feeding the binary the exact stdin JSON Claude Code sends,
labelling the result as a contract test rather than a real-agent test. The
distinction matters: one proves the hook works, the other proves the hook works
*with the thing it was built for*.

**Report:** what the agent tried, what was allowed, what was denied, what the
agent did when denied, and the audit rows produced. Include the reason strings
a real user would see — if they are unhelpful, that is a finding worth more
than a passing test.

Then clean up the scratch directory and all containers.
