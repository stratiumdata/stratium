# Understand a denial

**You are** anyone running an agent behind Stratium. **You want** to know why a
tool call was blocked, and whether to fix your configuration or accept the
answer.

Every denial carries a reason, and the agent sees it. The first question to ask
is whether **you** made a mistake or the **system** is doing its job.

## Step 1: Is it configuration or policy?

| The reason… | What it means |
|---|---|
| names an environment variable (`missing required configuration: …`) | The PEP is misconfigured. **Not** a policy decision. |
| says the PDP couldn't be reached or didn't respond | A network problem or PDP outage. The PEP failed closed. |
| names a tier, a tool, a classification, or a delegation | Stratium is working. Read on. |

## Step 2: Find which check refused it

A call is allowed only if three independent checks all pass: **you** (policy),
**the agent** (its trust and allowlist), and **the delegation** (what you
handed over). The reason tells you which one refused.

| Reason begins with | Refused by | What you can do |
|---|---|---|
| `default deny: no policy verdict allowed` | Policy | Write or fix a policy for this person. [User guide §5.4](../user-guide.md#54-crud-policies) |
| `agent trust tier X insufficient for action tier Y` | Agent | Raise the agent's trust tier, deliberately. |
| `tool "X" not in agent allowed_tools` | Agent | Edit the agent's allowlist. [§5.5](../user-guide.md#55-crud-agents) |
| `action tier X exceeds delegation max_action_tier Y` | Delegation | Start a new session with a higher `STRATIUM_PEP_REQUESTED_TIER`, if your policy allows it. |
| `tool "X" not in delegation approved_tools` | Delegation | Add the tool to `STRATIUM_PEP_REQUESTED_TOOLS` and start a new session. |
| `resource classification X exceeds delegation cap Y` | Delegation | The file is above the agent's clearance. This is usually the right answer. |
| `resource declares no classification; … cannot be evaluated` | Delegation | A cap is set and nothing labelled this resource. Add a catch-all label rule. |
| `delegation … is revoked` / `expired at …` | Delegation | Start a new session. |

A reason that reads `action tier X at or above delegation escalate_at Y` is
not a denial: the call is waiting for a person to
[approve it](require-approval.md).

`at depth N` in a reason tells you which hop of a delegation chain refused:
`depth 0` is the session you started, and higher depths are
[sub-agents](sub-agents.md).

## Step 3: Decide whether to change anything

Most denials are the system doing what you asked. Before widening anything:

- **Widening a delegation widens every action at that level** for the rest of
  the session, not just the one you were blocked on.
- **An agent will often find another route.** If `rm -rf node_modules` is
  refused, an agent may try `find . -name node_modules -delete`, which looks
  like a read. Treat the tool list, the tier ceiling, and the
  [workspace scope](workspace-scope.md) as the real limits, not the command
  classifier.
- **Tier overrides only raise.** You can make Stratium treat a command as more
  dangerous, never less. If a tool is consistently rated too high, fix its
  [tool catalog](../user-guide.md#56-crud-tools-the-tool-catalog) entry.

## Limits to know

- **Tools that name no file can't be checked under a cap or a scope.** `Glob`,
  `Grep`, `WebFetch`, `WebSearch`, and `TodoWrite` are denied whenever a
  classification cap or workspace scope is set, and so is a shell command that
  names no path, such as `npm test`. Stratium has nothing to check, so it
  refuses.
- **A refused call costs two round trips.** The PEP retries once with a fresh
  token in case the old one expired. That retry is expected.
