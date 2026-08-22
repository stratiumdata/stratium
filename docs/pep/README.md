# The five PEP surfaces

`stratium-pep` is one binary with five subcommands. Each is a different place to
stand between an agent and the thing it is about to do.

| Mode | Enforces | Vars | Session file | Blocks on approval |
|---|---|---|---|---|
| [`session-start`](session-start.md) | *nothing* — it **creates** the delegation | 8 | writes it | — |
| [`hook`](hook.md) | a coding agent's tool calls | 8 | reads it | yes |
| [`mcp`](mcp.md) | MCP `tools/call` | 9 | reads it | yes |
| [`proxy`](proxy.md) | gRPC method calls | 9 | no | no |
| [`extauthz`](extauthz.md) | HTTP requests, via Envoy | 6 | no | no |

Every variable count above was read off the binary, by running each mode with an
empty environment and letting it name what it wanted. Each page quotes that
output verbatim.

---

## Which one do I want?

**Your agent is Claude Code or Codex.** [`hook`](hook.md), preceded by
[`session-start`](session-start.md). This is the highest-fidelity surface: the
PDP sees the tool name and its arguments, so classification caps and
resource labels all work.

**Your harness has no hook system** — ChatGPT, Claude Desktop, anything that
speaks MCP and nothing else. [`mcp`](mcp.md). Same fidelity, delivered by
standing in front of the MCP server instead of beside the agent.

**You are policing calls to a gRPC service.** [`proxy`](proxy.md). No client
change beyond one address.

**You are policing HTTP and already run Envoy.** [`extauthz`](extauthz.md).

---

## Two divisions worth understanding

**Session file or not.** `hook` and `mcp` read a session file that
`session-start` wrote — they are companions to a delegation issued on the same
machine. `proxy` and `extauthz` take the delegation token from the *caller*,
in gRPC metadata or an HTTP header, so the agent carries its own authority
across the network.

**Blocking or not.** `hook` and `mcp` can hold a call open while a human
approves an escalation — that is what `APPROVAL_POLL_INTERVAL` and
`APPROVAL_TIMEOUT` are for. `proxy` and `extauthz` cannot: Envoy's `ext_authz`
budget is milliseconds, and a held-open gRPC stream is its own problem. Both
degrade an escalation to a denial carrying the approval id, for the caller to
retry.

---

## What is the same everywhere

- **Fail closed.** A misconfigured surface denies. It does not fall through and
  it does not crash — run any mode with no environment and watch it refuse
  rather than start.
- **One tenant per PDP,** named at that PDP's startup. No request carries one.
- **Nothing is permitted until a policy permits it.** Seeing everything denied
  on a fresh install is usually correct.
- **The delegation's `approved_tools` is checked before the catalog matters.**
  A tool nobody has catalogued is not held, and denies — there is no fall-through
  for unknown tool names.

## The trap that spans all of them

**A surface that cannot run is not a broken enforcement point, it is no
enforcement point.** A hook whose command does not resolve exits `127`, which a
harness treats as a non-blocking error — the tool call proceeds unchecked, and
the only sign is a hook error in a transcript nobody reads. The same shape
appears as `failure_mode_allow: true` on Envoy's filter.

Check the surface is actually running before trusting it. `deploy/stratium
doctor` does this for the `hook` case.

---

## See also

- [`../pep.md`](../pep.md) — the operator reference: every configuration value,
  the decision cache, escalation, and a table decoding every denial string.
- [`../quickstart.md`](../quickstart.md) — a scripted path to a working `hook`
  install, if you would rather not do it by hand.
- [`../architecture.md`](../architecture.md) — how the PEP, PDP and PAP fit
  together.
- [`../../example/`](../../example/) — all five surfaces as runnable programs
  (or, for `hook`, a configuration plus a real captured transcript): a real
  local model, real enforcement, a passing or denied run you can reproduce.
