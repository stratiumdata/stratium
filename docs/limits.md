# What Stratium does not stop

Stratium decides whether a tool call may go ahead. It is not a sandbox, and it
does not make an agent safe by itself. This page collects the limits that the
rest of the documentation states where they apply, so you can read them in one
place before you rely on it.

None of these is a reason not to deploy. They are the shape of what you get.

## The enforcement point is only as strong as its install

The hook governs an agent that runs as you, and anything you can write, the
agent can write.

- **A per-project or per-user install can be removed by the agent.** The hook
  entry, the binary and the configuration are all within its reach. That
  install is right for trying Stratium out, and for an agent you trust not to
  edit its own guard rails. It does not hold against an agent that is trying
  to get out.
- **The system install puts all three where only root can write.** What that
  does and does not stop differs by harness; each harness page says.
- **A tool call that ran without a decision is reported, not prevented.** The
  PDP records it as `unmatched_tool_use` and marks the session. That tells you
  afterwards; it relies on the reporting hook still being in place.

See [What the install protects](pep/hook.md#what-the-install-protects).

## The shell classifier is a heuristic

The PDP reads a command's text. It does not run a shell.

- **A capable agent can route around a tier.** `rm -rf node_modules` is rated
  destructive; an interpreter one-liner that deletes the same directory is
  rated as an ordinary modification. The controls that hold are the
  delegation's ceiling, the tool list and escalation, not the classifier.
- **`READ_ONLY` is the exception.** It is an allowlist of plain commands, not
  a guess.

See [A default posture](default-posture.md#6-what-this-posture-does-not-defend-against).

## A path scope is not a sandbox

An `id_prefix` keeps a well-behaved agent in its lane.

- **On a shell tool it checks words, not effects.** A script or interpreter
  that opens files itself, a bare name given to a command the check does not
  know, and a symlink inside the scope that points out of it all get through.
  To confine a shell, run it where the files outside its scope are not
  reachable.
- **Scope limits where, not how dangerous.** A delegation allowed to delete
  can delete anything inside its scope.
- **Commands and tools that name no resource are refused under a scope**:
  `npm test`, and search tools with no path argument.

See [Keep an agent in its workspace](journeys/workspace-scope.md) and the
`id_prefix` notes in the [user guide](user-guide.md).

## Arguments are authorized as sent

Stratium decides on the tool call it is shown.

- **It does not see what a tool does next.** An MCP server or an HTTP API can
  do more with its arguments than they say.
- **It polices the tool call, not the model.** Nothing here reads prompts or
  model output, and nothing detects prompt injection. It limits what an
  injected agent can do, which is a different thing.

See the limits on [mcp](pep/mcp.md#limits), [proxy](pep/proxy.md),
[extauthz](pep/extauthz.md#limits) and [agentgateway](pep/agentgateway.md#limits).

## The model has gaps it names

- **No ceiling across one person's sessions.** Each delegation is checked
  against what that person may grant. Nothing checks two of them against each
  other, so one session that can read a secret and another that can reach the
  internet are each in bounds. `GET /v1/principals/{id}/effective` reports the
  union; nothing enforces against it.
- **Trust tier is asserted, not proven.** It records a decision a person made
  about an agent. There is no attestation of the agent itself.
- **Routine and catastrophic share a tier.** Permitting a routine destructive
  operation permits every destructive operation the scope allows.
- **Raw tool inputs are never stored.** The audit chain proves which agent was
  allowed which tool at which tier, and holds a digest of the input, never the
  command.

See [Concepts](concepts.md) and
[the scope statement](validation-journeys.md#6-honest-scope-statement-now-that-1-2-and-4-6-have-landed).

## Approvals need a person

- **One approval covers one call**, bound to its exact input.
- **Unattended runs have no one to approve.** Keep an overnight or CI agent's
  ceiling below the approval threshold, or expect it to stop there.

See [Require approval](journeys/require-approval.md).

## It is a pre-release

Settings, wire contracts and defaults can still change between versions. Not
every harness was verified the same way: each harness page says how, and the
[Codex](pep/harnesses/codex.md) page says it was not run in a live session.

To report something this page should say and does not, see
[SECURITY.md](https://github.com/stratiumdata/stratium/blob/main/SECURITY.md).
