# Require approval for risky actions

**You are** a platform or security lead. **You want** an agent to work on its
own for routine actions, and to stop and wait for a person before anything
destructive, such as deleting files or running a migration.

This is the **escalation threshold**. At or above the tier you choose, a call
doesn't run and isn't refused. It waits until a person approves or denies it.

## 1. Make sure the agent may do the work at all

Approval is layered on top of the normal checks, never instead of them. A
`DESTRUCTIVE` (tier 4) action still needs a `PLATFORM_TRUSTED` agent and a
session whose ceiling reaches tier 4. If the agent's trust tier is lower, the
call is refused outright and no one is asked.

## 2. Set the threshold on the agent

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/escalation" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"escalate_at": 4}'
```

```json
{"agent_id": "...", "escalate_at": 4, "live_delegations": 1, "applies": "at next issuance"}
```

`4` means everything up to tier 3 (`EXTERNAL_COMMS`) runs unattended, and
anything `DESTRUCTIVE` waits for a person. Use `3` to also ask before anything
that reaches outside, such as `git push` or `curl`.

The threshold is set by an admin on the agent, not by the session, because a
session can't be trusted to ask for its own supervision. A session may ask for
a *lower* threshold (`STRATIUM_PEP_ESCALATE_AT`), never a higher one or none.

## 3. Start a new session

The threshold is copied onto each session when it starts. Revoke any live
sessions, then start one with a ceiling that reaches the band, for example
`STRATIUM_PEP_REQUESTED_TIER=4`. The session file shows what you got:

```json
"granted_scope": { "max_action_tier": 4, "tools": ["Read", "Bash"], "escalate_at": 4 }
```

If the session's ceiling ends up below the threshold (say policy only grants
tier 3), the threshold could never fire. It is dropped and listed under
`removed` with the reason `unreachable`.

## 4. The agent hits the band

The agent runs `rm -rf build/`. Stratium rates it `DESTRUCTIVE`, creates a
pending approval, and the call **waits**. On `hook` and `mcp` the agent's tool
call blocks, polling for an answer every `STRATIUM_PEP_APPROVAL_POLL_INTERVAL`,
for up to `STRATIUM_PEP_APPROVAL_TIMEOUT`.

## 5. A person approves it

In the admin console, open **Approvals**. Or with the API:

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/approvals"
curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/approvals/$ID/approve"
```

Only the **person the agent is acting for** can approve: the approver needs
the admin role *and* an approver identity equal to the approval's
`root_principal`. Being an admin alone isn't enough. See
[the approver claim](../user-guide.md#44-the-approver-claim-and-why-it-is-separate).

## 6. The call proceeds

The waiting call is retried with the approval and runs. Every other check is
evaluated again at that moment, so a session revoked while the approval was
pending still refuses.

## What you'll see

| Situation | Result |
|---|---|
| A call below the threshold | runs, no one is asked |
| A call at or above it | waits; approved, it runs; denied, it is refused |
| No answer before the PEP's timeout | refused, with a reason naming the approval |
| No answer within `STRATIUM_APPROVAL_TTL` (default 24h) | the approval expires and a retry is refused |
| Above the session's ceiling, or not trusted enough | refused outright: approval never overrides the other checks |

## Limits to know

- **One approval covers one call.** It is bound to the exact input. A retry
  with a different command needs its own approval.
- **Only `hook`, `mcp`, and the Python SDK wait.** `extauthz` and `proxy`
  refuse with a reason naming the approval id, and the client must retry after
  it is approved. See [Govern a tool server](tool-server.md).
- **Unattended runs have no one to approve.** For overnight or CI agents, keep
  the session's ceiling below the threshold, or expect the run to stop there.
- **Removing or raising a threshold is recorded as a widening** in the audit
  log, with the operator who did it. See
  [Investigate what an agent did](investigate.md).

## Undo

```bash
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents/$AGENT/escalation"
```
