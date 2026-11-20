# Stop an agent now

**You are** on call, or you have just seen an agent do something it shouldn't.
**You want** it stopped on its very next tool call, everywhere it is running,
without losing the record of what it did.

Pick the narrowest switch that covers the problem:

| To stop | Do this | Role |
|---|---|---|
| **One session** | Revoke its delegation | admin |
| **Every session of one agent** | Suspend the agent | editor |
| **One kind of action** | Narrow the agent's allowlist, then revoke and restart its sessions | editor, then admin |

All three take effect on the **next tool call**. Every change in the admin plane
invalidates every cached decision across the fleet, so no agent keeps working
from an old answer.

## Revoke one session

Find it, then revoke it:

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/delegations"
curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/delegations/$ID/revoke"
```

The agent's next call is refused with `delegation … is revoked`. Any
[sub-agent](sub-agents.md) delegations issued under it stop too, because the
whole chain is rechecked on every call.

## Suspend the agent

`PUT` replaces the whole record, so send every field with `suspended: true`:

```bash
curl -X PUT "http://$PAP/v1/agents/$AGENT" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"name":"alice-claude-code","provider":"anthropic","model_id":"claude",
       "trust_tier":3,"enabled":true,"suspended":true,"allowed_tools":[]}'
```

Set `suspended` back to `false` to resume. Nothing else needs to change.

!!! tip "Suspend, don't delete"
    Deleting an agent that still has live delegations or approvals returns
    `409`. Suspending is immediate, reversible, and keeps the history intact.

## Afterwards

If you are here because the Delegations screen marked a session `N undecided`,
revoking does not stop it: that session's tool calls are running without
asking. Stop the agent process itself, then find out why its decision hook is
not running ([Reporting tool calls](../pep/hook.md#reporting-tool-calls)).

Revocations and suspensions are recorded in the audit log, attributed to the
operator who made them. Continue with
[Investigate what an agent did](investigate.md).
