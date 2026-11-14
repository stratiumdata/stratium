# Keep an agent in its workspace

**You are** a platform engineer. **You want** an agent to work freely inside
one project directory and touch nothing outside it, even if it is allowed
powerful tools.

This is the **workspace scope**, a path prefix every file a call touches must
fall under. It is how you say *"this agent may write and delete, but only under
`/workspace/`"*.

## 1. Set the scope on the agent

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/resource-constraints" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"resource_constraints": {"id_prefix": "/workspace/"}}'
```

The response tells you what the change will cost before it bites:

```json
{
  "agent_id": "...",
  "resource_constraints": {"id_prefix": "/workspace/"},
  "unsatisfiable_tools": ["Glob", "Grep", "TodoWrite", "WebFetch", "WebSearch"],
  "live_delegations": 2
}
```

- `unsatisfiable_tools`: tools that will **always** be refused under a scope,
  because they don't name a file Stratium can check.
- `live_delegations`: sessions already running that this change does **not**
  affect yet.

The prefix must end in `/`. Without it, `/workspace` would also match
`/workspace-evil/`, so Stratium refuses it.

## 2. Make it take effect

A scope is copied onto each new session when it starts. Running sessions keep
what they were issued with. To apply it now, revoke the live sessions:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/delegations/$ID/revoke"
```

Then start a new session (`session-start`, or `deploy/stratium run`).

## 3. What the agent experiences

| Call | Result |
|---|---|
| `Read /workspace/app/main.go` | allowed |
| `Write /etc/hosts` | **denied**, outside the scope |
| `cat /workspace/a.txt; cat /etc/shadow` | **denied**. Every path in a shell command is checked, so an in-scope path can't carry an out-of-scope one through. |
| `ls /workspace` (no trailing slash) | **denied**. The scope's own root is not inside itself. |
| `npm test` | **denied**. The command names no path, so there is nothing to check. |
| `Grep`, `Glob`, `WebFetch`, … | **denied**, as reported in step 1 |

## Narrowing further for sub-agents

A sub-agent's delegation may go deeper (`/workspace/service-a/` under
`/workspace/`) but never wider, and it can't drop the scope. See
[Hand a sub-agent less](sub-agents.md).

## Limits to know

- **Scope limits *where*, not *how dangerous*.** A delegation allowed to delete
  can delete anything inside the scope. Pair the scope with a tier ceiling that
  fits the work.
- **Path-less commands and search tools are refused under a scope.** Decide
  whether this agent needs them before you set one.

## Undo

```bash
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents/$AGENT/resource-constraints"
```

This clears the scope for sessions started from now on.
