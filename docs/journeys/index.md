# User journeys

Each journey starts from something you want to get done, then shows the steps,
what Stratium does at each one, and what you will see.

| I want to… | Who it's for | Journey |
|---|---|---|
| Put my coding agent behind Stratium and see it enforce | Developer, platform engineer | [Your first governed agent](first-agent.md) |
| Understand why a tool call was blocked | Anyone running an agent | [Understand a denial](understand-a-denial.md) |
| Keep an agent inside one project directory | Platform engineer | [Keep an agent in its workspace](workspace-scope.md) |
| Stop an agent from reading sensitive files | Security, data owner | [Protect sensitive data](sensitive-data.md) |
| Have a person approve destructive actions | Platform, security lead | [Require approval for risky actions](require-approval.md) |
| Give a sub-agent less authority than its orchestrator | Agent developer | [Hand a sub-agent less](sub-agents.md) |
| Put an MCP server, HTTP API, or gRPC service behind Stratium | Platform engineer | [Govern a tool server](tool-server.md) |
| Check what a permission change would allow before making it | Security reviewer | [Review a change before you make it](review-a-change.md) |
| Stop a misbehaving agent right now | On-call, security | [Stop an agent now](stop-an-agent.md) |
| Find out what an agent did | Security, compliance | [Investigate what an agent did](investigate.md) |

## Before you start

The API examples assume two shell variables:

- `$PAP`: the admin plane's address, for example `localhost:8080`.
  `deploy/stratium status` prints it for the local stack.
- An operator token in `$VIEWER`, `$EDITOR`, or `$ADMIN`, matching the role the
  call needs. See [Getting a token for scripting](../user-guide.md#45-getting-a-token-for-scripting).

Everything shown with `curl` can also be done in the admin console at `http://$PAP/`.

## Three habits that save time

1. **Read the reason.** Every denial says which check refused it and why.
   [Understand a denial](understand-a-denial.md) shows how to read one.
2. **Scope and caps apply at the next session.** A delegation keeps the limits
   it was issued with. To apply a change now, revoke the live delegation and
   start a new session.
3. **Ambiguity denies.** If Stratium cannot tell whether a call is allowed, it
   refuses it. When something unexpected is blocked, look for what Stratium
   could not see, such as a file with no label or a tool that names no path.
