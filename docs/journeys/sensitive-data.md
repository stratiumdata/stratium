# Protect sensitive data

**You are** a security lead or data owner. **You want** agents to work normally,
but never read files above a clearance level you choose, however the request is
phrased.

This takes two parts:

- **Labels** say what a file is (`/srv/secret/` is `SECRET`).
- **A cap** says how high an agent may reach (`CONFIDENTIAL`).

Stratium works out the label itself, from the path in the tool call. The agent
can't claim a lower label for a file.

## 1. Label everything, then the exceptions

Start with a **catch-all**, an empty prefix that gives every file a default
level. Without it, every unlabelled file is refused once a cap is set.

```bash
curl -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"prefix":"","hierarchy":"nato","level":"UNCLASSIFIED"}'

curl -X POST "http://$PAP/v1/resource-label-rules" \
  -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  -d '{"prefix":"/srv/secret/","hierarchy":"nato","level":"SECRET"}'
```

The longest matching prefix wins. End prefixes with `/`: `"/srv/secret"` would
also match `/srv/secret-notes.txt`.

Two hierarchies ship, `nato` (`UNCLASSIFIED` up to `TOP-SECRET`) and
`commercial` (`PUBLIC` up to `HIGHLY-CONFIDENTIAL`).

## 2. Cap the agent

```bash
curl -sS -X PUT "http://$PAP/v1/agents/$AGENT/classification-caps" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"classification_caps": {"nato": "CONFIDENTIAL"}}'
```

```json
{
  "classification_caps": {"nato": "CONFIDENTIAL"},
  "catch_all": {"nato": "UNCLASSIFIED"},
  "unsatisfiable_tools": ["Glob", "Grep", "TodoWrite", "WebFetch", "WebSearch"],
  "live_delegations": 2,
  "applies": "at next issuance"
}
```

If you haven't created a catch-all, this returns `409`. Stratium won't let you
cap an agent into refusing almost everything by accident.

## 3. Start a new session

Caps are copied onto a session when it starts, like the
[workspace scope](workspace-scope.md). Revoke the live sessions and start new
ones to apply the cap now.

## What the agent experiences

| Call | Result |
|---|---|
| `Read /srv/app/config.yaml` | allowed: `UNCLASSIFIED` is under the cap |
| `Read /srv/secret/plans.txt` | **denied**: `resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato"` |
| `cat /srv/app/x; cat /srv/secret/plans.txt` | **denied**: the strictest label among all paths decides |
| `Grep`, `Glob`, `WebFetch`, … | **denied**, as reported in step 2 |

A sub-agent inherits the cap and can only lower it.

## Limits to know

- **Tools that name no file are refused under any cap**, and so are shell
  commands that name no path. Test your agent's normal work before you enable a
  cap on it.
- **Labels match the path as written.** On macOS, `/tmp` and `/private/tmp`
  are different strings for the same place. Label both spellings.
- **Deleting the catch-all un-labels everything,** so every capped call is then
  refused. Only admins can delete label rules for this reason.

## Undo

```bash
curl -X DELETE -H "Authorization: Bearer $ADMIN" "http://$PAP/v1/agents/$AGENT/classification-caps"
```
