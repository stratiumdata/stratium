# Review a change before you make it

**You are** a security reviewer, or anyone about to change what an agent may do.
**You want** a straight answer to *"does this allow anything that wasn't allowed
before?"*, without testing calls one at a time.

## Compare two permission sets

Give Stratium the current grant (`baseline`) and the proposed one
(`candidate`). It writes nothing.

```bash
curl -X POST -H "Authorization: Bearer $EDITOR" -H 'Content-Type: application/json' \
  "http://$PAP/v1/containment" -d '{
    "question":  "grant",
    "baseline":  {"approved_tools":["Read","Write"],"max_action_tier":3,"expires_at":"2026-12-01T00:00:00Z"},
    "candidate": {"approved_tools":["Read","Bash"],"max_action_tier":3,"expires_at":"2026-12-01T00:00:00Z"}
  }'
```

```json
{"question":"grant","contained":false,"reason":"child tool Bash not in parent approved_tools"}
```

`contained: false` means the candidate allows more, and `reason` names the first
place it does. `contained: true` means nothing got wider.

Send all six fields that bound a grant (`approved_tools`, `max_action_tier`,
`escalate_at`, `classification_caps`, `resource_constraints`, `expires_at`). An
omitted field counts as empty, which isn't always the same as unrestricted.

## Ask the right question

| `"question"` | Asks | Use it when |
|---|---|---|
| `"grant"` | *Did this get wider?* | Reviewing a change to an agent's grant. Adding a cap counts as narrowing. |
| `"delegation"` (default) | *May a child hold this?* | Checking whether a [sub-agent](sub-agents.md) delegation would be accepted. A child can't add a limit its parent didn't have. |

The two can answer differently for the same input, so name the one you mean.

## Catch widenings after the fact

When an edit to an agent widens its grant, the edit goes through, and Stratium
records a `containment` entry in the audit log. To see them:

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/audit?event_type=containment"
```

## See everything one person has handed out

Each delegation is checked against the one above it, but separate delegations
held by the same person aren't checked against each other. One session that can
read `/secret` and another that can reach the internet are each fine alone, and
together they're a way out for the data. To see the combined reach:

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/principals/alice@example.com/effective"
```

```json
{
  "principal_id": "alice@example.com",
  "union": {"approved_tools":["Bash","Read"],"max_action_tier":3, "...": "..."},
  "delegations_counted": 2,
  "imprecision": ["resource constraint id_prefix differs across members (/workspace/ vs /tmp/), so the union is unconstrained for it"]
}
```

- `delegations_counted` tells "holds nothing" apart from "holds everything",
  because an empty tool list means unrestricted.
- `imprecision` lists where the union had to round up.

This is a **report**. Nothing is enforced against it yet.
