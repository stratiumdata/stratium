# Investigate what an agent did

**You are** reviewing an incident, or answering an auditor. **You want** to know
what an agent was allowed to do, what it tried, and who changed its permissions.

Every decision is recorded, allowed or refused, in an append-only log where
each entry is chained to the one before it by a hash. Every admin change is
recorded the same way, attributed to the operator who made it. A call whose
record can't be written is refused, so no allowed call goes unrecorded.

## 1. Pull the agent's history

```bash
curl -H "Authorization: Bearer $VIEWER" "http://$PAP/v1/audit?agent_id=$AGENT&limit=200"
```

```json
{
  "entries": [{
    "seq": 1287,
    "prev_hash": "3q2+7w==", "entry_hash": "kR4x9A==",
    "occurred_at": "2026-09-16T23:58:35Z",
    "event_type": "decision",
    "agent_id": "5359f7c0-…",
    "decision": "DENY",
    "reason": "resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"
  }],
  "next_before_seq": 1240
}
```

Entries come newest first. To page back, pass `before_seq` set to the
`next_before_seq` you got. When `next_before_seq` is missing, you have
reached the beginning.

## 2. Narrow it down

| Filter | Shows |
|---|---|
| `event_type=decision` | every allow and deny |
| `event_type=delegation_created` | when sessions and sub-agent delegations were issued, and the [approval threshold](require-approval.md) each one got (`action`: `escalate_at DESTRUCTIVE`, or `escalate_at none`) |
| `event_type=containment` | edits that widened an agent's grant |
| `agent_id=…` | one agent |
| `limit=…` | page size, up to 500 |

Filters combine.

## 3. Reconstruct the picture

From the log you can answer:

- **Which agent, for which person,** under which delegation and at what depth.
- **Which tool, at which danger tier,** and whether it was allowed.
- **Which file or path** it touched. Denial reasons name the paths.
- **Who changed what:** every admin edit, revocation, and approval, with the
  operator's identity.

Use [Stop an agent now](stop-an-agent.md) if you haven't already, and
[effective permissions](review-a-change.md#see-everything-one-person-has-handed-out)
to see everything the person behind the agent had handed out.

## Limits to know

- **The exact command isn't stored.** Only a fingerprint (hash) of each tool
  call's input is kept. Raw shell commands in a log that can't be deleted would
  be a liability of their own. You can show *that* `Bash` ran at a given tier,
  not what it ran.
- **Anyone with the viewer role can read the log,** including the paths named in
  reasons. Choose viewers accordingly.
- **This endpoint reads the log; it doesn't verify it.** Each entry carries
  `prev_hash` and `entry_hash`, so you can re-walk a contiguous range yourself.
