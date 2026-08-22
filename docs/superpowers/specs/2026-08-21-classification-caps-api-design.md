# Design — an API for `classification_caps`

**Date:** 2026-08-21
**Status:** approved, not implemented
**Supersedes:** the "Known gap" note at `docs/architecture.md:370` and the
`classification_caps` entry in its §8 gap list

---

## The problem

A delegation's `classification_caps` is the ceiling the PDP checks a resource's
label against. Today nothing can set it.

- Issuance writes an empty map on every root delegation
  (`services/internal/pdpgrpc/delegation.go:176`).
- A child copies its parent's map unchanged
  (`services/internal/pdpgrpc/delegation.go:197`), so a chain that starts empty
  stays empty for its whole depth.
- No route on the admin plane writes the column. The PAP exposes
  `GET /v1/delegations` and `POST /v1/delegations/{id}/revoke` and nothing else
  for delegations (`services/cmd/stratium-pap/server.go:239-240`).

`CheckCap` returns allow for an empty map
(`services/pkg/classification/classification.go:130`), so the practical effect
is that **classification enforcement is unreachable**: it cannot be turned on
through any supported interface. Exercising it at all requires a direct `UPDATE`
against `delegations`, which is what the resource-labelling manual test plan
does in its Part B, and what `deploy/stratium verify` declines to do — printing
"NOT DEMONSTRATED" on every run instead.

## What makes this more than a missing setter

Turning a cap on is not a small narrowing. Three behaviours compound:

1. **Empty is the off switch, not a neutral value.** `len(caps) == 0` returns
   allow before anything else is considered
   (`classification.go:130-132`). So any write path that can produce `{}` by
   accident silently disables enforcement.

2. **A cap makes unlabelled resources deny.** With any cap set, a resource whose
   label cannot be resolved returns
   `"resource declares no classification; the delegation's classification cap
   cannot be evaluated and therefore denies"` (`classification.go:149`). This is
   deliberate — the comment above it distinguishes "we could not check" from "we
   checked and it was over the line" for the audit trail — but it means a cap
   without a catch-all label rule denies essentially everything.

3. **Five tools can never satisfy a cap.** `Glob`, `Grep`, `WebFetch`,
   `WebSearch` and `TodoWrite` carry no `resource_field`, so they produce no
   resource id and match no rule — not even the empty-prefix catch-all — and
   deny outright under any cap (`docs/architecture.md` §8).

The design below is shaped by those three facts more than by REST convention.

## Decisions

| # | Question | Decision |
|---|---|---|
| 1 | Where does a root's cap come from? | The **agent row**, like `trust_tier`. Issuance copies it. |
| 2 | Guard against the deny-everything case? | **Refuse** a cap for a hierarchy with no catch-all rule, overridable. |
| 3 | The five fieldless tools? | **Keep denying**; the API names them in its response. |
| 4 | Effect on live delegations? | **Next issuance only.** `revoke` remains the immediate lever. |

Decision 1 puts the ceiling somewhere the agent cannot name for itself: a root
delegation has no parent to clamp against, so a cap supplied in the issuance
request would let an agent choose its own ceiling. Decision 4 preserves the rule
that a delegation is fixed once minted — the property the chain-narrowing
argument rests on.

## Surface

A sub-resource, not a field on the agent object.

```
GET    /v1/agents/{id}/classification-caps    RoleViewer
PUT    /v1/agents/{id}/classification-caps    RoleAdmin
DELETE /v1/agents/{id}/classification-caps    RoleAdmin
```

**Why not a field on `PUT /v1/agents/{id}`.** That route is a whole-object
update at `RoleEditor` (`server.go:221`). A client performing an ordinary
read-modify-write that omits `classification_caps` — an older client, a script
predating the field, a hand-written `curl` — would set it to `{}`, and `{}` is
the off switch. Enforcement would disappear on a `200 OK` with nothing in the
response to indicate it. A sub-resource cannot be cleared by omission: clearing
is an explicit `DELETE`.

Two further reasons follow from the same split. A classification ceiling is
closer in authority to `DELETE /v1/agents/{id}` (`RoleAdmin`, `server.go:222`)
than to renaming an agent, and it cannot have that role while riding on the
editor-level update. And the response carries advice specific to caps, which
would be noise on every unrelated agent edit.

### `PUT` request

Wrapped rather than a bare map, so the route can gain a field later without
ambiguity:

```json
{ "classification_caps": { "nato": "CONFIDENTIAL" } }
```

### `PUT` and `GET` response — `200`

```json
{
  "agent_id": "0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19",
  "classification_caps": { "nato": "CONFIDENTIAL" },
  "catch_all": { "nato": "UNCLASSIFIED" },
  "unsatisfiable_tools": ["Glob", "Grep", "WebFetch", "WebSearch", "TodoWrite"],
  "live_delegations": 2,
  "applies": "at next issuance"
}
```

`GET` returns the same shape, so an operator can read the consequences before
committing to them.

Field meanings, stated because two of them are easy to misread:

- `catch_all` — the level the empty-prefix rule resolves to, per capped
  hierarchy; `null` for a hierarchy with none, reachable only via the override
  below.
- `unsatisfiable_tools` — tools that can never satisfy *any* cap, not tools
  denied by this one. See validation step 3.
- `live_delegations` — the count of the agent's delegations that are neither
  revoked nor expired at the time of the call. These are the delegations the new
  cap does **not** affect. It is a warning, not a confirmation.
- `applies` — a fixed human-readable string, always `"at next issuance"` under
  decision 4. Present so a reader of the raw response is not left to infer
  timing; not a machine-readable field, and clients should not branch on it.

### `DELETE` — `204`

Clears to `{}`, which disables classification enforcement for delegations issued
from that point on. Admin-only and explicit, by decision 2's reasoning.

## Storage and issuance

```sql
ALTER TABLE agents ADD COLUMN classification_caps JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE agents ALTER COLUMN classification_caps DROP DEFAULT;
```

The default exists only to backfill existing rows and is then dropped, so every
`INSERT` must state its intent. This mirrors `000001_baseline.up.sql:38`, which
declines a default on `delegations.approved_tools` and
`delegations.classification_caps` for the same reason.

Issuance changes in exactly one place. `pdpgrpc/delegation.go:176` currently
hardcodes:

```go
ClassificationCaps:  map[string]string{},
```

and becomes a copy of the agent's caps. **Line 197 does not change** — a child
still copies its parent, so children continue to inherit and narrow only, and
the change is confined to roots no longer being special-cased to "no ceiling".

No new read is needed. `pdpgrpc/delegation.go:109` already calls
`s.store.LoadAgent(ctx, agentID)` and **discards the result** —
`if _, err := s.store.LoadAgent(...)` — using it purely as an existence and
eligibility check. The implementation keeps the returned agent instead of
throwing it away, and reads `ClassificationCaps` off it.

## Validation, in order

1. **Well-formedness.** Every key must be a known hierarchy and every value a
   level within that hierarchy, per `services/pkg/classification`. Otherwise
   `400`, naming the valid levels for the hierarchy supplied.

2. **Catch-all precondition.** For each hierarchy named in the cap, a
   resource-label rule with prefix `""` must exist in that hierarchy. Otherwise
   `409`. Overridable with `?allow_uncovered=true` for an operator who
   deliberately wants a deny-by-default posture.

   `409` rather than `400` follows the distinction `writeStoreError` states for
   itself at `services/cmd/stratium-pap/respond.go:88-98`: this describes what
   the tenant's state already is, not something wrong with the request as
   submitted.

3. **Unsatisfiable tools.** Advisory, never blocking. Computed as the agent's
   effective tool set intersected with catalog entries having no
   `resource_field`.

   **`allowed_tools: []` means every tool, not no tools.**
   `store.ErrAllowedToolsRequired` says so verbatim — *"allowed_tools is
   required (use [] to explicitly grant every tool)"*
   (`services/internal/store/agent.go:47`) — and the allowlist check applies
   only `if len(agent.AllowedTools) > 0`
   (`services/internal/authz/agent.go:63`). `nil` is refused outright; there is
   no silent default. So when `allowed_tools` is `[]`, intersect against the
   **entire tool catalog**. Intersecting against the empty list would return no
   warnings for exactly the agents with the widest reach.

4. **Audit.** New event types `agent_caps_set` and `agent_caps_cleared`,
   alongside the existing `agent_created` / `agent_updated` / `agent_deleted`
   (`services/internal/store/agent.go:31-33`). A change to a classification
   ceiling should be searchable on its own rather than folded into
   `agent_updated`.

## Errors

| Code | When | Body |
|---|---|---|
| `400` | unknown hierarchy, or a level not in that hierarchy | names the valid set for the hierarchy given |
| `403` | caller is not `RoleAdmin` | bare `forbidden` |
| `404` | no such agent | bare `not found` |
| `409` | no catch-all rule for a named hierarchy | names the fix and the `?allow_uncovered=true` override |

**Success bodies are JSON; error bodies are plain text.** This is the PAP's
existing convention, not a choice made here — a `401` is the bare word
`unauthorized`, and a conflict is a sentence beginning `store:`. Any client,
test or documentation example must read the status code before parsing. Step 0d
of the agent-integration plan piped `curl` straight into `json.load` and turned
both of its failure modes into the same `JSONDecodeError` with the status and
the message discarded; nothing built against these routes should repeat that.

## Testing

**Store.** Validation matrix: each hierarchy against valid and invalid levels;
catch-all present, absent, and absent-with-override; `nil` versus `{}` on input.

**Handler.** The role matrix, extending the table at
`services/internal/store/pap_e2e_integration_test.go:296-300`: viewer, editor
and admin against `GET`, `PUT` and `DELETE`, asserting editor receives `403` on
both writes.

**Issuance.** Three cases:
- an agent with caps produces a root delegation carrying them;
- a child still copies its parent unchanged;
- an agent with `{}` still produces `{}` — pinning today's behaviour so this
  change cannot silently start capping existing fleets.

**End to end.** The test that is impossible without SQL today. Cap the agent at
`nato: CONFIDENTIAL`, register `/secret/` → `SECRET` and the catch-all, run
`session-start`, then feed the hook a `Read` of `/secret/plans.txt` and assert
`exit=2` with:

```
resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

That string is already documented at `docs/architecture.md:366` and cannot
currently be produced through any supported interface.

**Downstream.** `deploy/stratium verify` gains a fourth assertion and drops its
"NOT DEMONSTRATED" block. The resource-labelling plan's Part B stops needing its
direct SQL write, and its "one thing you cannot test" section shrinks.

## Out of scope

- **Named, shareable cap sets** (a `/v1/classification-caps` object agents
  reference by id). Correct once several agents share a ceiling; nothing needs
  it today, and it adds an object, a join and a lifecycle. This design does not
  foreclose it — a cap set would reuse the same validation.
- **Setting caps at issuance**, via `CreateDelegation` or a
  `STRATIUM_PEP_CLASSIFICATION_CAPS` variable. Rejected: a root has no parent to
  clamp against, so it would let an agent choose its own ceiling.
- **Mutating live delegations.** `POST /v1/delegations/{id}/revoke` is the
  immediate lever and already exists.
- **Changing how fieldless tools behave.** Exempting them from the cap check
  would let `WebFetch` and `WebSearch` reach data with no classification check —
  the hole the cap exists to close. Giving them `resource_field`s is a
  tool-catalog change, tracked separately.

## Risks

- **A cap is a bigger change than it reads as.** Even with the catch-all guard,
  an operator capping an agent removes five tools from it permanently. The
  advisory response is the whole mitigation; if it is dropped in implementation,
  the feature becomes a foot-gun.
- **The override exists.** `?allow_uncovered=true` reintroduces the
  deny-everything case by design. It should appear in the audit entry.
- **`live_delegations` is a count, not a guarantee.** It reports what will *not*
  be affected. An operator reading past it may believe a cap took effect
  immediately when it did not.

## References

- `services/pkg/classification/classification.go:129` — `CheckCap`
- `services/internal/pdpgrpc/delegation.go:176,197` — issuance and inheritance
- `services/internal/authz/delegation.go:105` — the decision-time call
- `services/cmd/stratium-pap/server.go:218-222,239-240` — routes and roles
- `services/cmd/stratium-pap/respond.go:84-106` — status mapping
- `services/internal/store/agent.go:31-33,47` — audit events, `allowed_tools`
- `services/migrations/000001_baseline.up.sql:38,46` — the delegations column
- `docs/architecture.md:366,370` and §8 — the denial string and the gap
  (untracked at the time of writing; line numbers may drift before it lands)
- `docs/testing/2026-08-19-resource-labelling-manual-test.md` — Part B's SQL write
