# Escalation at Issuance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make human approval something an operator can actually turn on. Today
a delegation escalates only if its `escalate_at` column is set, and nothing
outside a direct database write ever sets it: `CreateDelegation` never
populates it, `RequestedScope` has no field for it, and neither `session-start`,
the PAP, nor the SDK exposes it. The approval machinery downstream of that
column (the delegation leg's escalate band, approvals, `hook`/`mcp`/SDK
waiting) is built and tested. This plan connects the missing front end.

**Architecture:** The threshold enters a chain the way classification caps and
resource constraints already do: **an admin sets it on the agent, and
`CreateDelegation` copies it onto every root.** A caller may additionally ask
for a *lower* threshold, which only ever narrows. Children inherit their
parent's threshold and may lower it. Nothing a caller sends can raise or remove
a threshold.

**Tech Stack:** Go 1.25.0, module `github.com/stratiumdata/stratium`, stdlib
only. Postgres via `lib/pq`. Python SDK regenerated with `grpcio-tools==1.83.0`.

## Why the threshold lives on the agent, not only in the request

The tempting design is a `RequestedScope.escalate_at` field and nothing else.
It fails the project's one test, *could a hostile enforcement point get a
better answer by lying?* `session-start` runs on the agent's machine. If the
threshold exists only when the caller asks for it, a caller that omits it gets
a tier-4 delegation with no human in the loop, whenever policy permits tier 4.
Omission is the lie. So the operator's threshold must come from a row the
caller cannot write (the agent), exactly as `ClassificationCaps` and
`ResourceConstraints` do (`internal/pdpgrpc/delegation.go`, "the only place an
operator can set a ceiling"). The request field is kept because it can only
make a delegation stricter, and children need some way to lower a threshold.

## Effective threshold, by case

`min` treats `nil` as "never escalate", so `min(nil, x) = x`.

| Hop | Agent / parent threshold | Requested | Stored `escalate_at` |
|---|---|---|---|
| root | agent `A` | none | `A` |
| root | agent `A` | `R` | `min(A, R)` |
| root | none | `R` | `R` (a root has no parent, so introducing one narrows) |
| child | parent `P` | none | `P` |
| child | parent `P` | `R` | `min(P, R)` |
| child | none | `R` | **rejected**, as today: `child introduces escalate_at` (spec §4.3.1 shape rule) |

Then, against the **granted** ceiling (after `authz.Clamp`):

- **Root, threshold above granted `max_action_tier`.** The threshold can never
  fire. Store `nil` and report a `ScopeRemoval{Dimension: "escalate_at"}` so
  the caller sees why. This is not a weakening, because no reachable tier is at
  or above it. Today `store.CreateDelegation` returns `ErrEscalateAtUnreachable`
  for this, and `pdpgrpc` maps that to `Internal`. That mapping should never
  fire after this task, and is changed to `InvalidArgument` defensively.
- **Child, threshold above the child's own `max_action_tier`.** See decision D1.

## Decisions for the reviewer

**D1: a worker below its parent's threshold.** Parent `max 4, escalate_at 4`
(unattended up to tier 3), child `max 3`. Today's `permset.Contains` forbids
the child dropping `escalate_at`, and `store.CreateDelegation` forbids storing
`4` above `max 3`. So the child must carry `escalate_at ≤ 3`, which makes its
tier-3 actions escalate even though the parent allowed them unattended. An
orchestrator that hands a worker a *smaller* ceiling ends up with a *noisier*
worker.

- **D1-a (recommended): allow the omission only when it is unreachable.** In
  `Contains`, a child may have `EscalateAt == nil` when
  `inner.MaxTier < *outer.EscalateAt`. That child genuinely cannot reach the
  band, so `nil` and "above my ceiling" mean the same thing. The shape rule's
  purpose (a child's shape derivable from its parent's) still holds, because
  the derivation is "the threshold is above my ceiling". Every other case of
  `TestContains_EscalateAtPresenceIsAsymmetric` is unchanged. A grandchild
  under that child inherits `nil`, which is correct since it is capped at
  `max ≤ 3` too.
- **D1-b: inherit `min(P, child max)`.** No change to `permset`, at the cost of
  the noisy worker above, documented as a limit.

**D2: should the PAP's agent `PUT` carry the threshold?** No (recommended).
Removing a threshold widens a grant, and `PUT /v1/agents/{id}` is editor-level.
It gets its own admin-only route, like caps and scope.

## Global Constraints

- **No new dependencies.** `services/go.mod` byte-identical at the end.
- **Run Go commands from `services/`.** `make ui` once before any task that
  compiles `cmd/stratium-pap` (Tasks 4 and 8).
- **Raise-or-equal only from the caller.** No code path may let a
  caller-supplied value raise or remove a threshold. Every task that touches
  issuance has a test asserting that.
- **Reason strings are operator-facing.** New ones follow the existing
  `child … parent …` wording.
- **Tests run with `-race`.** Conventional commits. Work on a branch.

---

### Task 1: `GrantWidens` must treat an introduced threshold as narrowing

**Bug, independent of the rest.** `permset.GrantWidens` widens
`ClassificationCaps` and `ResourceConstraints` with introduced keys before
calling `Contains`, so adding a cap reads as narrowing. It does nothing for
`EscalateAt`, so adding a threshold to an agent's grant hits `Contains`'s
`child introduces escalate_at` branch and is recorded as a **widening**: a
false `containment` audit entry, and a wrong answer from
`POST /v1/containment` with `"question":"grant"`.

**Files:** `services/pkg/permset/grantwidens.go`, `grantwidens_test.go`

- [ ] Failing test: `before.EscalateAt = nil`, `after.EscalateAt = &4` →
  `GrantWidens` returns `""`.
- [ ] Failing test: `before = &3`, `after = nil` still widens, and
  `before = &3`, `after = &4` still widens.
- [ ] Fix: in `GrantWidens`, when `before.EscalateAt == nil`, set
  `widened.EscalateAt = after.EscalateAt` before `Contains`, mirroring
  `withIntroducedKeys`.
- [ ] `go test -race ./pkg/permset/ ./cmd/stratium-pap/` passes.

### Task 2: D1, unreachable omission in `Contains` (skip if D1-b)

**Files:** `services/pkg/permset/contains.go`, `contains_test.go`

- [ ] Failing test: outer `{Max 4, Esc 4}`, inner `{Max 3, Esc nil}` →
  contained.
- [ ] Test that stays rejected: outer `{Max 4, Esc 4}`, inner
  `{Max 4, Esc nil}` → `child drops parent escalate_at`.
- [ ] Test that stays rejected: outer `{Max 4, Esc 3}`, inner
  `{Max 3, Esc nil}` (3 is reachable) → rejected.
- [ ] Narrow the `outer != nil && inner == nil` case with
  `&& inner.MaxTier >= *outer.EscalateAt`. Extend the asymmetry test's doc
  comment with the reason.

### Task 3: The agent's threshold, in the store

**Files:** `services/migrations/000022_agent_escalate_at.{up,down}.sql`,
`services/pkg/models/agent.go`, `services/internal/store/agent.go`, new
`services/internal/store/agent_escalation.go` and test

- [ ] Migration: `ALTER TABLE agents ADD COLUMN escalate_at SMALLINT CHECK
  (escalate_at BETWEEN 0 AND 4);`, nullable with no default. `NULL` means never
  escalate, for the reason migration 000011 gives.
- [ ] `models.Agent.EscalateAt *ActionTier`, loaded by every agent read.
  `UpdateAgent` (`PUT`) must **preserve** it, the same treatment
  `ClassificationCaps` gets. Test: a `PUT` without the field leaves an existing
  threshold intact.
- [ ] `SetAgentEscalation`, `GetAgentEscalation`, `ClearAgentEscalation`,
  shaped like `agent_constraints`: one transaction, an audit entry attributed
  to the operator, a tenant-epoch bump, and `recordWideningTx` with
  `permset.Set{EscalateAt: before}` → `{EscalateAt: after}`. Clearing or
  raising records a `containment` entry. Setting the first threshold, or
  lowering one, records none (needs Task 1).
- [ ] View type: `{agent_id, escalate_at, live_delegations, applies: "at next
  issuance"}`.

### Task 4: PAP routes

**Files:** new `services/cmd/stratium-pap/agent_escalation.go` and test,
`server.go`, `server_test.go`

- [ ] `GET /v1/agents/{id}/escalation` (viewer), `PUT` (admin),
  `DELETE` (admin). `PUT` body `{"escalate_at": 4}`. A missing key or `null` is
  `400` naming `DELETE`, the same omission guard `resource-constraints` has. An
  out-of-range tier is `400` from `models.ParseActionTier`.
- [ ] Add to `routeTable` and mirror into `papRouteTable`. Bump the pinned
  write-route count (24 → 26) and the doc comment that quotes it.
- [ ] Route-level role tests, plus the omission guard.

### Task 5: Proto

**Files:** `proto/pdp/v1/pdp.proto`, regenerated Go and Python stubs

- [ ] `RequestedScope`: `optional int32 escalate_at = 3;` with a doc comment
  saying it may only lower the effective threshold, never raise or remove one.
- [ ] `GrantedScope`: `optional int32 escalate_at = 4;`, the stored value, so
  callers can display it.
- [ ] `make proto` and `make proto-python`. Check that the generator version
  headers didn't change.

### Task 6: Issuance

**Files:** `services/internal/pdpgrpc/delegation.go` and test,
`services/internal/authz` only if a helper is warranted

- [ ] Validate a requested threshold with `models.ParseActionTier`
  (`InvalidArgument`).
- [ ] Compute the effective threshold per the table above (root from the
  agent, child from the parent, `min` with the request). Apply the unreachable
  rule against **granted** `MaxActionTier`, recording a `ScopeRemoval` at the
  root, and following D1 for a child.
- [ ] Set `d.EscalateAt`. Echo it in `GrantedScope`.
- [ ] Map `store.ErrEscalateAtUnreachable` to `InvalidArgument`, not
  `Internal`.
- [ ] Tests, one per table row, plus:
  - a request of `R > A` stores `A` (cannot raise);
  - a request with no threshold under an agent with one stores the agent's
    (omission cannot remove);
  - root `max` clamped to 3 by policy with agent threshold 4 → `nil`, and a
    removal is reported;
  - a child request to raise is refused by `Contains`, with the existing reason.

### Task 7: `session-start` and the SDK

**Files:** `services/cmd/stratium-pep/session_start.go` and test,
`sdk/python/stratium/{_client,_session,__init__}.py` and tests

- [ ] `STRATIUM_PEP_ESCALATE_AT`, optional. Empty means not requested.
  `session-start` prints the granted threshold, or "none".
- [ ] SDK: `escalate_at: int | None = None` on `Client.create_delegation` and
  `Session`. Add `Scope.escalate_at`.

### Task 8: Live proof

**Files:** `services/internal/store/journeys_integration_test.go` (or a new
`escalation_integration_test.go`)

- [ ] Against the compose stack, with no SQL: register an agent at
  `PLATFORM_TRUSTED`, `PUT …/escalation {"escalate_at":4}`, `CreateDelegation`
  with `max 4`. A tier-4 `Decide` returns `ESCALATE` with an approval id. Approve
  it through the PAP as the root principal. The retry with `approval_id`
  returns `ALLOW`. A tier-3 call never escalates.
- [ ] The same flow with `DELETE …/escalation` before issuance: tier 4 is
  allowed unattended, and the audit log holds a `containment` entry for the
  delete.
- [ ] Replace any existing integration fixture that inserts `escalate_at` by
  SQL with the real path, where that is the point of the test.

### Task 9: Docs

- [ ] `user-guide.md` §5.2 route table, a new §5.5 subsection beside
  resource constraints, and §6.4: add the `action tier X at or above delegation
  escalate_at Y` reason.
- [ ] `pep/session-start.md`: the new variable.
- [ ] `default-posture.md` §5: replace `max_action_tier: 4, escalate_at: 4`
  with the actual commands.
- [ ] New journey `docs/journeys/require-approval.md`: set the threshold, start
  a session, watch `hook` block, approve in the console, see the call proceed.
  Plus approver identity (§4.4), the 24h approval TTL, the network surfaces
  degrading to a denial, and unattended runs. Add it to `journeys/index.md` and
  the nav.
- [ ] Glossary: point **Escalation** at the journey.

## Out of scope

- A `deploy/stratium up --escalate-at` flag. The journey uses the PAP route
  directly. Add the flag if the quickstart should demo approvals.
- An admin-console panel for the threshold. The console's agents screen gains
  caps and scope panels only when asked. The route is enough to ship.
- Per-tool thresholds. The model is one band per delegation, and this plan
  doesn't change that.

## Risks

| Risk | Mitigation |
|---|---|
| A caller removes or raises a threshold by omission or by asking | Tasks 6 and 8 assert both directions, against the store and live |
| D1-a loosens a security rule in `permset` | It applies only when the band is unreachable from the child's own ceiling; the two "stays rejected" tests in Task 2 pin the boundary |
| Existing delegations change behaviour | None: thresholds are copied at issuance only, and existing rows and agents read `NULL` (never escalate) |
| An agent-level threshold surprises an operator mid-session | The PUT response reports `live_delegations` and `applies: "at next issuance"`, like caps |
