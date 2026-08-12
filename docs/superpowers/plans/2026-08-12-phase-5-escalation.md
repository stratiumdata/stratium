# Phase 5 — Escalation and the approval subsystem

Implements spec §3.4 **E4**/**E5** and §4.6.1 **E6**–**E9**. Unblocks conformance
properties **C21** and **C22**. Five tasks.

**What exists and what does not.** `ESCALATE` has been a first-class effect
since Phase 0: `authz.FoldVerdicts` checks for it before default-deny,
`authz.Decide` propagates it, `DecideResponse` carries it, and the hook PEP
denies on it with an honest "approval is required and not yet implemented".

**Nothing produces it.** No engine emits an escalating verdict and no other
path sets one, so every one of those branches is unreachable today. That is
deliberate — the subsystem did not exist — but it means this phase is the first
time any of that machinery runs, and the branches must be treated as unproven
rather than as working code being extended.

**Escalation is not a policy verdict** (§4.6.1 E9). Cedar and XACML have exactly
two effects, so a policy-driven escalation would be expressible in Rego and
JSON only, reintroducing the per-engine capability gap Phase 4a existed to
eliminate. It keys off the derived tier instead, which every engine and every
surface already shares.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- `internal/authz` stays pure: no database handle, no network, no ambient
  clock. `Now` is injected. It may import `models`; it may never import
  `internal/policy` or `internal/store`.
- **`authz.FoldVerdicts` keeps its shape** — N verdicts in, one `LegResult` and
  one deciding verdict out. One decision per check. Nothing in this phase adds
  a second combining rule.
- **Deny still overrides escalate.** An action above the delegation's
  `max_action_tier` denies, whether or not it is also at or above the
  escalation threshold. Escalation exists only in the band between the two.
- **Fail closed everywhere.** An approval that cannot be loaded, parsed,
  matched, or verified denies. A missing approval denies. An expired approval
  denies. There is no path on which an error produces an allow.
- **An approval is a fourth condition, never a bypass.** It satisfies the
  escalation requirement only; the principal, agent, and delegation legs all
  still evaluate on the approved retry. An approval must never turn a denial
  into an allow.
- Every store query is tenant-scoped by RLS via `beginTenantTx`; **no
  `WHERE tenant_id` in any Go query**.
- `audit_chain` is append-only and hash-chained. Any new `Entry` field enters
  `Hash()`'s serialization in the same change; `TestHash_CoversEveryField`
  asserts coverage via `reflect.NumField()` and will fail until it does.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The escalation threshold, and making `ESCALATE` reachable

**Files:** `services/pkg/models/delegation.go`, `services/internal/authz/`,
a migration, and their tests.

`Delegation` gains an escalation threshold beside `max_action_tier`. At or above
it, and within the ceiling, a decision escalates.

**Represent "never escalate" explicitly, not as a zero value.** `REASONING` is
tier 0, so a plain `models.ActionTier` zero would mean "escalate on everything",
which is the opposite of a safe default for existing rows. Use a nullable column
and a pointer or an explicit sentinel, and make the migration's default mean
*never escalate* so every delegation written before this phase behaves exactly
as it does today. Say so in the migration comment.

**The band, and its ordering.** Given `escalate_at` and `max_action_tier`:

```
tier > max_action_tier      -> DENY      (unchanged; deny overrides escalate)
escalate_at <= tier <= max  -> ESCALATE
tier < escalate_at          -> unchanged by this leg
```

A threshold above the ceiling is unreachable — the ceiling denies first. That
is not an error, but it is almost certainly an authoring mistake, so
`CreateDelegation` should reject it rather than persist a rule that can never
fire. This is the same *semantically dead* class Phase 4a swept out of all four
policy engines; do not reintroduce it one layer up.

**`ScopeNarrows` must handle the new dimension** (spec §4.3.1). A child may
**lower** the threshold — escalating sooner is narrower — and may never raise
it. And per §4.3.1 a child may not introduce a threshold its parent leaves
unset, nor drop one its parent sets. Add all three cases to
`delegation_test.go`, and mutation-test each: the omission case is the one that
has bitten this function before.

**Tests:** each boundary of the band exactly (at the threshold, one below, at
the ceiling, one above); deny wins when the tier exceeds the ceiling even
though it also exceeds the threshold; an unset threshold never escalates; and
`ScopeNarrows` accepts a lowered threshold, rejects a raised one, rejects an
introduced one, rejects a dropped one.

**Mutation-test and report survivors:** make the band inclusive at the wrong
end; let escalate win over deny; make an unset threshold mean tier 0.

---

## Task 2 — The approvals table

**Files:** a migration, `services/internal/store/approval.go`, and tests.

One row per escalated decision. Columns, at minimum: id; tenant id; the agent,
delegation, and root delegation ids; the requesting subject; the **root
principal** who may approve (C21); the tool, action, and derived tier; the
request's `input_digest`; a status; `requested_at`; `expires_at`; and nullable
`approved_by` / `approved_at`.

**Status is a closed vocabulary with a CHECK constraint** — `pending`,
`approved`, `denied`. There is deliberately no `expired` status: expiry is a
function of `expires_at` and the current time, and a stored status that must be
kept in sync with a timestamp is a status that will drift out of sync with it.
A reader computes expiry; nothing writes it.

**RLS on the table, enabled and forced, exactly as every other tenant table.**
Grants: the serving role needs `SELECT` and `INSERT` (the PDP creates pending
records and reads them). It must **not** get `UPDATE` — under E7 the PDP never
grants an approval, and the grant is the enforcement of that, not a comment
saying so. Say that in the migration.

`CreateApproval` and `LoadApproval`, tenant-scoped via `beginTenantTx`.

**Tests** with sqlmock: the tenant is set before the query; a row round-trips
field for field with distinguishable values (this project has twice had a
fixture whose fields were indistinguishable enough to mask a mixup); a load of
an unknown id is a clean not-found rather than an error; and the transaction is
committed or rolled back on every path. Then an integration test proving the
serving role genuinely **cannot** `UPDATE` the table — a grant nobody tests is
a grant that will be widened by accident.

---

## Task 3 — `Decide` escalates, and consumes an approval

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/`, and tests.

`DecideResponse` gains an approval id, set when the effect is `ESCALATE`.
`DecideRequest` gains an **optional** approval id, sent on the retry.

**Without an approval id:** a decision landing in the escalation band creates a
pending approval row and returns `ESCALATE` with its id. The row's approver is
the **root** principal of the delegation chain — at depth > 0 the immediate
delegator is an agent, and routing approval to an agent would let the chain
approve itself (C21).

**With an approval id**, verify every one of these, and deny naming the reason
if any fails:

1. the approval exists and belongs to this tenant (RLS does this);
2. its status is `approved`;
3. `now` is before `expires_at`;
4. `approved_by` equals the chain's root principal;
5. it **matches this request** — same agent, delegation, tool, action, derived
   tier, and `input_digest`.

**Point 5 is the load-bearing one.** Without it an approval for
`Read /tmp/notes.txt` authorizes `Bash rm -rf /`. `input_digest` already exists
for the audit chain; reuse it rather than inventing a second notion of request
identity. Test the mismatch of each bound field separately — one test covering
"some field differs" would leave the others unguarded.

**A valid approval satisfies the escalation condition only.** All three legs
still evaluate on the retry, and a leg that denies still denies. Assert this
directly: an approved escalation whose delegation has since been revoked must
deny, not allow.

**Audit both events.** The escalation and the approved retry are separate
decisions and each gets its own chain entry. A phase that made escalations
invisible to the audit chain would be worse than one that denied them.

**Mutation-test and report survivors:** skip the `input_digest` match; accept
an approval whose `approved_by` is the immediate delegator rather than the
root; accept an expired approval; let a valid approval short-circuit the other
legs.

---

## Task 4 — `GetApproval`, and the PEP blocks

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/`,
`services/cmd/stratium-pep/`, and tests.

`GetApproval(approval_id)` returns the status and `expires_at`. Read-only, and
it must not extend, refresh, or mutate anything — under E7 the PDP does not
write approvals except to create pending ones.

The hook PEP, on `ESCALATE`: poll `GetApproval` until it resolves or the
deadline passes, then either retry `Decide` with the approval id or deny. This
replaces the current honest stub at `cmd/stratium-pep/hook.go`.

**Configuration:** a poll interval and a total escalation timeout, both
required, no defaults — the same rule the PEP already applies to its other
required values. The total timeout is what C22 tests.

**Fail closed on every path**, one test each, reporting the exit code and
reason for all of them: the deadline passes while still pending; the approval
is denied; the PDP becomes unreachable mid-poll; `GetApproval` returns an
unknown id; the retry `Decide` denies anyway. **A timeout must deny, never
retry-forever** — an agent silently blocked is indistinguishable from a hung
tool call, and C22 exists because this is the failure an operator will hit
first.

**Never log the approval id to a file.** It names a live authorization grant;
the same reasoning that keeps `raw_input` out of local logs applies.

**Then unskip `TestC21_EscalationRoutesToRootPrincipal` and
`TestC22_EscalationTimeoutDenies`** and make them pass. Report the conformance
tally: it should move from 14 pass / 11 skip to **16 pass / 9 skip**, still 25
executed. Report it either way; a number that moves differently is a finding.

---

## Task 5 — The non-blocking mapping, and end to end

**Files:** the integration suite, and `services/internal/pdpgrpc/`.

**C23 — assess before implementing.** It says a non-blocking surface returns
deny plus a pending record. The only non-blocking surface is `extauthz`, which
does not exist. **Read what C23 actually asserts.** If it genuinely requires
that surface, leave it skipped with a **corrected reason** naming what is still
missing, exactly as C19 was handled — do not force a pass. What this phase can
and should do is ensure the *response* carries what a non-blocking surface
would need to degrade correctly, and test that mapping directly.

**Prove end to end against a live stack:**

1. A delegation with a threshold below its ceiling: an action in the band
   returns `ESCALATE` with an approval id, and the pending row exists with the
   root principal as approver.
2. An action above the ceiling **denies**, with no approval row created —
   deny overrides escalate, and an escalation record for a decision that was
   never escalatable is noise an operator would have to explain.
3. A control-plane `UPDATE` to `approved` (written directly, as E7 requires),
   then a retry with the approval id **allows**, and the audit chain contains
   both the escalation and the approved retry, and `audit.Verify` passes over
   the pair.
4. An approval for one action does **not** authorize a different one — the
   `input_digest` binding, over the wire.
5. A depth-2 chain routes approval to the root principal, not the depth-1
   agent (C21, end to end rather than in a unit test).
6. Cross-tenant: a second tenant cannot read or approve the first tenant's
   approval — `NotFound` via RLS.

**Report the decision latency** for an escalated decision and for an approved
retry, against Phase 1c's ~2.5 ms baseline and Phase 4's four-engine figure. An
escalation writes a row, so it is the first decision path that is not read-only;
if that cost is material, say so.
