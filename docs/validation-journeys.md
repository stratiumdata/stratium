# Validation journeys, and where the model is too tight

Written 2026-08-27, from reading the code at `a7eb4ce`; J1, §4.3, and J10
confirmed against a live stack on 2026-08-28 (see their own sections).

Except where a section records a live result, every claim is either
**[traced]** (followed through the source, with the file and line given, and so
about as strong as reading gets) or **[hypothesis]** (a prediction the journey
exists to confirm or kill).

Its two questions:

1. Which end-to-end journeys have to be exercised before this is in front of
   anyone, and what should each one be expected to break on?
2. Is the authorization model too constraining for ordinary business
   workflows? — §2, and the short answer is *not architecturally, but in three
   specific and fixable places.*

Companion documents: [`concepts.md`](concepts.md) for the model,
[`architecture.md`](architecture.md) for the mechanism.

---

## How to read a journey

Each one is: the flow, what it is expected to expose, the evidence behind that
expectation, and a **pass criterion** — the observable that decides whether the
journey succeeded. A journey with no pass criterion is a demo, not a
validation.

Journeys are grouped by when the problem would find you, not by component.

## The harness

Six of these journeys have executable coverage, in two files:

| File | What it is | Run it with |
|---|---|---|
| `services/internal/authz/journeys_test.go` | The pure half. Pins each journey's *mechanism* in the packages that own it — no database, no stack. Runs in milliseconds. | `cd services && go test ./internal/authz/ -run TestJourney -v` |
| `services/internal/store/journeys_integration_test.go` | The live half. Real HTTP to a real `stratium-pap`, real `CreateDelegation` RPC, real containerized PDP. | `make integration` |

| Journey | Unit | Live |
|---|---|---|
| J1 — caps vs. tools naming no resource | `TestJourney1_FieldlessToolsCanNeverSatisfyAClassificationCap`, `TestJourney1_ACommandFieldToolNowYieldsAResourceIdentity`, `TestJourney1_AFieldedToolHasAPathToAnAllowThatAFieldlessOneDoesNot` | `TestIntegration_Journey1_AClassificationCapDeniesEveryFieldlessToolCall`, `TestIntegration_Journey1_AShellCommandIsLabelledByEveryPathItNames` |
| J2 — denial route-around | `TestJourney2_ADeniedDestructiveCommandHasALowerTierEquivalent` | — |
| J6 — sub-delegation narrowing | `TestJourney6_AChildCannotAddAConstraintItsParentLeftOpen` | — |
| J10 — concurrent decisions | — | `TestIntegration_Journey10_ConcurrentDecideDoesNotDenyOnAnAuditCollision` |
| §4.1 — tier coarseness | `TestJourney41_TheTierLadderCannotDistinguishRoutineFromCatastrophic`, `TestJourney41_PermittingTheRoutineCasePermitsTheCatastrophicOne` | — |
| §4.2 / §4.3 — no downgrade, scope is reachable and binds | `TestJourney42_NoCatalogRowOrOverrideCanLowerAPositiveMatch` | `TestIntegration_Journey43_ResourceConstraintsAreEnforcedAndReachable`, `TestIntegration_Journey43_AScopedDelegationConstrainsEveryPath` |

**Most of these are characterization tests.** They assert behaviour this
document argues is *wrong*, so that the day someone fixes it the test breaks
loudly and the fix and the documentation move in the same commit. Each carries
a `WHEN THIS FAILS` marker naming what to update here. Two are the opposite —
`TestJourney42_...` and the widening case inside `TestJourney6_...` assert
security properties that must never change, and a failure there is a
regression, not good news.

**J10 is a throughput probe and a regression guard**, not a prediction of
failure: the per-tenant advisory lock should keep collisions at zero, and the
test asserts that while logging sustained decisions/sec. Raise
`STRATIUM_IT_JOURNEY_CONCURRENCY` (default 8) to run the real load validation.

The remaining journeys (J3, J4, J5, J7, J8, J9, J11, J12) have no automated
coverage, and mostly should not: J4 is a stopwatch on a human, J8 is a review
exercise, J3 and J5 need a human approver and wall-clock hours, and J7 needs
the stack torn down mid-run. They are checklists, not tests, and pretending
otherwise would produce tests that pass without proving anything.

---

## 1. Tier 1 — would block a launch

### J1. Turn on classification caps for an agent that has shell access

**Flow.** Register an agent, set `PUT /v1/agents/{id}/classification-caps`, start
a session, run a normal working sequence: a `Read`, a `Bash`, a `Grep`, a
`WebFetch`.

**Expected.** Every `Bash`, `WebFetch`, `WebSearch`, and `TodoWrite` call denies.
Not intermittently — always, for as long as any cap is configured. **[traced]**

**Evidence.** `Bash`'s catalog row carries `resource_field NULL`
(`deploy/seed/tool-catalog-claude-code.sql:85`), as do `WebFetch`, `WebSearch`,
and `TodoWrite` on the lines above it. The hook never populates the resource map
itself (`services/cmd/stratium-pep/hook.go:251`) — deliberately, that is the D1
rule. So extraction yields an empty resource map, nothing labels, and a
configured cap against an unlabelled resource is an explicit denial
(`services/pkg/classification/classification.go:149`).

**And no operator action can clear it.** The documented fix for an unlabelled
resource is an empty-prefix catch-all rule. That fix cannot reach this case:
`labelResource` returns at `services/internal/pdpgrpc/label.go:85` when the
extracted id is empty — *before* `classification.Resolve` is called at all — so
no rule is ever consulted and no rule can ever match. This is what makes J1 a
structural incompatibility rather than a misconfiguration, and it is the single
assertion the live test is built around.

**Why it matters more than its "sharp edge" billing.** Each individual rule here
is right: fail-closed on an unevaluable cap is the correct call, and the PEP not
supplying a resource identity is the whole security model. The *product*
consequence is that the flagship feature cannot coexist with the tool agents use
most. Classification caps are, today, only usable for agents whose entire
toolkit is catalogued file-shaped tools.

**Pass criterion.** A tenant with a `nato` cap can complete an ordinary
development session including shell commands. Failing that, the honest scope
statement in §2 has to ship with the feature.

**RESOLVED for shell tools, 2026-08-28.** `Bash` — and any tool catalogued
with a `command_field` — now derives a resource identity from every path its
command names, with the strictest resulting label deciding. Design:
[`superpowers/specs/2026-08-28-shell-resource-identity-design.md`](superpowers/specs/2026-08-28-shell-resource-identity-design.md).
Two things did not change: a command naming **no** path still denies under a
cap, and the five tools declaring neither field (`Glob`, `Grep`, `WebFetch`,
`WebSearch`, `TodoWrite`) still deny. So caps-plus-shell went from impossible
to workable, not to solved.

**The finding as originally confirmed live, 2026-08-28, before the fix.** Against the full stack, with a catch-all rule
in place, a `TOP-SECRET` cap (the ceiling of `nato` — nothing outranks it), a
`PLATFORM_TRUSTED` agent, an unrestricted tool list, and the tool registered at
`READ_ONLY` under a `READ_ONLY` delegation:

```
fieldless tool -> EFFECT_DENY "resource declares no classification; the
delegation's classification cap cannot be evaluated and therefore denies (depth 0)"
fielded tool, identical raw_input, same delegation -> EFFECT_ALLOW
same fieldless call on a fresh delegation with no cap -> EFFECT_ALLOW
```

The cap is the sole cause, and no label rule can satisfy it. J1 is not a
hypothesis any more.

---

### J2. Denial recovery — what the agent does on attempt two

**Flow.** Give an agent a delegation that denies `DESTRUCTIVE`. Ask it to clean a
build directory. Watch three attempts, not one.

**Expected.** `rm -rf node_modules` denies at tier 4. So does
`find . -name node_modules -delete`. A capable agent then tries an interpreter
one-liner such as `perl -e 'use File::Path; remove_tree(q(node_modules))'`, which
rates **INTERNAL_MODIFY** and is allowed under a tier-2 ceiling. **[traced]**

**Evidence.** `reDestructive` (`services/internal/authz/tier.go`) matches `rm`
with a recursive or force flag and `find ... -delete` anywhere in the input, so
the first two forms are tier 4 regardless of target. The third matches nothing in
`reDestructive` or `reExternal`, and it is not on the read-only allowlist
(`isReadOnlyCommand`), so it falls to the classifier's default for a command it
does not recognise: INTERNAL_MODIFY.

**What changed.** `find ... -delete` used to rate READ_ONLY, because READ_ONLY
was decided by a command's first word. READ_ONLY is now an allowlist of plain
commands checked argument by argument, so the route-around no longer reaches an
agent held to tier 1. It still reaches one allowed to modify.

**The general shape.** The adversary in the agent era is not usually malicious —
it is goal-directed and inventive, and it will do gradient descent on the
controls for free, at no cost and with no intent to evade. Classifier coverage
matters much less than what happens on the second attempt. `tier.go`'s own
RESIDUAL RISK note already concedes the classifier is a heuristic; this journey
measures how much that concession costs in practice.

**Pass criterion.** Measure the *route-around rate*: of N denials, how many the
agent successfully circumvents within three attempts using a differently-worded
equivalent. That number, not the classifier's pattern count, is the control's
real efficacy. Anything above single digits means the tier ceiling — not the
classifier — is doing all the work, which is fine, but should be known and said.

---

### J3. Escalation, end to end, with a human who is not at their desk

**Flow.** Configure `escalate_at` below `max_action_tier`. Trigger it on the
`hook` surface. Have the approver respond at 30 seconds, at 30 minutes, and not
at all.

**Expected.** `hook` and `mcp` block while waiting; the other two surfaces
degrade to a denial naming the approval id. **[traced, architecture.md §10]**
Everything else about the experience — the agent's own timeout, what it does with
a blocked call, whether it abandons the task, what happens once `ApprovalTTL`
lapses — is unvalidated. **[hypothesis]**

**Why it is Tier 1.** Escalation is the *only* pressure valve for a
misclassified routine action (§2.2). If the escalation experience is bad, every
operator's fix is to widen the delegation instead — which the code comments
themselves name as trading "a loud annoyance for a quiet weakening"
(`tier.go:94`). The usability of this journey directly sets how much real
enforcement survives contact with a deadline.

**Pass criterion.** An approver-absent escalation degrades to something an agent
and its user both understand, within a bounded time, without the operator
concluding that a wider delegation is the practical answer.

---

### J4. Day-0 operator onboarding, stopwatch running

**Flow.** Fresh stack, no SQL access. Register agent → write policy → seed the
tool catalog → add label rules → `session-start` → one successful `Read`.

**Expected.** Reachable without SQL — there is already a test asserting the
classification path is (`services/internal/store/pap_e2e_integration_test.go`),
which is a genuinely good sign. **[traced]** The open question is cost: how long,
and how many concepts must be held simultaneously before anything at all works.
**[hypothesis]**

**Why it is Tier 1.** Every tool call is denied until a session exists and a
policy permits it, so "installed, and everything is denied" is the default first
experience of the product. That is correct behaviour and a brutal first
impression; the two facts are unrelated and both true.

**Pass criterion.** An operator who has not read `architecture.md` reaches one
allowed tool call in under 30 minutes, and can explain why the call before it was
denied.

---

## 2. Tier 2 — surfaces in week one

### J5. Long-running and unattended sessions

Token expiry mid-session, delegation TTL lapsing at hour 9 of an 8-hour job, and
who re-runs `session-start` for an overnight CI agent with no human present.
Note the interaction with J3: an unattended run that escalates has nobody to
approve it. **[hypothesis]**

**Pass criterion.** A 12-hour unattended run either completes or fails in a way
that names the credential that expired.

---

### J6. Sub-agent delegation with a real multi-agent topology

An orchestrator spawning workers meets `ScopeNarrows`' rule that a child may not
introduce a dimension its parent left open
(`services/pkg/models/delegation.go:146` for caps, `:193` for resource
constraints). The natural pattern — hand a worker a *tighter* scope than the root
delegation bothered to specify — is rejected outright. **[traced]**

The rule is deliberate and well-argued (a child's shape stays derivable from its
parent's, which makes chain review tractable). It is also exactly backwards from
how defence-in-depth is usually practised, where a narrower sub-scope is a virtue
you can add at any layer.

**Pass criterion.** Your actual orchestration topology can be expressed. If it
cannot, the decision is whether to relax the rule for constraint-introduction
specifically, or to require roots to enumerate every dimension up front.

---

### J7. PDP outage

`mcp` degrades to its in-memory decision cache inside the staleness window.
`hook` has no cache and denies immediately. `extauthz` and `proxy` have **no**
fallback, by design — a cache hit is a decision made without the only component
that verifies signatures, and on those surfaces the caller is the party being
policed. **[traced, architecture.md §11]**

The consequence to validate is a business one, not a technical one: a PDP outage
is a total outage of any API fronted by Envoy.

**Pass criterion.** The business owner of the fronted API has seen that
statement and accepted it, and the PDP's availability target is set to match.

---

### J8. Incident forensics

Something goes wrong; you open the audit chain. It will tell you which agent,
under which delegation, at which depth, was allowed which tool at which tier. It
will not tell you what the command was — raw inputs are never stored, only
`InputDigest`. **[traced, architecture.md §14]**

The reasoning is sound (raw shell commands in an undeletable table, before
per-tenant key management exists, is a worse problem than not having them). The
question is whether it satisfies the compliance requirement that is presumably
driving adoption in the first place.

**Pass criterion.** Walk a real incident review using only what the chain
records. If the reviewer's first question cannot be answered, per-tenant
encrypted input storage moves onto the roadmap ahead of it being asked for in a
procurement questionnaire.

---

### J9. The network-surface integration journey

`extauthz` and `proxy` are a different product experience from the hook: the
caller re-authenticates on every call, `proxy` requires sender-constrained
tokens, and escalation degrades to a denial carrying an approval id — so the
**client application** has to implement the approval-and-retry loop itself.
**[traced, architecture.md §10, §12]**

**Pass criterion.** That loop exists as shipped SDK code with an owner, or the
surfaces are documented as not supporting escalation.

---

## 3. Tier 3 — scale and operations

### J10. Concurrent decision throughput, per tenant

**Flow.** N agents deciding simultaneously against one tenant. Raise N.

**Expected.** Every decision serializes behind a per-tenant advisory lock, so
one tenant's decision throughput is bounded by audit-write latency. Denials
under concurrency are *already mitigated* and should not occur. **[traced]**

**Evidence, and a correction.** The naive reading of this path is alarming and
wrong. `appendAuditTx` takes `pg_advisory_xact_lock(hashtext(tenant_id))`
before reading the chain tail (`services/internal/store/audit.go:199`), held
for the transaction and released on commit, rollback, *or* process death — so
two writers cannot both link to the same tail. That lock was added after this
exact failure was measured at "30-70% denials for a single tenant under ten
concurrent decisions," and its own comment records the number.

The residual path still exists and is defensive: `audit.go:238` raises
`ErrConcurrentAppend` on a unique violation, `server.go:786` maps it to
`Aborted`, and nothing retries — the blind reissue fires only on an
`EFFECT_DENY` *response*, never a transport error. Under the lock it should be
unreachable. A collision observed today means either the lock was bypassed by a
new append path, or it was removed.

**So the finding is throughput, not denials.** Every `Decide` for a tenant
queues behind one lock and one audit write. That is a deliberate trade, and
`audit.go:197` names the escape hatch: *"If that ceiling ever binds, the answer
is batching appends behind the lock, not removing it."*

**Pass criterion.** Measure sustained decisions/sec for a single tenant and
confirm it clears the fleet's expected peak with margin. Zero collisions is the
secondary assertion, and a regression guard on the lock rather than a
prediction of failure.

**First measurement, 2026-08-28:** 8 concurrent decisions, 24ms wall clock, 0
collisions — **334 decisions/sec** for one tenant. Treat that as a floor, not a
ceiling: 8-way concurrency does not saturate the advisory lock, so this
establishes only that contention does not fail at that level. Finding where the
curve bends needs `STRATIUM_IT_JOURNEY_CONCURRENCY` set well higher, which is
the load validation this journey is actually asking for.

---

### J11. The cost of a denial

Every denial is two round trips and two audit rows, because both `hook` and `mcp`
attempt exactly one blind token reissue rather than trying to distinguish an
expired token from a policy denial. **[traced, architecture.md §9]** A noisy
agent therefore doubles its own load on precisely the path that J10 shows is the
bottleneck.

**Pass criterion.** Denial rate under a realistic workload is low enough that the
2× multiplier is not the dominant load term.

---

### J12. Operational lifecycle

Signing key rotation through the current/previous key pair; five-minute operator
tokens; one PDP process per tenant as tenant count grows. **[hypothesis]**

**Pass criterion.** A key rotation is performed with no decision downtime, and
the per-tenant process model has a stated ceiling.

---

## 4. Is the model too constraining for normal business workflows?

**Architecturally, no.** `allow = principal ∧ agent ∧ delegation` constrains
nothing by itself — the ceiling goes wherever an operator puts it. The
conjunction is the right shape and the fail-closed defaults are the right
defaults.

**In its current granularity and defaults, yes**, in three specific places. All
three are fixable, and none of them require revisiting the architecture.

### 4.1 The tier ladder is too coarse to express an ordinary permission

`rm -rf node_modules` and `rm -rf /` are both `DESTRUCTIVE`, both requiring a
`PLATFORM_TRUSTED` agent and a tier-4 delegation. Granting the routine case
grants the catastrophic one, in the same act. **[traced — `tier.go:81` matches
`rm -[a-z]*[rf]` with no notion of target; `agent.go:33` requires
`PLATFORM_TRUSTED` for tier 4.]**

One tier down, the same shape: `curl http://localhost:3000/health` is
`EXTERNAL_COMMS` (`tier.go:105`), so a local health check demands the same trust
tier as `aws s3 rm`. A build that runs `git push` needs `CERTIFIED`.

Real permissions are conditional on *what is touched*. The tier axis has no way
to say that.

### 4.2 A false positive has no downgrade path

Tier overrides are raise-only, enforced at write time in the PAP and again at
read time during the decision. Above them sits the evidence rule: a positive
destructive-or-external match on raw input is never lowered by any name-keyed
lookup. **[traced, architecture.md §6]**

Both rules are correct — without them, a hostile PEP picks a benign tool name and
chooses its own tier, which is D1 by another route. But together they mean a
misclassified routine command has exactly two remedies:

1. **Raise the ceiling** — which weakens every other action at that tier, for
   that agent, for the life of the delegation.
2. **Escalate it** — a human approval, every single occurrence, forever.

There is no third option, and `tier.go:94` already names the resulting dynamic in
its own comment: operators get pressured into widening delegations to get work
done, "which trades a loud annoyance for a quiet weakening."

### 4.3 The dimension that would fix this is now reachable

**RESOLVED, 2026-08-28.** `resource_constraints` is enforced on every hop of
every chain (`services/internal/authz/delegation.go:102`,
`checkResourceConstraints`), and now has a write path:
`PUT /v1/agents/{id}/resource-constraints` (RoleAdmin) sets the one key with
real semantics, `id_prefix` — a prefix every resource identity the call
resolves to must fall inside, enforced by `strings.HasPrefix` against
write-time-validated values (`services/internal/store/agent_constraints.go`).
`CreateDelegation` copies the agent's current scope onto every root
delegation at issuance (`services/internal/pdpgrpc/delegation.go:187`), the
same way it copies classification caps, and `GET /v1/delegations` reads it
straight back.
**[traced, live: `TestIntegration_Journey43_ResourceConstraintsAreEnforcedAndReachable`]**

And it binds against a shell command's derived identities, not only a
fielded tool's single id: `id_prefix` requires **every** identity a call
resolves to be inside the prefix, the same strictest-member argument J1's
shell fix makes for classification labels — a benign path prepended to an
out-of-scope one cannot buy scope for the command as a whole, because the
out-of-scope member still fails on its own.
**[live: `TestIntegration_Journey43_AScopedDelegationConstrainsEveryPath`]**
That test also surfaced and
closed a defect in the shell-identity plumbing this task's own fix had
introduced (2026-08-28): the PDP's resource-identity list carried an empty
entry for every command-field-only call, which made `id_prefix` deny every
shell call under a configured scope regardless of what paths the command
actually named. `services/internal/pdpgrpc/server.go` now omits that entry
when the field is empty, matching `labelResource`'s own treatment of it.

Two things did not change, and are the honest edges of this fix:

- **A command naming no path still denies**, for the identical reason a
  fieldless call still denies under a classification cap — nothing to check,
  and unevaluable must not read as satisfied.
- **The five tools declaring no resource field at all** (`Glob`, `Grep`,
  `WebFetch`, `WebSearch`, `TodoWrite`) still deny under any configured scope,
  the same way they still deny under any configured cap (J1, §1).

### 4.4 The one-sentence version

> Strictness is aimed at **how dangerous an action is**. Business workflows vary
> by **what the action touches**. Since 2026-08-28 the API can express that
> second dimension too.

"This agent may do destructive things, but only under `/workspace`" is now a
sentence an operator can write and have enforced: `PUT
/v1/agents/{id}/resource-constraints` sets it, it is copied onto every root
delegation, and it binds against every identity a call — fielded or shell —
resolves to. What it still cannot do is what §4.1 and §4.2 already named: say
*how dangerous* the action within that scope may be any more precisely than
the tier ladder allows, or rescue a tool (or a pathless command) that names no
resource at all.

---

## 5. Changes that move it from "too strict" to "strict in the right places"

| # | Change | Unlocks |
|---|---|---|
| 1 | ~~**Give `Bash` a resource identity**~~ — **done 2026-08-28.** Every path the command names is extracted; the strictest label decides | Caps for the tool that matters most, and — now that #2 has landed too — resource-constraint scope for it as well (§4.3) |
| 2 | ~~**Add a write path for `resource_constraints`**~~ — **done 2026-08-28.** `PUT /v1/agents/{id}/resource-constraints`, copied onto every root delegation at issuance | Scope-conditional permissions — the §4.4 sentence is now writable |
| 3 | **Ship a documented default posture** — trust tier 3, `escalate_at: 4`, a real tool allowlist | A new tenant's first hour is not "everything denies" (J4) |
| 4 | ~~**Make attenuation fail closed on new dimensions**~~ — **done 2026-09-16.** `ScopeNarrows` moved into `pkg/permset`; a `models.Delegation` field that is classified as neither a dimension nor an explicit exclusion now fails the build | A field added to a delegation can no longer leave children silently unconstrained on it |
| 5 | ~~**Make a change's blast radius answerable**~~ — **done 2026-09-16.** `POST /v1/containment` answers "does this candidate allow anything the baseline forbids"; agent-grant writes record a `containment` audit entry when they widen | Config review stops being a point query someone has to think of |
| 6 | ~~**Make a principal's *combined* reach visible**~~ — **done 2026-09-16.** `GET /v1/principals/{id}/effective` unions a principal's live root delegations | The sibling gap §7 of `concepts.md` describes can at least be seen; enforcing against it still needs a principal ceiling |

One more, unnumbered because it is conditional: batch audit appends behind the
existing per-tenant lock, and only if J10's measurement says the ceiling binds.
Not a retry, and not removing the lock — `audit.go:197` already rules both out.

Note that #1 needs designing carefully rather than just implementing. Extracting
a path from a shell command is *interpretation of a value*, which is exactly the
line `extract.go`'s package doc forbids that file from crossing — it may look up
which field holds a value, never inspect what a value means. The extraction
therefore belongs on the classification side of the boundary, next to
`BuiltinTier`, not in `extract.go`. That constraint is a feature: it keeps the
new logic server-side, where a hostile PEP cannot reach it.

---

## 6. Honest scope statement, now that #1, #2 and #4-#6 have landed

Stronger and narrower than the current docs imply:

> Stratium is strong for **tool-scoped, tier-scoped, and — since 2026-08-28 —
> resource-scoped** authorization over agents touching money, production
> infrastructure, or customer data — where escalation friction is acceptable.
>
> It fits a general-purpose coding agent under classification caps and under
> an `id_prefix` scope alike, with the same two limits worth stating up front
> for both: a shell command naming no path (`npm test`) still denies, and five
> tools declaring no resource field at all (`Glob`, `Grep`, `WebFetch`,
> `WebSearch`, `TodoWrite`) still deny. Neither mechanism can rescue a call
> that names no resource to check.
>
> The remaining structural limit is §4.1: routine destructive operations
> cannot be permitted without also permitting catastrophic ones, because the
> tier ladder itself has no notion of scope — a `DESTRUCTIVE` delegation is
> `DESTRUCTIVE` everywhere the scope allows it, not just where the operator
> meant.

Both halves are true, and saying the second one first is what makes the first
one credible.
