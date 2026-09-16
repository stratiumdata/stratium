# Design — permission-set containment

Gives Stratium one way to answer *"is this set of permissions contained in that
one?"*, and points the four places that need that answer at it. Closes the
gaps recorded as 1, 5, 6 and 8 in the 2026-09-15 gap review: no universal
queries, hand-written attenuation that fails open on new dimensions, no
reasoning about a *group* of agents, and an unguarded trust table.

Status: design. Decisions taken 2026-09-15 (lattice algebra with an SMT seam;
blocking for delegations, advisory for config).
Prior art and motivation:
[NVIDIA OpenShell, *What We Have Learned Applying Formal Methods to Control AI
Agents*](https://nvidia.github.io/OpenShell-Research/dev-notes/posts/2026-09-10-learning-formal-methods-agent-policy-prover/),
and AWS Zelkova before it.

---

## The problem

Every question Stratium can ask today is a **point query**.

| Mechanism | Question it answers |
|---|---|
| `POST /v1/policies/test` | what happens for *this one* sample input |
| `policy.Probe` (`internal/policy/probe.go:37`) | may this principal hold this tier/tool — with an empty resource |
| `models.ScopeNarrows` (`pkg/models/delegation.go:107`) | is this child delegation shaped like a subset of its parent |

Nothing answers the universal question: *does this change permit anything it
did not permit before?* `Probe`'s own doc comment concedes the shape of the
gap — "a resourceless probe under-granting resource-conditional policies is
accepted, not a gap to fill in."

That absence shows up as four separate defects, which are the same defect:

1. **No config-change review.** An operator editing a policy, a catalog row, an
   override, or a label rule has no way to learn what the edit widened. The
   only feedback is a point query they have to think of themselves.
2. **`ScopeNarrows` fails open on new dimensions.** It is a sequence of
   hand-written `if` blocks, one per dimension. Add a field to
   `models.Delegation` and nothing fails — children are simply unconstrained on
   it until someone remembers to write a loop. Compare the raise-only override
   rule, which is enforced at three independent layers precisely because
   forgetting it once would be silent.
3. **No horizontal reasoning.** The delegation leg enforces child ≤ parent at
   every hop, exhaustively. Nothing compares *siblings*. Two live root
   delegations under one principal — one reaching `/secret`, one reaching
   `EXTERNAL_COMMS` — are never considered together, and their union is bounded
   by nothing.
4. **`TrustTable` has no raise-only guard.** `internal/authz/agent.go:12-19`
   states it plainly: "there is no `ValidateTrustTable` or equivalent, so
   nothing today stops a tenant-supplied table from requiring LESS trust than
   `DefaultTrustTable`." Only `DefaultTrustTable()` is wired today
   (`internal/pdpgrpc/server.go:587`), so the hazard is latent — but the type is
   already per-tenant data, and the day a load path lands the floor becomes
   silently lowerable.

---

## What makes this more than extracting a helper

The tempting reading is that `ScopeNarrows` is a long function that wants
factoring. It is not. Two of its rules are **not lattice containment**, and
turning them into containment would be a security change wearing a refactor's
clothes:

- **`EscalateAt` presence must match.** A child may not introduce the field
  where the parent leaves it unset, *and* may not drop it where the parent sets
  it. Dropping is obviously a widening. Introducing genuinely narrows — and is
  rejected anyway, so that a child's shape is derivable from its parent's fixed
  set of dimensions rather than from which hop first introduced one.
- **`ResourceConstraints` may not be introduced either**, by the same rule and
  for the same reason, even though adding a constraint narrows.

Both are stricter than pointwise ordering requires. Both are deliberate (spec
§4.3.1). A clean lattice would quietly permit what they forbid.

So the binding constraint on this work is:

> **`Contains` must reproduce `ScopeNarrows` bit for bit, including the parts
> that are not orderings.** The existing `ScopeNarrows` tests are the
> acceptance criteria and must pass unmodified.

Extract, do not redesign. The value of this change is the *registry and its
completeness test*, not a tidier comparison.

---

## Decisions

1. **A lattice algebra, not a solver.** Stratium's permission set is today a
   product of independently ordered dimensions, so containment is pointwise
   comparison — which is exactly what `ScopeNarrows` already computes by hand.
   Z3 earns its keep when dimensions stop being independent (a per-scope tier,
   a network glob); none exists yet. No new dependency, no CGO, no `z3` binary
   on build and PAP hosts.
2. **`Contains` is exact; `Union` may over-approximate upward.** `Contains`
   blocks a write and must be precise in both directions. `Union` only ever
   feeds an advisory report, so widening it is safe: an over-approximated union
   flags more often, never less.
3. **Blocking for delegations, advisory for config.** `ScopeNarrows` stays
   blocking, unchanged in behaviour. Config writes get a recorded verdict and
   land regardless. This is the Zelkova posture, and it sidesteps the
   bootstrapping problem — the first policy in a tenant has no baseline to be
   contained in.
4. **The baseline is the live config, not a snapshot.** Stratium keeps no
   configuration history and this design does not add any. "Does this write
   widen what is deployed right now" is the question operators actually have,
   and it needs no new tables.
5. **Agent trust tier is out of scope of `Set`.** It belongs to the agent leg,
   not the delegation leg. Folding it in would conflate two conjuncts that the
   architecture deliberately keeps separate.
6. **Gap 8 gets a guard, not a feature.** `ValidateTrustTable` with no caller
   would be scaffolding for a load path nobody has asked for. A test pinning
   the single construction site is the whole change.

---

## Surface

One new package, `services/pkg/permset`. It must be under `pkg/`, not
`internal/`: `pkg/models` is its first consumer, and `pkg/models` already
imports `pkg/classification` for the same reason.

```go
// Set is a permission grant, reduced to the dimensions that bound what a
// holder may do. It is the common denominator of four shapes that are
// unrelated types today: a delegation's grant, an agent's registered grant,
// a principal's optional ceiling, and a computed union.
type Set struct {
    Tools               []string           // empty means unrestricted
    MaxTier             models.ActionTier
    EscalateAt          *models.ActionTier
    ClassificationCaps  map[string]string  // hierarchy -> level
    ResourceConstraints map[string]string  // id_prefix, today
    ExpiresAt           time.Time
}

// Contains reports whether inner is a valid subset of outer, returning the
// empty string when it is and a reason naming the first violated dimension
// when it is not. The empty-means-valid convention matches ScopeNarrows,
// whose contract this reproduces exactly.
func Contains(outer, inner Set) string

// Union returns the weakest Set that contains every input: the permissions a
// holder of all of them would jointly have. It over-approximates upward
// where a dimension cannot represent a join exactly, and names each such
// widening in the returned reasons.
func Union(sets ...Set) (Set, []string)
```

---

## The dimension registry, and the test that closes gap 5

Containment is driven by an explicit table — one entry per dimension, naming
its containment rule and its union rule. Alongside it sits a second table of
`models.Delegation` fields that are deliberately **not** dimensions, each
carrying its reason.

```go
var notDimensions = map[string]string{
    "ID":       "identity",
    "TenantID": "identity; the tenant boundary is RLS",
    "UserID":   "identity",
    // Not "identity": a child delegating to a DIFFERENT agent is the whole
    // point of a chain. The agent leg bounds each one independently.
    "AgentID":  "acting agent; bounded by AgentLeg, not by containment",
    "Purpose":  "human-readable, carries no authority",
    "CreatedAt": "metadata",

    // Authorization-bearing, but enforced per hop at decision time rather
    // than by containment. DelegationLeg walks every hop and denies on each
    // of these independently, so a containment rule would be a second,
    // divergent implementation of a check that already holds.
    "Revoked":   "enforced per hop: authz/delegation.go",
    "RevokedAt": "enforced per hop: authz/delegation.go",
    "Depth":     "bounded per request by maxDepth",
    "ChainAgentIDs": "enforced per hop",

    "ParentDelegationID": "chain structure",
    "RootDelegationID":   "chain structure",
}
```

Then the test that is the point of this whole section:

> `TestEveryDelegationFieldIsClassified` reflects over `models.Delegation`'s
> fields. Every field must appear in the dimension registry **or** in
> `notDimensions`. A field in neither fails the build.

That is the entirety of gap 5. It converts "someone remembered to add an `if`"
into "the compiler asked a question." It is the same species as
`cmd/stratium-pap/ui_test.go` — a test whose only job is to detect that a step
was skipped, and which is worthless the moment it is made to pass by
weakening it.

**The reasons are load-bearing.** A bare exclusion list degrades into a place
to silence the test. Requiring a sentence per entry makes the wrong answer
visible in review, because "enforced per hop" is falsifiable and "not
relevant" is not.

---

## Containment rules, carried over verbatim

| Dimension | Rule (unchanged from `ScopeNarrows`) |
|---|---|
| `MaxTier` | child ≤ parent |
| `EscalateAt` | presence must match exactly; then child ≤ parent (**lower is narrower**) |
| `Tools` | empty parent is unrestricted; empty child under a restricted parent is a **widening**; otherwise subset |
| `ClassificationCaps` | iterate the **parent's** hierarchies: child must cap each one, at a level ≤ parent's. Child may not introduce a hierarchy. Unknown level either side is an error, not a pass. |
| `ResourceConstraints` | every parent key must appear in the child. `id_prefix` narrows by `strings.HasPrefix` — sound only because a stored prefix always ends in `/`, validated at write time. Other keys compare exactly. Child may not introduce a key. |
| `ExpiresAt` | child ≤ parent |

Each row's reason string is preserved verbatim too. `store.CreateDelegation`
wraps them into an error an operator reads; changing the wording changes an
operator-facing message for no gain.

---

## Union rules, and the one honest imprecision

| Dimension | Join |
|---|---|
| `MaxTier` | max |
| `EscalateAt` | the weakest: highest value, and `nil` (never escalates) absorbs |
| `Tools` | union; unrestricted absorbs |
| `ClassificationCaps` | highest level per hierarchy; a hierarchy capped by only one side becomes **uncapped** |
| `ExpiresAt` | latest |
| `ResourceConstraints` | exact where values agree; **unconstrained where they differ**, with a reason |

The last row is the imprecision, and it is deliberate. The union of
`id_prefix=/workspace/` and `id_prefix=/tmp/` is not a prefix, and `Set` holds
one string. Rather than introduce a prefix-set type for a report nobody has
read yet, the union widens to unconstrained and says so.

This is safe **only** because of decision 2: `Union` feeds an advisory report,
so over-approximating makes it noisier, never blinder. It carries a
`ponytail:` comment naming the ceiling and the upgrade path — a prefix set,
if and when the noise is real. Any future use of `Union` in a blocking path
must revisit this row first.

---

## Consumers

### `ScopeNarrows` — gap 5

**It moves to `pkg/permset` rather than adapting in place.** `permset` must
import `pkg/models` for `ActionTier`, so `pkg/models` cannot import `permset`
back — Go rejects the cycle. Keeping the adapter in `models` and giving
`permset` bare `int` tiers was the alternative, and it was rejected: the
reason strings are operator-facing and name tiers by symbol
(`EXTERNAL_COMMS`, not `3`), and preserving them verbatim is a hard
requirement of this design.

So: `permset.ScopeNarrows(parent, child *models.Delegation) string`, same
name, same contract, same reason strings. Every call site changes only its
package qualifier — one production site (`internal/store/delegation.go:120`)
and seven in tests. Still blocking, still called inside
`CreateDelegation`'s transaction.

Its existing tests move with it, **contents unmodified** — the file changes
package and the two fixtures gain a `models.` qualifier; not one assertion
changes. That is the regression suite for the extraction.

### `POST /v1/containment` and config-write verdicts — gap 1

A new endpoint (`RoleEditor`) takes a baseline and a candidate and returns
contained / not-contained plus a reason. Callers pass either two explicit sets
or a reference to a live object. `RoleEditor`, not `RoleViewer`, even though it
writes nothing: this codebase gates every POST route at `RoleEditor`
regardless of whether the handler persists anything, and `POST
/v1/policies/test` — the point-query counterpart to this universal one — is
gated the same way for the same reason.

Separately, writes that change an **agent's grant** record a containment
verdict against the pre-write value: `PUT /v1/agents/{id}`,
`PUT /v1/agents/{id}/classification-caps`, and
`PUT /v1/agents/{id}/resource-constraints`. The write lands either way
(decision 3); the verdict is recorded and surfaced.

**Only two of the six epoch-bumping tables carry a `Set`.** `agents` and
`delegations` hold grants. The other four — `policies`, `tool_catalog`,
`tier_overrides`, `resource_label_rules` — change the **classification
function**: what tier an action derives, what label a resource resolves to.
"Did this widen the permission set" is not a question that typechecks against
them; the question they need is "did this lower a derived tier or a resolved
label for any input," which is a different engine over a different domain.

That is not a gap this design leaves open by accident, and two of the four
already have guards: `tier_overrides` is raise-only, enforced three ways
(`architecture.md` §6), and `resource_label_rules` refuses to drop a tenant's
catch-all. `tool_catalog` and `policies` genuinely have none, and belong to
the classification-function work, not here.

The agent grant is where widening is currently both **unchecked and
invisible**: those three endpoints set the template copied onto every root
delegation issued afterwards (`internal/pdpgrpc/delegation.go:187`), and
nothing today compares the new template to the old one.

### `GET /v1/principals/{id}/effective` — gap 6

Returns `permset.Union` over the principal's **live** root delegations —
expiry and revocation filter the input set rather than joining into it.

**This design ships the report only.** There is no principal ceiling to check
it against, and this design does not add one: a ceiling is a new configurable
concept with its own storage, write path, and RLS story, and it should not be
designed as a footnote to an engine.

That is the half of gap 6 that matters first, because today the union is not
merely unchecked — it is *invisible*. The endpoint makes it visible, reuses
`Set` unchanged, and leaves a ceiling to a follow-up that can compare against
it with one call to `Contains`.

### `TrustTable` — gap 8

`TestDefaultTrustTableIsTheOnlyConstructionSite` asserts that
`internal/pdpgrpc/server.go:587` is the sole place a `TrustTable` is built.
A tenant-supplied load path then cannot land without editing the test, and the
test names the raise-only note in `agent.go:12-19` that the editor needs to
have read.

No `ValidateTrustTable`. It would have no caller.

---

## Where verdicts go

`audit_chain` already carries an `event_type` column and a hash chain with
tail rederivation (`internal/store/audit.go:13-27`). Containment verdicts
become event type `containment`, alongside the existing `decision`,
`delegation_created`, `policy_created` and the rest.

No new storage. And the artifact a regulated deployment actually wants — a
record of what a configuration change was proven *not* to permit — lands in
the one log the system can already prove was not edited afterwards.

---

## The SMT seam, stated so it is not oversold

`Contains` and `Union` are the interface an SMT backend would implement
second. This design does **not** build one, does **not** add a dependency, and
does **not** claim the seam is free.

What it claims is narrower: when a dimension arrives that is not independently
ordered — a per-scope tier ceiling (`validation-journeys.md` §4.1), or the
network globs of the action-description work — the lattice implementation will
fail to express it as a registry entry, and that failure will be a compile
error in a table, not a subtle wrong answer in a comparison. Finding out from
the type system is the only benefit being claimed here.

Note for whoever reaches that point: `github.com/yashtewari/glob-intersection`
is already in the module graph, pulled in indirectly by OPA. Glob overlap is
the genuinely hard piece of network containment, and it may already be paid
for.

---

## Testing

| Test | Status |
|---|---|
| Every existing `ScopeNarrows` test | must pass **unmodified** — this is the acceptance criterion for the extraction |
| `TestEveryDelegationFieldIsClassified` | new; fails the build on an unclassified field |
| `TestDefaultTrustTableIsTheOnlyConstructionSite` | new; gap 8 |

New properties this change needs:

- **The extraction is behaviour-preserving**, as a property rather than by
  inspection: a table of parent/child pairs covering every dimension and every
  rejection reason, asserted identical between the old and new implementations
  before the old one is deleted.
- **`EscalateAt` presence asymmetry survives**: introducing is rejected,
  dropping is rejected, lowering is accepted. Named as its own test, because
  it is the rule most likely to be "fixed" by a future reader.
- **An empty child tool list under a restricted parent is a widening**, not an
  inheritance.
- **A hierarchy the parent caps and the child omits is a widening.**
- **`id_prefix` sideways movement is rejected**: parent `/workspace/`, child
  `/workspace-evil/` denies. This is the trailing-slash argument, and it
  deserves a test that says so.
- **Union over-approximation is loud**: differing prefixes union to
  unconstrained *and* the reason list says which two disagreed. A silent
  widening here would be the worst outcome in the design.
- **Union absorbs correctly**: one unrestricted tool list makes the union
  unrestricted; one `nil` `EscalateAt` makes the union never-escalate.
- **A revoked or expired sibling contributes nothing** to
  `GET /v1/principals/{id}/effective`.

---

## Out of scope

- **The network dimension** (`host`, `port`, `scheme`, `method`, `layer`), the
  split tool identity between `extauthz` and `hook`, and the classifier's
  INTERNAL_MODIFY default. That is the action-description work, and it is the
  first real test of this registry.
- **Offline tolerance / proof-carrying delegation.** It depends on this engine
  being able to establish a universal allow, which is a query this design does
  not yet expose.
- **Any change to `tier.go`.** The classifier is a heuristic by design and its
  RESIDUAL RISK note stands. This engine works above it, on derived tiers,
  never on command text.
- **Any change to Cedar, Rego, XACML or JSON evaluation.** The policy
  languages are not a product lattice and stay outside the engine. The engine
  bounds what a policy is conjoined *with* — which is where the real ceiling
  already lives, per `allow = principal ∧ agent ∧ delegation`.
- **Configuration history.** Decision 4.
- **Containment over the classification function.** `policies`,
  `tool_catalog`, `tier_overrides` and `resource_label_rules` change what an
  action derives, not what a grant permits. See the consumer section above.
- **A principal ceiling.** `GET /v1/principals/{id}/effective` reports the
  union; nothing enforces it. Adding a ceiling is a follow-up whose entire
  implementation is one `Contains` call against a value this design already
  produces.
- **(2026-09-15) A read path for the containment verdict.** Verdicts are
  written to the audit chain and have no reader: no read endpoint, no console
  screen. Direct SQL is the only way to see one today. Remaining work before
  this design is complete: either an audit read endpoint filtered to
  `event_type=containment`, or a console screen over it. Not done in this fix
  wave — see the Risks section below.

---

## Risks

- **A behaviour-preserving extraction that is not.** This is the risk to review
  hardest. `ScopeNarrows` is enforced inside `store.CreateDelegation`'s
  transaction and is the only thing standing between a child delegation and
  its parent's ceiling; a subtle difference in the extracted version is a
  silent widening at the most load-bearing check in the system. Mitigated by
  keeping the existing tests unmodified and by the differential table above —
  but the mitigation is only as good as the coverage of the old tests, which
  should be measured before the old implementation is deleted, not after.
- **The completeness test can be satisfied by lying.** A future reader who
  adds a field and writes `"not relevant"` in `notDimensions` has passed the
  test and reopened gap 5. Requiring a falsifiable reason makes this visible in
  review; nothing makes it impossible.
- **An advisory verdict nobody reads is theatre.** Decision 3 trades safety for
  adoptability. If containment warnings accumulate unread in the audit chain,
  this feature has cost effort and bought nothing. As of this fix wave, that
  risk is not mitigated: the verdict is recorded but not yet surfaced. There is
  no audit read endpoint and no console screen, and direct SQL is the only way
  to see one. Until a read path exists, this design is partially delivered.
- **`Union`'s imprecision escaping into a blocking path.** The over-approximation
  in decision 2 is sound only for advisory use. The `ponytail:` comment says
  so; a reviewer should treat any new blocking caller of `Union` as a design
  change.

---

## References

- `services/pkg/models/delegation.go:107` — `ScopeNarrows`, the implementation being moved and extracted
- `services/pkg/models/delegation_test.go` — its regression suite, which moves with it
- `services/internal/authz/delegation.go` — `DelegationLeg`, which enforces per hop what containment enforces per issuance
- `services/internal/authz/agent.go:12-19` — the `TrustTable` raise-only note and its TODO
- `services/internal/policy/probe.go:37` — the existing point query and its stated limits
- `services/internal/store/audit.go` — the chain the verdicts join
- `services/migrations/000015_tenant_epoch_trigger.up.sql` — the six tables that define this design's scope
- [`docs/validation-journeys.md`](../../validation-journeys.md) §4.1 — the per-scope tier ceiling that will break the product lattice
- [`docs/architecture.md`](../../architecture.md) §5, §11 — the compound decision and the epoch
