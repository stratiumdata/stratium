# Phase 2d — The delegation-creation gate

Closes spec defect **D3** and unblocks conformance property **C6**. Implements
§3.8 **G6** as amended 2026-08-10. Five tasks.

**The defect.** In the predecessor, `CreateDelegation` evaluated no policy at
all. Any authenticated user could mint a delegation granting
`max_action_tier: DESTRUCTIVE`, every tool, and any classification cap. That is
the privilege amplification the product's own positioning names first. This
repository has no delegation-creation path yet, so the gate is built correct
rather than retrofitted.

**What the clamp is and is not.** Defence in depth, not the only barrier. An
over-broad artifact does not by itself let an agent act beyond its principal —
the principal leg still evaluates at runtime and denies. The clamp buys an
artifact that is honest about what it permits, a cheaper and earlier denial,
and a backstop if the principal leg is ever misconfigured.

**Scope boundary.** No token is minted here. Delegations are referenced by ID,
which is what `DecideRequest` already carries. Signed, sender-constrained
tokens are a later plan.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The clamp covers resource-independent dimensions only** — the action-tier
  ceiling and the tool set. Resource scope and classification stay with the
  runtime principal leg, which has the concrete resource. Probing action
  policies with no resource under-grants severely; see spec §3.8 G6.
- **Clamp silently, record it, and return the granted scope** (§3.3 Y4). An
  over-broad request is narrowed, not rejected: an agent framework requesting a
  generous default should degrade, not fail hard. The response must state what
  was actually granted so the caller knows its real bounds.
- **A probe that errors or is inconclusive drops the dimension.** An
  unanswerable question is not a grant.
- **The tenant comes from configuration, never the request** — as everywhere
  else in this system.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — The grant probe

**Files:** `services/internal/policy/probe.go` and its test.

```go
// GrantProbe asks what a principal may delegate, as distinct from what they
// may do. It answers only the resource-independent dimensions, because a probe
// carries no resource and a resource-conditional policy would not match one.
type GrantProbe struct {
	Principal   authz.Principal
	Tool        string             // empty when probing the tier ceiling
	Tier        models.ActionTier
	Environment map[string]string
}
```

`func Probe(ctx, set CompiledPolicySet, p GrantProbe) (bool, error)` builds an
`EvaluationInput` with no resource and no agent, evaluates, folds the verdicts
with the existing `authz.FoldVerdicts`, and reports whether the result allows.

**Reuse `FoldVerdicts`.** Do not write a second combining rule — the whole
reason C12's fold moved into `authz` was that a security property enforced in
two places drifts. Deny-overrides and default-deny apply here identically.

**Tests.** A permit for the principal allows; a forbid denies; no matching
policy denies (default-deny); an engine error denies **and** returns the error
rather than swallowing it; and — the important one — a policy scoped to a
resource does **not** allow a resourceless probe, which is the under-granting
behaviour the design accepts deliberately. Assert it so nobody later "fixes" it
into a wildcard match.

---

## Task 2 — The clamp

**Prerequisite found in Task 1.** `EvaluationInput.DerivedTier` is populated
from `GrantProbe.Tier`, but Cedar's `buildRequest` does not yet map it into the
request context — so a policy conditioning on tier cannot answer a tier-ceiling
probe. Extend the Cedar context mapping to carry `DerivedTier` before the clamp
can work, and add a Cedar test proving a policy that forbids above a tier
actually denies a probe at that tier. Without it the tier walk-down below has
nothing to walk against.

**Files:** `services/internal/policy/cedar/` (the context mapping),
`services/internal/authz/clamp.go` and its test.

```go
// RequestedScope is what the caller asked for.
type RequestedScope struct {
	MaxActionTier models.ActionTier
	Tools         []string
}

// GrantedScope is what survived the clamp, with what was removed and why.
type GrantedScope struct {
	MaxActionTier models.ActionTier
	Tools         []string

	// Removed names each dimension that was clamped away and the reason, so
	// the caller and the audit row can both say what happened rather than
	// silently returning something narrower than was asked for.
	Removed []ClampRemoval
}
```

`func Clamp(ctx, req RequestedScope, allows func(tool string, tier models.ActionTier) (bool, error)) (GrantedScope, error)`

The `allows` callback is injected so `authz` stays pure — it holds no engine
and no database handle. Task 3 supplies one backed by `Probe`.

**The tier clamp walks down.** If the requested tier is not permitted, try the
next lower tier until one is, or reach `REASONING`. Do not simply drop to zero:
a principal permitted `INTERNAL_MODIFY` who requests `DESTRUCTIVE` should get
`INTERNAL_MODIFY`, not `REASONING`.

**Tests.** Every dimension permitted yields the request unchanged with an empty
`Removed`; a denied tool is dropped and recorded; a too-high tier walks down to
the highest permitted; a probe error drops that dimension and records the
reason; a request permitted at nothing yields `REASONING` and an empty tool
list rather than an error; and clamping is **idempotent** — clamping an
already-clamped scope changes nothing.

**Mutation-test and report survivors:** remove the tier walk-down so it drops
to zero; make a probe error grant rather than drop; stop recording removals.

---

## Task 3 — Persist the delegation

**Files:** `services/internal/store/delegation.go` and its test.

`func (s *Store) CreateDelegation(ctx, d *models.Delegation) error`

Tenant-scoped via `beginTenantTx`, no `WHERE tenant_id` in the Go query, RLS
does the isolation.

**For a child delegation, `models.ScopeNarrows(parent, child)` must pass before
the insert.** That function is the most heavily mutation-tested code in this
repository and it already enforces every narrowing dimension including the
omission cases. Call it; do not reimplement any part of it.

**Tests** with sqlmock: the tenant is set before the insert; a root delegation
inserts with `root_delegation_id` equal to its own id and depth 0; a child
inherits its parent's root and depth+1; a child whose scope widens is rejected
before any insert is attempted; and the transaction is committed or rolled back
on every path.

---

## Task 4 — The `CreateDelegation` RPC

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/`, and tests.

`CreateDelegationRequest` carries the principal subject, the agent id, the
requested scope, an optional parent delegation id, a purpose, and a TTL.
**No tenant field** — configuration, as everywhere else.

`CreateDelegationResponse` returns the delegation id and the **granted** scope,
including what was removed and why. A caller that asked for more must be able
to see what it actually received.

Order: validate → load the agent → load the parent chain if any → probe and
clamp → build the delegation → `ScopeNarrows` if child → persist → **audit** →
respond. As with `Decide`, a failed audit write fails the call; a delegation
that was created without a record did not happen.

**Tests:** a clamped request returns the narrowed scope with removals listed; an
unknown agent is `NotFound`; a child widening its parent is `PermissionDenied`;
an audit failure returns an error and **no delegation id escapes**; and the
persisted row matches what the response reported.

---

## Task 5 — End to end, and unskip C6

Extend the integration suite against a live stack:

1. A principal with a Cedar policy permitting `INTERNAL_MODIFY` requests
   `DESTRUCTIVE` with three tools, two of them not permitted. The response
   grants `INTERNAL_MODIFY` with one tool, and lists the three removals.
2. **The persisted delegation matches the response** — query the row and
   compare field by field, not merely that it exists. Provenance fields being
   plumbed but never populated has bitten this project twice.
3. A `Decide` call using the clamped delegation denies an action above the
   granted tier, at the **delegation** leg.
4. The audit row records the creation, and `audit.Verify` passes over a chain
   containing both a creation and a decision entry.
5. A second tenant's principal cannot create a delegation referencing the first
   tenant's agent — `NotFound`, via RLS.

**Then unskip `TestC6_DelegationClampedToPrincipalAuthority`** and make it
pass. Report the conformance tally: it should move from 13 pass / 12 skip to
**14 pass / 11 skip**, still 25 executed. That is the first skip this project
has converted.
