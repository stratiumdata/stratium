# Phase 12 — The revocation epoch

Implements spec §4.8 and §4.8.1 **V1**–**V4**. Prerequisite for the PEP decision
cache, which unblocks **C19**, **C20**, and **C24**. Three tasks.

**The gap.** `tenant_epoch` has existed since the baseline migration —
`tenant_id`, `epoch BIGINT NOT NULL DEFAULT 1`, `updated_at` — and **no
non-test code has ever read or bumped it**. §4.8's entire invalidation story
rests on it. This is the seventh instance in this project of a mechanism
plumbed and never populated, and it is the one that a whole planned feature
depends on.

**What this phase is not.** It does not build the cache. It builds the counter
the cache will validate against, plus the plumbing that lets a PEP know the
current value without an extra round trip. That ordering is deliberate: an
epoch is independently useful — it is what makes "revoke root, cascade on the
next action" true for *cached* decisions, as it already is for live ones — and
it can be proven on its own, so a defect in it cannot be mistaken for a defect
in the cache.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **`internal/authz` stays pure** — no database, no network, no ambient clock.
  The epoch is read in `store` and passed in, as policies are.
- **The PDP never bumps the epoch.** The trigger does, on the control plane's
  writes. A PDP that bumped would be a PDP writing authorization configuration,
  which **E7** and **T1** exist to prevent.
- **Fail closed.** A missing `tenant_epoch` row, an unreadable epoch, or a read
  error denies rather than reporting a plausible number. An epoch that is
  wrongly *low* would let a consumer serve stale decisions; wrongly *high*
  would invalidate needlessly. Only the second is safe, so err there.
- No `WHERE tenant_id` in any Go query; RLS is the only tenant boundary.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The trigger

**Files:** a migration, and integration tests.

A trigger bumps `tenant_epoch.epoch` for the affected tenant, **in the same
transaction as the write**, on changes to `policies`, `agents`, `delegations`,
`tool_catalog`, and `tier_overrides`.

**Narrow `delegations` to `UPDATE` and `DELETE`.** An `INSERT` there is a new
delegation, which is purely additive and invalidates no existing decision.
Bumping on it would mean every new agent session invalidates every PEP's cache
tenant-wide — correct but wasteful, and wasteful in a way that would only show
up as a mysteriously low hit rate much later. For the other four tables, all of
`INSERT`/`UPDATE`/`DELETE` bump: a new policy or catalog row changes what an
existing decision would evaluate to.

**A row must exist to bump.** Decide what happens for a tenant with no
`tenant_epoch` row — create on demand within the trigger, or seed on tenant
creation — and justify it. A trigger that silently no-ops for a tenant whose
row is missing is an invalidation mechanism that is off for exactly the tenants
nobody set up carefully.

**Write it so it cannot be bypassed.** That is the entire argument for a trigger
over application code (**V1**), so verify it holds against the paths that
actually exist: the serving role's writes, the migration role's writes, and a
direct `psql` `UPDATE` as an operator would make. **Say in your report which
roles and paths you tested.**

**Document it where a Go reader will look.** A trigger is invisible from the
application code that depends on it; put a pointer in `internal/store`'s package
doc as well as in the migration.

**Tests** (integration — a trigger cannot be tested with sqlmock, which has no
database to fire one): each of the five tables bumps on the operations it should;
`INSERT` on `delegations` does **not** bump; a bump is visible to a reader in the
same transaction and is rolled back with it; two writes in one transaction bump
sensibly (decide whether once or twice, and justify); and a write by a
**different role** still bumps.

**Mutation-test and report survivors:** drop the trigger from one table; make it
fire `AFTER` the transaction rather than within it; let `INSERT` on `delegations`
bump; make the bump non-monotonic.

---

## Task 2 — Read it, and return it

**Files:** `services/internal/store/`, `services/internal/pdpgrpc/`,
`proto/pdp/v1/pdp.proto`, and tests.

`LoadTenantEpoch`, tenant-scoped via `beginTenantTx`. `DecideResponse` carries
the epoch the decision was computed under, so a PEP always has the current value
**without an extra round trip** — which is what makes epoch validation free at
the edge rather than doubling the request count.

**Read the epoch first, before any other read in `Decide`** (**V3**). This is
the correctness property of the task:

```
read policies at N -> bump to N+1 (a revocation) -> read epoch = N+1
   => the decision ignored the revocation but is labelled current.  UNSAFE.
```

Reading first means a decision can only be labelled **older** than the state it
reflects, so a consumer invalidates at least as eagerly as it should. **Test the
ordering directly** — not that the code reads first by inspection, but that a
bump interleaved between the epoch read and the policy read produces a decision
labelled with the *older* epoch. That is a concurrency test and it is the one
that matters.

`CreateDelegationResponse` and `IssueTokenResponse` should carry it too if a PEP
would otherwise start with no epoch at all — decide and justify.

**Tests:** the epoch round-trips into the response; a tenant with no row behaves
as Task 1 decided; the read is tenant-scoped; the ordering property above; and a
read failure denies rather than reporting a default.

**Mutation-test and report survivors:** read the epoch last; return a hardcoded
epoch; make a read failure return zero and continue.

---

## Task 3 — Prove it end to end

**Files:** the integration suite.

Against a live stack:

1. A control-plane `UPDATE` revoking a delegation bumps the epoch, and the very
   next `Decide` reports the new value **and** denies at the delegation leg.
   That is the cascade property §4.8 promises, now observable to a cache.
2. Suspending an agent bumps it; changing a policy bumps it; adding a catalog
   row bumps it.
3. Creating a delegation does **not** bump it.
4. A revocation on a **root** delegation bumps once and denies every descendant
   — cascade, proven at depth, since `DelegationLeg` already checks `Revoked` at
   every hop.
5. Two tenants' epochs move independently — a write in one does not invalidate
   the other's cached decisions. This is the tenancy property and it is the one
   a trigger could plausibly get wrong.
6. The epoch is monotonic under concurrent writes: run the audit suite's
   concurrency pattern against a table with the trigger and confirm no value is
   reused or skipped backwards.

**Then re-check the three conformance properties this unblocks but does not
close.** C19, C20, and C24 all still require the **cache**, which is Phase 13.
Their skip reasons currently name the cache as missing; confirm that is still
accurate now that the epoch exists, and correct any that now overstate what is
absent. **Do not convert any of them** — the epoch is a prerequisite, not the
property.
