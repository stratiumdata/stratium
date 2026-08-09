# Phase 2a — Serialize the audit append, split the migration identity

Two bounded fixes carrying measured evidence from Phase 1c's integration run.
Both block real Phase 2 work; neither needs a design cycle.

## Task 1 — Per-tenant advisory lock on the audit append

**The measurement.** Ten concurrent `Decide` calls for one tenant, three
fresh-volume runs: **3/7, 7/3, 4/6** succeeded/aborted. `UNIQUE (tenant_id,
prev_hash)` is working exactly as designed — writers racing on the same chain
tail collide, one wins — but "a failed audit write denies the action" (spec D3)
turns each collision into a denial. A 30–70% denial rate for a single tenant
under concurrency is not viable for an agent fleet.

It is invisible today only because no ALLOW is producible, so nothing valuable
is lost to the race yet. That stops being true the moment Phase 2 lands a
policy engine.

**Why an advisory lock rather than the alternatives.**

- *Bounded retry on 23505* degrades under precisely the load that triggers it.
  Every loser re-reads the same tail and races again; a burst becomes a
  thundering herd, and the retry budget is consumed fastest exactly when it is
  most needed.
- *Decoupling the append from the response* revisits D3. D3 exists because an
  ALLOW that was never recorded did not happen, as far as an auditor is
  concerned. Changing that is a spec decision, not an optimisation.
- *A per-tenant advisory lock* serializes correctly across multiple PDP
  instances, is released automatically at transaction end (so a crashed writer
  cannot wedge a tenant), and costs one round trip.

**The change.** In `services/internal/store/audit.go`, inside the existing
tenant-scoped transaction and **before** the tail read:

```go
// Serialize appends per tenant. Two writers that read the same chain tail
// both link to it, and UNIQUE (tenant_id, prev_hash) then rejects one — which
// D3 turns into a denied action. Measured at 30-70% denials for a single
// tenant under ten concurrent decisions.
//
// pg_advisory_xact_lock is held for the transaction and released on commit or
// rollback, including if the process dies, so a crashed writer cannot wedge a
// tenant. hashtext gives a stable per-tenant key; collisions between distinct
// tenants only serialize them unnecessarily, never mix their chains.
//
// This bounds a tenant's decision throughput by audit-write latency. If that
// ceiling ever binds, the answer is batching appends behind the lock, not
// removing it.
if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.tenantID); err != nil {
    return fmt.Errorf("acquire audit append lock: %w", err)
}
```

`ErrConcurrentAppend` and its `23505` detection **stay**. The lock makes the
collision unreachable in normal operation; the constraint remains the backstop
if a future writer bypasses the lock, and the error path remains tested.

**Tests.** Add to the sqlmock suite: the advisory lock is acquired inside the
transaction and **before** the tail read (ordered expectations), and a lock
failure aborts the append without attempting a write. Keep every existing test.

**Verification, which is the point of this task.** Re-run Phase 1c's
concurrency measurement against a live database: ten concurrent `Decide` calls
for one tenant, three fresh-volume runs. Report the actual split. The
expectation is 10/0 every time. Report the wall-clock time for the burst as
well, so the serialization cost is on record rather than assumed.

Also confirm two tenants appending concurrently do **not** block each other —
seed a second tenant and interleave, showing the lock is per tenant and not
global.

## Task 2 — Separate the migration identity from the serving identity

**The finding.** `main.go` runs migrations on the same connection it serves
from, so the login role needs standing membership in `stratium_audit_owner`.
That membership also grants DDL over `audit_chain`: `DROP TRIGGER` succeeds for
the serving identity, which is the one thing `000004`'s ownership split existed
to prevent. `UPDATE` and `DELETE` remain blocked regardless, so this is not a
live tamper path — but it is the ownership split not actually holding.

**The change.** Two database URLs rather than one:

- `STRATIUM_MIGRATION_DATABASE_URL` (optional) — used only for `migrations.Up`,
  then closed before serving begins. When unset, migrations are skipped and the
  PDP logs that it is assuming an already-migrated schema.
- `STRATIUM_DATABASE_URL` (required) — the serving connection, which must not
  be a member of `stratium_audit_owner`.

Add a startup check: the serving identity queries whether it holds membership
in the audit-owner role and **refuses to start** if it does. That converts a
deployment convention into an enforced invariant, which is the same reasoning
that put the tenant check inside `audit.Verify` rather than in a doc comment.

**Tests.** Config: both URLs parse; the migration URL is optional; the serving
URL is required. Startup check: a serving identity holding audit-owner
membership fails startup with a named error.

**Verification.** Against a live database, prove that after startup the serving
role can `INSERT` and `SELECT` on `audit_chain` but is refused `DROP TRIGGER` —
the state `000004` was written to produce.
