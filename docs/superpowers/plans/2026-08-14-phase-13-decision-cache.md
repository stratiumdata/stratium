# Phase 13 — The PEP decision cache

Implements spec §4.8 and §4.8.2 **W1**–**W5**. Closes conformance properties
**C19**, **C20**, and **C24**. Four tasks.

**What it is for.** §4.8 is explicit that caching buys **outage tolerance**
first and speed second, because the principal leg's key includes the resource
instance and its hit rate is near zero. This is an availability feature. A plan
that optimises it for latency will optimise the wrong thing.

**Everything it depends on now exists.** Phase 12 built the revocation epoch —
bumped by a database trigger in the same transaction as any control-plane write,
read *first* in `Decide` so a decision can only be labelled older than the state
it reflects, and returned on `Decide`, `CreateDelegation`, and `IssueToken` so a
PEP always holds a current value without an extra round trip.

**The three properties this closes, and which condition closes each:**

```
C20  a stale epoch cache entry is not served        -> epoch match
C24  an expired token is denied despite a hit       -> token validity + recorded expiry
C19  PDP unreachable + no valid entry -> deny       -> staleness window
```

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP classifies nothing, decides nothing, and combines nothing.** It
  stores a verdict the PDP produced and replays it, or it denies. Any logic that
  derives a verdict from parts is spec defect **D1**.
- **Escalation outcomes are never cached** (**W4**, §4.6). The failure is silent
  if missed: a cached `ESCALATE` either re-blocks an approved call or serves an
  approval nobody granted.
- **Fail closed.** A missing, unreadable, corrupt, or ambiguous cache is a
  cache miss, and a miss with an unreachable PDP is a denial. **No cache
  failure may ever produce an allow.**
- **A cache hit must not extend a credential's life.** The token is checked
  independently; a token can only be refreshed by reaching the PDP.
- **Never log a cached decision's reason, a token, or a cache key's input
  digest.**
- `internal/authz` stays pure and is not touched by this phase.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The store

**Files:** `services/cmd/stratium-pep/cache.go` and tests.

An on-disk cache beside the session file. Entries keyed by
`(delegation id, tool, input digest)` (**W2**), each recording the decision, the
epoch it was computed under, the delegation's expiry, and when it was cached.

**Follow `writeSessionFile` exactly** (`session_file.go`): `os.CreateTemp` in
the target directory, then `os.Rename`, with `0600` set **at creation** rather
than `chmod`'d after. Tool calls run in parallel — the `hook` is a fresh
subprocess per call and several may run at once — so a non-atomic write is a
torn authorization record, not a slow one.

**Concurrent access is the hard part of this task.** Several `hook` processes
may read and write simultaneously with no shared memory between them. Work out
what happens when two processes write concurrently, and what a reader sees
mid-write. **A lost update is acceptable** — it costs a cache miss. **A torn
read is not** — it could yield a decision assembled from two entries. Say what
you chose and why, and test it with real concurrent processes or goroutines, not
by reasoning.

**Bound the file.** An unbounded cache on a developer's laptop grows until
something else breaks. Decide an eviction policy — size, count, or age — and
justify it. Note that entries past the staleness window are dead weight by
construction, which makes age the obvious first lever.

**Tests:** an entry round-trips; the file is `0600`; a corrupt file is a miss,
not an error; a partially-written file is a miss; concurrent writers do not
produce a torn read; eviction bounds the file as you specified.

**Mutation-test and report survivors:** write in place instead of
temp-then-rename; `chmod` after creation instead of at it; make a corrupt file
an error that propagates rather than a miss.

---

## Task 2 — Validity

**Files:** `services/cmd/stratium-pep/cache.go` and tests.

The four conditions of **W3**, **all required**, each independently testable:

1. the entry's epoch equals the last epoch the PEP saw — **C20**;
2. the delegation has not expired, per the entry's own recorded expiry —
   **C24**'s time half, and the reason §4.8.1 **V2** deliberately keeps expiry
   out of the epoch;
3. the caller's token is still valid — **C24**'s credential half;
4. the entry is within the configured staleness window since the last
   successful PDP contact — **C19**'s bound.

**Each gets its own test, and each gets its own mutation.** A single test
asserting "an invalid entry is not served" would leave three conditions
unguarded, and this project has repeatedly found exactly that shape.

**The staleness window is required config with no default.** An operator states
how long an unverifiable decision may keep working; no default is right for
every deployment, and a wrong one is either useless or too permissive.

**"Last successful PDP contact" needs a definition.** It is not the same as the
entry's `cached_at` — a PEP may contact the PDP successfully for a *different*
call, which proves the PDP is reachable and the epoch current. Decide whether
the window runs from the entry's own caching time or from the most recent
successful contact of any kind, and **justify it**; the two differ sharply
during an outage that begins after a busy period.

**Never cache an escalation** (**W4**). Test that an `ESCALATE` response is not
stored, and that no cached entry can ever produce one.

**Mutation-test and report survivors:** drop each of the four conditions
individually; cache an escalation; make the window run from the wrong instant.

---

## Task 3 — Wire the two locally-invoked surfaces

**Files:** `services/cmd/stratium-pep/` — `hook.go`, `mcp_authorize.go`,
`extauthz.go`, `proxy.go` — and tests.

Consult the cache before calling the PDP; store the result after — on `hook`
and `mcp` **only** (spec §4.8.3 **W6**). `extauthz` and `proxy` always call the
PDP and get no cache.

**Why, because it will look like an omission otherwise.** A cache hit is defined
by not calling the PDP, and the PDP is the only component that verifies a
token's signature (**K2**) — the PEP reads it with `ParseUnverified`. On a
network surface the caller *is* the policed party, so a forged token naming a
known delegation would satisfy all four **W3** conditions and be served a cached
ALLOW with the PDP never contacted. On the local surfaces the caller already
holds the session file containing a real token, so the cache grants nothing new.

**C19 still closes**: "every surface denies when there is no valid entry" is
trivially true of a surface with no cache.

**The surfaces differ in a way that matters.** `hook` is a short-lived
subprocess that must read and write the file every call. The other three are
long-lived servers that could hold an in-memory layer above the file — **do not
build one in this task.** A second cache tier is a second invalidation path, and
this phase has enough of those; note it as a possible later optimisation and
move on.

**On a cache hit, the PDP is not called at all** — that is the outage tolerance.
Assert it directly: the PDP client must not be contacted, not merely that the
result matched.

**On a miss with an unreachable PDP, deny** with a reason distinguishing "no
cached decision and the PDP is unreachable" from an ordinary policy denial. An
operator debugging an outage needs to know which they are looking at.

**Tests, per surface:** a hit serves without contacting the PDP; a miss calls
the PDP and stores the result; a miss with an unreachable PDP denies with the
distinguishing reason; an escalation is not stored.

---

## Task 4 — Prove it, and close three properties

**Files:** the integration suite, `services/internal/authz/conformance_test.go`.

**Against a live stack:**

1. A decision is cached and served without the PDP being contacted.
2. **Stopping the PDP entirely**, a valid cached entry still serves — the
   outage-tolerance promise, proven by actually stopping the container rather
   than simulating unreachability.
3. With the PDP stopped and **no** cached entry, every surface denies — **C19**.
4. A control-plane write bumps the epoch; the next `Decide` returns the new
   value; the previously cached entry is **not served** — **C20**, end to end,
   and the payoff for Phase 12.
5. An expired token is denied **despite a valid cache entry** — **C24**.
6. Past the staleness window with the PDP still down, entries stop serving.

**Then convert C19, C20, and C24 — if the proofs establish them.** Read what
each actually asserts first. C19 says *every* surface; confirm all four are
covered before converting it. **Do not force any of them** — C23 converted only
when a real Envoy proved it, and five others were left skipped with honest
reasons. If a property is established only at a layer `internal/authz` cannot
reach, `provenElsewhere` with a machine-checked pointer is the honest
classification, not `pass`.

Report the resulting tally. If all three convert, it moves from 14/5/6 to
somewhere near 14 pass / 8 proven elsewhere / 3 not built — but **report what
actually happens**, and treat a different number as a finding rather than an
error to correct.

Confirm the conformance gate still bites afterwards: rename a pointed-to test,
watch it fail, restore.
