# Resource labelling

Implements spec §3.9.1 **R4**–**R8**. Closes the gap **R3** records. Five tasks.

**What this makes true.** Classification caps are a declared authorization
dimension that **cannot currently be used at all**. `CheckCap` reads
`resourceAttrs["classification"]`; nothing anywhere supplies one; and **R2**
makes an unusable cap deny. So a tenant that configures a cap today gets a
denial on every action. Opt-in, so nobody is broken by default — but the
feature is inert for anyone who tries it.

**This is the same shape as the tier overrides Phase 14 found inert, with one
difference that sets the whole plan's tone: that one needed wiring, this one
needed designing.** ZTDF was where labels lived and ZTDF was removed; **R1**
forecloses the obvious shortcut on principle, because a classification the
server cannot independently check would simply be believed. §3.9.1 settles
where a label comes from. This builds it.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **`internal/authz` stays pure** — no database, no network, no ambient clock.
  The matcher belongs there or in `pkg/classification`; the rules are read in
  `store` and passed in, exactly as policies and catalog entries are.
- **The PEP supplies identity, never classification** (**R1**). Nothing in
  `cmd/stratium-pep/` changes. A structural allowlist test already asserts
  `classification` and `hierarchy` are never keys a PEP can produce — it must
  keep passing, and it is the guard that keeps **R1** true.
- **Prefix matching only** (**R5**). No regex anywhere on this path: the
  resource id derives from attacker-influenced `raw_input`, so a regex engine
  here is a reachable denial-of-service.
- **The longest matching prefix wins** (**R6**), including when it *lowers*
  the classification. That is the ruling, not an oversight — a public file
  inside a secret directory is genuinely public. **The PDP logs a lowering
  carve-out**; that log line is the operator's only signal.
- **An unlabelled resource still denies** (**R2**, **R7**). Do not add a
  default level, a fallback, or an "unclassified means allow" branch. The
  catch-all an operator needs is the empty prefix, which costs no mechanism.
- **The PAP writes, the PDP reads.** The new table follows **T1**/**T6**:
  `stratium_pap` gets write, `stratium_app` gets `SELECT` and nothing more.
  Those absent grants are the enforcement.
- **No `WHERE tenant_id` in any Go query.** RLS is the only tenant boundary.
- **Every PAP write is audited** (**N4**), in the same transaction.
- Never log a resource id at a level that would leak a path, a token, or
  policy text.
- Strict root `.golangci.yml`. Clean before each commit, from the repo root:
  `make build`, `make vet`, `make test`, `make lint`, `make conformance`,
  `make integration`.
- Conventional commits, no attribution trailers.
- Scratch work goes in the session scratchpad, never the repository.

## Standing rules, all earned in this project

- **A conflict test must supply every competing source**, not the subset the
  implementation happens to consult. A fixture omitting the field a mutant
  would read cannot distinguish "the code ignores it" from "it was not there."
- **A mutant dying is not evidence that the property you credited killed it.**
  Check which assertion fired.
- **A negative claim about what a system can observe is a claim to check, not
  to reason to.** `audit_chain` is a readable per-request record of what the
  PDP received; a proof that says "nothing can see this" is usually wrong.
- **Commit before running any mutation**, and before believing any result
  confirm `git diff --numstat` is non-empty **and** `go vet ./...` is clean. A
  no-op patch and a survivor are indistinguishable; so are a non-compiling
  mutant and a survivor.
- **If you change a fixture other tests route through, re-run every mutation
  those tests were credited with killing.**

---

## Task 1 — The matcher

**Files:** the prefix resolver and its tests. **Pure: no I/O, no clock.**

Given a set of rules — each a prefix, a hierarchy, and a level — and a
resource id, resolve the label: the level from the **longest matching prefix**
(**R6**), or none if nothing matches.

**It must also report whether the winning rule lowered the classification**
relative to the next-longest match, because **R6** requires the PDP to log
that and the matcher is the only thing that knows. Decide the shape — a second
return, a struct field — and justify it.

**Ties cannot happen and the code should say why**: two identical prefixes in
one tenant are a uniqueness violation the table forbids (Task 2). If you find
you need a tie-break rule, that is a finding about the schema, not a matcher
feature.

**The empty prefix matches everything** (**R7**), and is how an operator
registers a catch-all. It is not a special case in the matcher — it falls out
of prefix semantics — but test it explicitly, because a reader will look for
it and an implementation that special-cased it would be wrong in a way nothing
else catches.

**Tests:** the longest match wins over a shorter one; a lowering carve-out is
resolved *and* reported as lowering; no match yields no label; the empty
prefix matches everything including an empty id; a prefix that is not a path
boundary (`/data` against `/database/x`) — decide whether that matches and
justify it, because it is the case an operator will get wrong.

**Mutation-test and report survivors:** shortest match wins; ties broken
arbitrarily; the lowering flag never set; the empty prefix special-cased to
match nothing.

---

## Task 2 — The table and its read path

**Files:** a migration, `services/internal/store/`, and integration tests.

A tenant-scoped table of rules: prefix, hierarchy, level. **Unique on
`(tenant_id, prefix)` — NOT on `(tenant_id, prefix, hierarchy)`, which is what
this plan originally said and which Task 1 showed to be wrong before it was
built.**

`CheckCap` consumes exactly one `classification` and one `hierarchy` per
resource (`pkg/classification/classification.go`). A resource therefore cannot
carry a label in two hierarchies at once. Keying on the triple would let a
tenant register the same prefix under both `nato` and `commercial` — a pair no
resource can satisfy, which the matcher correctly refuses to resolve, and whose
**only symptom is total silent denial under that prefix** with nothing naming
the cause. A table must not be able to express a configuration the decision
path cannot consume.

Keying on `(tenant_id, prefix)` is what makes Task 1's "ties cannot happen"
true rather than assumed. Task 1 does not rely on it — it refuses ambiguity
deterministically and says so at its own boundary — but that is a safety net,
not a licence to leave the schema loose.

**One hazard the key does NOT close, carried to Task 3:** rules at *different*
prefix lengths in different hierarchies. A `commercial` PUBLIC carve-out
beneath a `nato` TOP-SECRET rule makes the resource escape the nato cap
entirely — arguably worse than a lowering, but it is not one, and reporting it
as a lowering would put a false claim in **R6**'s log line. Task 3 owns the
ruling.

`migrations/000013_tool_catalog.up.sql` is the template: `CREATE TABLE`, then
`ENABLE` and `FORCE ROW LEVEL SECURITY`, a `tenant_isolation` policy, then the
grants. Match its commenting standard — this codebase documents *why* in
migrations.

**Validate the level against the hierarchy at write time.** `pkg/classification`
knows the canonical levels; a row naming a level that hierarchy does not have
is a row that can never match, and storing it is the failure the admin plane
exists to prevent.

**`stratium_app` gets `SELECT` and nothing more** (**T6**'s reasoning). Prove
it with a test, as Task 2 of Phase 14 did for the grants it withheld.

**Tests** (integration — RLS and a uniqueness constraint need a database):
rules round-trip; a duplicate `(tenant, prefix, hierarchy)` collides; the same
prefix in two tenants does not; a level not in its hierarchy is refused;
`stratium_app` can read and cannot write; the epoch bumps on a write, if the
Phase 12 trigger covers this table — **check whether it does and say so**,
because a labelling change that does not invalidate a cached decision is a
stale authorization decision.

---

## Task 3 — Wire it into the decision path

**Files:** `services/internal/pdpgrpc/`,
`services/pkg/classification/classification.go`, and tests.

Load the tenant's rules, resolve the resource id's label, and put it where
`CheckCap` will find it — `resource["classification"]` and its hierarchy
attribute.

**Preserve V3's ordering.** The epoch is read first, before any other store
read. This adds one; it must not displace that, and
`TestDecide_EpochIsTheFirstStoreRead` is the guard.

**Log a lowering carve-out** (**R6**). Decide what the line carries — enough
for an operator to find the rule, not enough to leak a path into a log that
may be shipped elsewhere — and justify it.

**And rule on the cross-hierarchy case, which Task 1 surfaced and neither R6
nor Task 2's key resolves.** Rules at different prefix lengths in different
hierarchies mean a `commercial` PUBLIC carve-out beneath a `nato` TOP-SECRET
rule makes the resource escape the nato cap entirely. That is arguably worse
than a lowering — but it **is not** one, and logging it as a lowering would put
a false claim in the operator's log. Decide whether it is refused, reported
separately, or accepted with its reasoning recorded; do not let it fall through
the gap between the two.

**Close the unknown-hierarchy fail-open first** (**R9** — read it in the spec
before writing anything else in this task). `CheckCap` returns **allow** when
the delegation's caps name no hierarchy matching the resource's. That is right
for a hierarchy a cap simply does not mention, and wrong for a hierarchy that
does not exist — and this task is what first lets an operator-typed hierarchy
reach that branch, so it is this task's defect to close, not an inherited one.

```
rules: /data/    nato    SECRET
       /data/x/  natoo   UNCLASSIFIED     <- one typed character
caps:  {"nato": "CONFIDENTIAL"}
```

The carve-out wins on length, no cap matches `natoo`, `CheckCap` allows, and
**R6**'s lowering log stays silent because an unrankable hierarchy has no rank
to compare. A capped resource becomes an unconditional allow with no signal.

`Index` already returns `-1` for an unknown hierarchy (**R8** keeps them
hardcoded), and `CheckCap` computes it only *after* the `!hasCap` early return.
Move the validity check ahead of that return: an unknown hierarchy, or a level
unknown within its hierarchy, denies with a reason naming the unknown value.
**D10** — an unevaluable policy denies — applies to a label the system cannot
rank.

Two things to get right. A *known* hierarchy that the caps do not mention must
still allow; do not turn silence into denial. And 25 existing `CheckCap` tests
run through this function — read them before moving the check, and if any
asserted the old allow, work out whether it encoded this defect deliberately
before changing it.

**Do not add a fallback.** An unmatched resource gets no classification, and
`CheckCap` denies (**R2**). The temptation is a default level; resist it and
say why in the code.

**Tests:** a capped decision on a labelled resource resolves and is allowed or
denied on the label; a capped decision on an **unmatched** resource denies,
with a reason distinguishing "no rule matched" from an ordinary cap failure; a
carve-out that lowers is honoured and logged; an uncapped decision is
unaffected by the rules entirely; V3's ordering still holds.

**Tests for R9 specifically:** a resource labelled with an unknown hierarchy
denies, and the reason names the unknown value; a resource labelled with a
known hierarchy the caps do not mention still **allows**; a level unknown
within a known hierarchy denies. The first and second must both be present —
one without the other cannot distinguish the fix from a blanket denial.

**Mutation-test and report survivors:** default an unmatched resource to the
lowest level; default it to the highest; read the rules before the epoch; drop
the lowering log; **restore `!hasCap` to an unconditional allow**; **weaken the
R9 check to deny on any hierarchy the caps do not name** (this one must be
killed by the still-allows test, not by the denies test — check which assertion
fires).

---

## Task 4 — The PAP's CRUD

**Files:** `services/cmd/stratium-pap/`, and tests.

Create, read, update, delete for the rules. **Every write audited in the same
transaction** (**N4**), as a new `EventType`.

**Role gating** matches the existing resources: `viewer` reads, `editor`
writes, `admin` deletes. State the mapping and test each boundary.

**Refuse a level that is not in its hierarchy**, surfacing the store's own
validation rather than duplicating it — a second copy of the rule is a second
thing to drift.

**Mutation-test and report survivors:** persist without auditing; let `viewer`
write; accept a level outside its hierarchy.

---

## Task 5 — Prove it live, and write the cliff down

**Files:** the integration suite, `docs/pep.md` or the operator docs.

**Against a live stack:**

1. An operator registers a rule through the PAP; the epoch bumps; the next
   `Decide` resolves the label and enforces the cap.
2. A resource matching **no** rule denies, and the reason says so.
3. A lowering carve-out is honoured — a public subtree inside a classified
   one — and the log line naming it is present.
4. The longest prefix wins over a shorter one, live, not only in the matcher's
   own tests.
5. `stratium_app` still cannot write the table.

**Then write R7's cliff into the operator documentation.** A tenant enabling a
cap without a catch-all denies every unmatched resource. That is correct
behaviour and it will read as an outage. It belongs somewhere an operator
finds *before* enabling a cap, alongside how to register the empty-prefix
catch-all.

**Then re-check the conformance suite.** Nothing here is expected to convert —
this builds a capability rather than proving a property. **Read the properties
that touch classification or resources before assuming that**, and say if any
becomes stronger or weaker. Do not force a conversion.

Tear the stack down; verify no strays. **A supabase stack for an unrelated
project runs on this host — do not stop, remove, or prune it. If Docker fills,
`docker builder prune -af` only.**
