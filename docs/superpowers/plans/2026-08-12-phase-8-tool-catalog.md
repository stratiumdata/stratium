# Phase 8 — The per-tenant tool catalog

Implements spec §4.4.2 **T1**–**T3**. Four tasks.

**The debt, and its interest.** Phase 3c wired a tool catalog and said plainly
in its own plan that the names were Claude Code-shaped in a server meant to be
framework-agnostic, naming a database-backed per-tenant catalog as the eventual
home. Three controls have since been blocked by it, none found by a test:

```
Phase 6  a READ_ONLY delegation denies EVERY third-party MCP read
         read_file has no catalog entry -> classifier default INTERNAL_MODIFY
Phase 7  ResourceConstraints cannot discriminate on MCP at all
         resourceIDFields knows only Claude Code's tool names
Phase 7  classification caps inherit the same gap
         same never-populated resource attributes
```

Each was found by a real-agent run. The pattern is worth naming: a hardcoded
table that is *documented* as a temporary shape does not announce itself when it
starts costing something — only running the system against the thing it was
supposed to support does.

**What changes.** One catalog row per tool per tenant, holding the tier, the
verb, and which `raw_input` fields carry the resource identity and the command.
The PDP reads it and does the extraction itself. The PEP's three parallel
per-tool tables and the `normalized_input` wire field all go.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **`internal/authz` stays pure** — no database, no network, no ambient clock.
  The catalog is *loaded* in `store` and *passed in*, exactly as policies are.
- **The evidence rule is not weakened** (§4.4.1). A positive
  destructive-or-external pattern match on raw input is never lowered — not by a
  catalog entry, not by an override, not by a tenant's row. It binds
  `DeriveTier` at the boundary and stays there.
- **The PEP classifies nothing, and after T2 it extracts nothing either.** It
  sends the tool name and `raw_input`. Any per-tool table remaining in the PEP
  at the end of this phase is a bug.
- **The serving role gets `SELECT` on the catalog and never `INSERT` or
  `UPDATE`** (T1, following E7). The absent grant is the enforcement, not a
  comment claiming it.
- **Fail closed.** A tenant with no catalog rows falls back to the built-in map
  and behaves exactly as today; a tool in neither still takes the classifier's
  default. No path here may turn a deny into an allow.
- No `WHERE tenant_id` in any Go query; RLS is the only tenant boundary.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The catalog table and its loader

**Files:** a migration, `services/internal/store/catalog.go`, and tests.

One row per tool per tenant: the tenant id, the tool name, the action tier, the
verb, and the `raw_input` field names carrying the resource identity and the
command. Nullable where a tool has no such field — a tool with no resource field
is ordinary, not an error.

**Tool names are matched exactly and case-sensitively.** Record why: a
case-insensitive match would have to decide what to do about two rows differing
only in case, and this project already fixed a cap-lookup that failed open on
exactly that ambiguity. A `UNIQUE (tenant_id, tool_name)` constraint makes the
ambiguity unrepresentable rather than merely handled.

**RLS enabled and forced.** Grants: `SELECT` only for the serving role.
**Not `INSERT`, not `UPDATE`, not `DELETE`** — T1 follows E7: the PDP
authenticates no callers, so an endpoint writing authorization configuration
could not verify who was calling. Say that in the migration, and add an
integration test proving the serving role genuinely cannot write, as Phase 5
Task 2 did for `approvals`. A grant nobody tests gets widened by accident.

`LoadToolCatalog`, tenant-scoped via `beginTenantTx`, ordered deterministically.

**Tests** with sqlmock: the tenant is set before the query; a row round-trips
field for field with **distinguishable values** — no two fields sharing a value,
adjacent scan targets especially; an empty result is not an error; the
transaction is committed or rolled back on every path. Plus the real-Postgres
grant test above.

---

## Task 2 — Server-side extraction, and the catalog in `DeriveTier`

**Files:** `services/internal/authz/`, `services/internal/pdpgrpc/`, and tests.

The per-tenant catalog slots into §4.4's existing resolution order —
**override, then catalog, then built-in** — with the built-in map as the
fallback for a tenant with no rows. That ordering already exists in
`DeriveTier`; do not restructure it.

The PDP extracts the resource identity and the command from `raw_input` using
the catalog's field names, and feeds them to `EvaluationInput.Resource` and to
tier derivation.

**Three properties that must survive, each with its own test:**

- **The evidence rule (§4.4.1) still outranks everything.** A positive
  destructive-or-external match on raw input is never lowered by a catalog
  entry, a tenant override, or an extracted field. This is the rule a previous
  phase found silently disabled when a lookup layer was added *above* it — do
  not repeat that by extracting first and classifying second.
- **A tenant with no catalog rows behaves exactly as today.** This is the
  regression guard and it is what makes the change safe to ship.
- **The PDP never infers a classification.** The catalog says which field holds
  the resource identity; it never says what that resource is classified as
  (§3.9 R3). Assert structurally that no path sets `classification` or
  `hierarchy`.

**Mutation-test and report survivors:** let a catalog entry lower a destructive
match; make an empty catalog deny everything; make extraction run before the
evidence check; infer a classification from a field name.

---

## Task 3 — Retire the PEP's tables and `normalized_input`

**Files:** `services/cmd/stratium-pep/`, `proto/pdp/v1/pdp.proto`, and tests.

Delete `resourceIDFields`, `normalizedInputFields`, and `toolVerbs`. Remove
`normalized_input` from the wire. Both modes send the tool name and `raw_input`
and nothing derived.

**This is deletion, and the risk is over-deletion.** Every property those tables
supported must still hold — proven by the PDP-side tests from Task 2 rather than
by the PEP tests you are removing. **For each PEP test you delete, say which
Task 2 test now defends that property.** If any property has no successor, stop
and report: that is a real gap, not an artefact of the refactor.

**`verb` needs a decision.** `toolVerbs` derived it from the tool name in the
PEP. The catalog now holds it, so the PDP can derive it — but `DecideRequest`
carries a `verb` field today. Either the PDP derives it and the field is
retired with `normalized_input`, or the field stays and the PEP sends something.
**Pick one, and justify it**; a wire field the PDP ignores is the
plumbed-but-unconsumed defect this project has hit five times.

**Both modes must end with no per-tool table of any kind.** Grep for one at the
end and say what you found.

---

## Task 4 — Seed, prove, and re-run the agent

**Files:** the integration suite, seed material, and a scratch real-agent run.

**Seeding.** A tenant needs catalog rows before third-party tools work. Provide
the seed material for the two servers this project has actually run against —
Claude Code's own tools and `@modelcontextprotocol/server-filesystem` — as
data, not code. Document how an operator adds a tool.

**Integration proofs against a live stack:**

1. A tenant with a catalog row for `read_file` at `READ_ONLY`: a `READ_ONLY`
   delegation **permits** it. This is Phase 6's negative 1, closed.
2. The same tenant's `write_file` at `INTERNAL_MODIFY` is **denied** under that
   delegation — proving the row is doing the work rather than the check being
   skipped.
3. A resource constraint **discriminates on the MCP surface**, using the
   catalog's resource field. This is Phase 7's finding B, closed.
4. A tenant with **no** catalog rows is unaffected — the regression guard.
5. The serving role cannot write the catalog.

**Then re-run the real agent**, same safety constraints as before: scratch
directory only, never a settings file outside it, never install into the session
doing the work, tear everything down.

Run the MCP surface with a seeded catalog and a `READ_ONLY` delegation.
**Phase 6's negative was that this denied every read; confirm it now works** —
and report what the agent does, since behaviour has been the most informative
output of every real-agent run so far.

**Also re-check Phase 7's finding A**, which this phase does not fix: resource
constraints scope to one exact resource identity, never a subdirectory, and any
constraint silently disables `Glob`. Confirm it is unchanged and not masked.
