# Phase 3c — Wire the tool catalog

Finishes what Phase 3b started. Two tasks.

**The remaining defect, measured.** Phase 3b fixed shell commands but not file
tools:

```
Bash  "ls -la"          -> READ_ONLY        fixed by 3b
Read  "/tmp/notes.txt"  -> INTERNAL_MODIFY  wrong
Write "/tmp/out.txt"    -> INTERNAL_MODIFY  indistinguishable from Read
Glob  "**/*.go"         -> INTERNAL_MODIFY  wrong
```

A `READ_ONLY`-capped delegation therefore denies reads — confirmed against a
real agent in Phase 3b Task 2, which reported the negative rather than
reshaping the scenario until it passed.

**Why extraction cannot fix it.** The classifier is *command-shaped*: its
patterns match verbs like `cat` and `ls`. A file tool's input is a bare path
containing no verb, so there is nothing to extract meaning from. `Read` is
read-only because it is **`Read`** — the meaning lives in the tool name, not
the argument.

**The mechanism already exists and is unwired.** `TierTable.Catalog` maps a
tool name to a tier and is already consulted by `DeriveTier` in the documented
order — override, then catalog, then built-in (spec §4.4). It is declared, it
is read, and nothing populates it. This phase connects it.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The catalog sits above the built-in classifier and below tenant
  overrides.** Do not change that order; it is spec §4.4 and the raise-only
  override rule depends on it.
- **The PEP still classifies nothing.** The catalog lives in the PDP. A tier
  hint from the PEP would be spec defect D1 — a sensitivity judgement made by
  the component being policed.
- **`Bash` must not get a catalog entry.** It must fall through to the command
  classifier, or every shell command collapses to one tier and Phase 3b is
  undone. Test this explicitly.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — Built-in catalog defaults

**Files:** `services/internal/authz/tier.go` (or a new `catalog.go`) and tests.

`func DefaultCatalog() map[string]models.ActionTier`, merged into `TierTable`
where the PDP builds it.

Seed the well-known tool names, and **write the reasoning next to each group**
rather than a bare table, because the next person will need to know why a tool
sits where it does:

- `READ_ONLY` — `Read`, `Glob`, `Grep`, `NotebookRead`, `LS`, `WebFetch`,
  `WebSearch`. Retrieval without mutation. Note that `WebFetch` and `WebSearch`
  read *external* data, which is a different axis from tier; if a tenant treats
  external reads as riskier, the raise-only override is the mechanism.
- `INTERNAL_MODIFY` — `Write`, `Edit`, `NotebookEdit`, `TodoWrite`. Mutates
  local state.
- **No entry** — `Bash`, and anything unrecognised. Falls through to the
  command classifier, which is the whole point for shell tools.

**These names are Claude Code-shaped in a server meant to be
framework-agnostic.** That is a deliberate trade: a catalog nobody populates
leaves the defect exactly where it is, and the failure is silent because the
default is merely coarse rather than an error. Record the trade in the package
doc, and note that a database-backed per-tenant catalog is the eventual home.

**Tests:** each seeded tool derives its expected tier; `Bash` has no entry and
still routes to the command classifier; an unknown tool falls through
unchanged; and a tenant override **raises** a catalog entry but cannot lower it
— the existing `ValidateOverride` rule must still hold above the catalog.

**Mutation-test and report survivors:** give `Bash` a catalog entry; put the
catalog below the built-in in the resolution order; let an override lower a
catalog entry.

---

## Task 2 — Prove it against a real agent

Re-run Phase 3b Task 2's **Session B**, unchanged, with the same safety
constraints: scratch directory only, never touch a settings file outside it,
never install the hook into the running session.

A delegation capped at `READ_ONLY`, and a prompt mixing reads with a write:
*"Read the two text files here and summarise them, then write the summary to
summary.txt."*

**The proof:** reads are **permitted**, the write is **denied at the delegation
leg**. Report the derived tier for every call.

Also confirm Phase 3b's gain did not regress — `Bash "ls -la"` must still
derive `READ_ONLY` — since a catalog entry for `Bash` would silently undo it.

**Report honestly if it does not work.** Phase 3b Task 2 reported a negative
and that is why this phase exists; a run bent until it passed would have cost
more than it saved.

Clean up the scratch directory, containers, and volumes.
