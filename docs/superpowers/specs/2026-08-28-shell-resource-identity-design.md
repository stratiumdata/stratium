# Design — a resource identity for shell commands

Closes J1 for `Bash` and every other command-field tool: today, configuring any
classification cap denies every shell call permanently, and no operator action
clears it.

Status: design. Decision taken 2026-08-28 (all-paths, strictest-wins).
Evidence and alternatives: [`docs/validation-journeys.md`](../../validation-journeys.md)
J1, §4.3, §5.

---

## The problem

A tool catalogued with a `command_field` and no `resource_field` produces no
resource identity. Extraction yields an empty resource map, `labelResource`
returns before consulting any rule, and `CheckCap` denies because a configured
cap cannot be evaluated against a resource that declares no classification.

The consequence is not a tunable strictness. It is a permanent denial that the
documented remedy cannot reach: the fix for an unlabelled resource is an
empty-prefix catch-all rule, and `labelResource` short-circuits on an empty id
at `internal/pdpgrpc/label.go:85` *before* `classification.Resolve` is called,
so no rule can ever match. Proven live at
`TestIntegration_Journey1_AClassificationCapDeniesEveryFieldlessToolCall`.

Six tools ship this way. Five are minor (`Glob`, `Grep`, `WebFetch`,
`WebSearch`, `TodoWrite`). `Bash` is not: it is the tool agents use most, and
its absence means classification caps and shell access are mutually exclusive
features.

---

## What makes this more than a path parser

The system already permits labelling an agent-influenced identifier, and
`label.go:41` states the premise that makes it safe — call it **R4**:

> the id is what the tool actually acts on. Naming a different resource changes
> what you get, not merely what you are permitted; lying does not pay.

For `Read(file_path)` R4 holds exactly. **A naive shell extractor breaks it.**
Taking the first path-like token from

    cat /tmp/notes.txt; cat /secret/plans.txt

yields `/tmp/notes.txt`, the catch-all labels it `UNCLASSIFIED`, and the command
still reads the secret. Lying now pays, and it pays better than the status quo:
it converts a loud denial into a silent allow. **A careless version of this fix
is materially worse than the gap it closes.**

So the requirement is not "extract a path." It is: *extract in a way that
preserves "lying does not pay."*

---

## Decisions

1. **All path-like tokens are extracted, and the strictest label wins.** A
   decoy cannot help — additional paths only add constraints — and the real
   target cannot be omitted, because the command needs it to run. That is what
   restores R4 in general rather than for a whitelist of command shapes.
2. **The resource map stays single-valued.** The fold happens inside
   `labelResource`; `classification` and `hierarchy` are written from the
   winning path. `CheckCap` is unchanged, `resourceFromID`'s one-key property
   is unchanged, and R1 stripping is unchanged.
3. **No `id` is written for a command-derived resource.** See "Resource
   constraints stay denied", below. This is the decision that keeps the change
   strictly safe rather than merely net-positive.
4. **Extraction lives beside the classifier, not in `extract.go`.** Reading
   meaning out of a command string is interpretation of a value, which
   `extract.go`'s package doc forbids that file from doing. New file
   `services/internal/authz/shellpaths.go`, next to `tier.go`, which already
   interprets the same string for the same reason.
5. **An empty path set denies, exactly as today.** `npm test` and `echo hi`
   name no resource. This change makes caps-plus-shell *better*, never
   *solved*, and the documentation must say so.

---

## Surface

One new exported function, pure, no I/O:

```go
// ShellResourceIDs returns every path-like token in a shell command, in
// source order, deduplicated. Over-extraction is safe and under-extraction
// is not: see the fold rule.
func ShellResourceIDs(command string) []string
```

`labelResource` takes `resourceIDs []string` where it takes `resourceID string`
today. Its single-id callers pass a one-element slice or nil.

`Decide` calls `ShellResourceIDs(ext.Command)` when the catalog row carried a
`command_field`, and passes the result to `labelResource` alongside the
existing extracted id. A tool with both fields contributes both.

---

## The fold, in order

Given the resolved labels for every extracted path:

| Case | Result |
|---|---|
| No paths extracted | No label written. A configured cap then denies — unchanged from today. |
| Any path resolves to no rule | No label written; the cap denies. An unrankable member makes the maximum unknowable, and an unknowable maximum must not read as satisfied. |
| Paths resolve across two hierarchies | Write the strictest per hierarchy; `CheckCap` already evaluates only the resource's own hierarchy. **Open question, below.** |
| Otherwise | Write the highest-ranked `(hierarchy, level)` by `classification.Index`. |

**Why over-extraction is tolerable and under-extraction is not.** A token that
is not really a path (`-la`, `--force`) still resolves under the catch-all rule
that any capped tenant is already required to have, so it contributes the
floor level and changes nothing. A *missed* path contributes nothing and can
lower the maximum below the truth — which is the R4 failure this design
exists to prevent. The extractor must therefore bias toward including doubtful
tokens.

That interlock is load-bearing: it works *because* the caps API already
refuses to set a cap without a catch-all (`ErrNoCatchAllRule`). Without that
rule, row 2 of the table above would fire on every flag token and deny
everything.

---

## Resource constraints stay denied

`checkResourceConstraints` denies when a constraint names a key the request
does not carry. `Bash` carries no `id` today, so every constrained delegation
denies every shell call — correct, if blunt.

Writing a command-derived `id` would change that to: *one* of several paths is
compared against the constraint. A decoy that satisfies the constraint while
another path does the real work would pass. That is the R4 failure again, one
consumer over.

So this design deliberately writes **no `id`** for a command-derived resource.
Shell commands remain unable to satisfy a resource constraint, exactly as
today. Fixing that requires the constraint check to receive the full path set
and require *every* member to satisfy — a separate change, gated behind fix #2
(a write path for `resource_constraints`), which no supported API can populate
anyway.

---

## Testing

The acceptance criteria already exist and currently assert the opposite. Both
carry `WHEN THIS FAILS` markers naming this document:

| Test | Today | After |
|---|---|---|
| `TestJourney1_FieldlessToolsCanNeverSatisfyAClassificationCap` | passes | **must fail for `Bash`**, and be split: `Bash` gains identity, the other four do not |
| `TestIntegration_Journey1_AClassificationCapDeniesEveryFieldlessToolCall` | passes | **must fail for a command naming a path**, and keep passing for one naming none |
| `TestJourney42_NoCatalogRowOrOverrideCanLowerAPositiveMatch` | passes | must keep passing — untouched |

New tests this change needs:

- The decoy case, as its own named property: `cat /tmp/ok.txt; cat /secret/x`
  denies under a cap that `/tmp/ok.txt` alone would satisfy. This is the whole
  design; it deserves a test whose name says so.
- Over-extraction is inert: a command of flags and no paths resolves entirely
  to the catch-all and allows.
- Under-extraction is loud: a path spelled with quoting or `${IFS}` is still
  found, mirroring `normalizeCommand`'s existing cases.
- An unrankable member denies rather than folding to the maximum of the rest.
- A command naming no path still denies under a cap.
- `resource["id"]` remains absent for a command-derived resource, so
  constraint behaviour is bit-for-bit unchanged.

---

## Out of scope

- **The other five fieldless tools.** `Glob`, `Grep`, `WebFetch`, `WebSearch`
  and `TodoWrite` keep denying under a cap. Each would need its own argument
  about what it "acts on", and none is load-bearing the way `Bash` is.
- **Resource constraints for shell.** See above.
- **Path-free commands.** A delegation-scoped working root was considered and
  rejected: it labels where a command runs rather than what it reaches, which
  is a weaker claim wearing a stronger label — the exact thing R4 forbids.
- **Making the classifier adversary-proof.** Unchanged. `tier.go`'s RESIDUAL
  RISK note still applies, and the controls that hold are still the ceiling,
  the allowlist, and escalation.

---

## Risks

- **Under-extraction is a silent weakening.** A path form the extractor misses
  lowers the effective classification below the truth. Mitigated by biasing
  toward inclusion, by the catch-all interlock, and by the decoy test — but
  this is the risk to review hardest, and any future edit that makes the
  extractor *more* selective must argue against this paragraph.
- **A spurious denial is loud but annoying.** A token wrongly treated as a path
  under a strict rule set can raise the effective label. Preferred direction,
  and diagnosable from the denial reason if the reason names the winning path.
  It should.
- **Two hierarchies in one command** is genuinely undecided. Writing one label
  per hierarchy is the obvious answer, but the resource map holds exactly one
  `(classification, hierarchy)` pair today, and widening it touches R1's
  stripping guarantee. Resolve before implementation; the conservative interim
  is to deny when extracted paths span hierarchies.

---

## References

- `services/internal/pdpgrpc/label.go` — R1, R4, and the empty-id short circuit
- `services/internal/authz/extract.go` — the boundary this change must not cross
- `services/internal/authz/tier.go` — the existing interpreter of the same string
- `services/pkg/classification/classification.go` — `CheckCap`'s ordered rules
- [`docs/validation-journeys.md`](../../validation-journeys.md) — J1, §4, §5
- [`docs/default-posture.md`](../../default-posture.md) §4 — what operators are told today
