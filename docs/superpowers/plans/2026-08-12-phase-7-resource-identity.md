# Phase 7 — Resource identity, and the inert delegation controls

Closes the two findings Phase 6's real-agent run produced. Four tasks.

**The defect, measured.** The delegation leg has four controls. Two of them do
nothing in a live deployment:

```
derived > MaxActionTier          WORKS   — tier is derived server-side
!HasTool(tool)                   WORKS   — the tool name is sent
CheckCap(caps, resource)         ALWAYS PASSES
ResourceConstraints              NEVER CHECKED AT ALL
```

`pkg/classification.CheckCap` returns `true` immediately when the resource
carries no `classification` attribute — and **no PEP mode has ever populated
`DecideRequest.resource`**. The wire field exists (`pdp.proto:77`),
`pdpgrpc/server.go` threads it into `EvaluationInput`, and all four policy
engines map it. No client fills it.

`Delegation.ResourceConstraints` is worse. Every non-test reference is
creation-time inheritance, persistence, or `ScopeNarrows` narrowing.
`internal/authz/delegation.go` never reads it. An operator can set
`{project: alpha}`, watch `ScopeNarrows` faithfully enforce that children only
narrow it, see it persisted — and nothing ever compares a request against it.

**Why this matters more than an ordinary gap.** Spec §4.4 names these among the
controls that carry weight: *"the delegation ceiling, the agent's tool
allowlist, the classification caps, and escalation."* Two of the four named
controls do not currently carry weight. And §3.8 asserts the clamp may safely
skip resource scope because it is *"left to the runtime principal leg, which
has the concrete resource"* — the runtime leg does not have it. The design rests
on an assumption the implementation never satisfied.

This is not a bypass: the ceiling and the tool allowlist hold, so an agent
cannot exceed its tier or reach an unlisted tool. But an operator who caps
`nato: CONFIDENTIAL` believes they have restricted classified material and has
not.

## The rulings (spec-level, record them)

**R1 — the PEP sends resource *identity*, never classification.** A PEP knows a
file path; it cannot know whether that file is CONFIDENTIAL. Extracting an
identifier from a tool's arguments by field name is structural — the same
category as `normalize`'s extraction, and the same category the PDP already
trusts for `tool`. Deciding what that identifier *means* is classification and
belongs to the PDP. A PEP that labelled a resource would be spec defect **D1**.

**R2 — a classification cap that cannot be checked denies.** `CheckCap`
currently returns `true` for a resource with no classification, so a configured
cap fails **open**, silently. Defect **D10** already ruled that a policy which
cannot be evaluated denies rather than being ignored; a cap that cannot be
evaluated is the same fact about a different control. **This is a behaviour
change**: any deployment with caps configured and no classification source will
begin denying. That is correct — it was already not enforcing them — but it
must be loud, documented, and released deliberately.

**R3 — resource labelling is an unresolved design gap, recorded not papered
over.** ZTDF was where labels lived and ZTDF was removed; nothing replaced it,
and §9 never listed it as open. R2 makes the gap loud rather than closing it.
Closing it needs a tenant-configured labelling source and is out of scope here.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP classifies nothing.** R1 is a narrow licence to extract an
  identifier by field name, nothing more. No tier logic, no labelling, no
  allowlist, no "obviously safe" shortcut.
- **`internal/authz` stays pure** — no database, no network, no ambient clock.
- **Fail closed everywhere.** Every change here adds denials; none may convert
  a deny into an allow. If one appears to, stop and report.
- Deny still overrides escalate; `FoldVerdicts` keeps its shape.
- No `WHERE tenant_id` in any Go query; RLS is the only tenant boundary.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The PEPs send resource identity

**Files:** `services/cmd/stratium-pep/` (`normalize.go` or a sibling), both
modes, and tests.

Extract a resource identifier from a tool call's arguments **by field name
only** and send it in `DecideRequest.resource`. The existing `normalize`
extraction is the model and the precedent: it maps `.command`, `.file_path`,
`.path`, `.pattern` by name, and its doc comment already states that a schema
map is not a policy.

Send identity attributes — at minimum an `id`, and a `type` where the field
name makes it unambiguous. **Do not send a `classification` or `hierarchy`
attribute from the PEP under any circumstances**: those are what `CheckCap`
consumes, and a PEP that supplies them is a PEP deciding its own
classification, which is D1 with higher stakes than the original.

**Keep the table small and dumb.** If it starts growing conditionals about what
a tool *means*, that is classification and it belongs in the PDP.

**Both modes.** `hook` and `mcp` must send the same attributes for equivalent
calls; a resource constraint that binds under one surface and not the other is
worse than one that binds under neither, because it looks enforced.

**Tests:** each recognised field name yields the expected `id`; an unrecognised
tool sends an empty resource map and is not an error; the two modes produce
identical attributes for the same logical call; and — assert explicitly — no
code path ever sets `classification` or `hierarchy`.

**Mutation-test and report survivors:** send a `classification` attribute; make
an unrecognised tool fail rather than send empty; make the two modes diverge.

---

## Task 2 — Enforce `ResourceConstraints` at the delegation leg

**Files:** `services/internal/authz/delegation.go`, and tests.

The leg compares the request's resource attributes against the delegation's
`ResourceConstraints`. `ScopeNarrows` already defines what narrowing means
between parent and child; **decision-time semantics are new and this task
defines them.** Settle and document each:

- A constrained key **absent from the request** — this is the load-bearing one.
  **Deny.** The constraint exists to bound what the agent may reach; a request
  that does not say what it is reaching cannot be shown to satisfy it, and
  fail-closed is this system's rule everywhere else. Silently passing would
  recreate exactly the `CheckCap` defect this phase exists to fix.
- A constrained key **present with a different value** — deny.
- A constrained key **present and matching** — pass. Values are opaque
  caller-defined strings, compared exactly. **No wildcards, no prefixes, no
  ranges** — `ScopeNarrows`' own comment gives the reason, that every such
  interpretation is a place a widening can hide.
- Extra request attributes the delegation does not constrain — ignored. A
  constraint set is a filter, not a schema.
- An **empty** constraint map — unrestricted, matching how `HasTool` treats an
  empty tool list. Note this is the one place empty-means-unrestricted survives
  after §4.3.1; say so, since a reader will expect the opposite.

**Where in the leg's order?** After the tool check and beside `CheckCap`. State
the reason in a comment: the checks are independent and the order only affects
which reason an operator sees first, so it should be the one that best explains
the denial.

**Mutation-test and report survivors:** make an absent key pass; make the
comparison a prefix match; make an empty map deny everything; skip the check
when the request's resource map is empty.

---

## Task 3 — An uncheckable classification cap denies

**Files:** `services/pkg/classification/`, `services/internal/authz/`, the spec,
and tests.

Implement **R2**. `CheckCap` currently returns `true` when the resource carries
no `classification`; make a configured cap with no classification a **denial**,
with a reason saying the cap could not be evaluated — not that it was satisfied.

**A cap set on a hierarchy the request says nothing about is unenforceable, and
unenforceable must not read as compliant.** That is D10's ruling applied to a
different control, and the audit row must be able to tell the two apart: "the
resource was CONFIDENTIAL and the cap allowed it" and "we could not tell what
the resource was" are different facts.

**The no-caps case is unchanged.** `len(caps) == 0` still returns true
immediately — a delegation with no caps is unrestricted on that axis and always
was. Only a *configured* cap becomes strict. Test that boundary explicitly; it
is the difference between this change and one that denies everything.

**Record R1, R2, and R3 in the spec**, including plainly that resource
labelling is an unresolved gap with no current source, that §3.8's "the runtime
principal leg has the concrete resource" was untrue until Task 1, and that §4.4's
list of controls that carry weight overstated two of four until this phase.

**This is a behaviour change and the docs must say so** — `docs/pep.md` and the
spec both. An operator with caps configured will begin seeing denials, which is
correct and was always the intended semantics, and they need to know why.

**Mutation-test and report survivors:** restore the permissive return; make the
no-caps case strict too; make the denial reason indistinguishable from an
ordinary cap violation.

---

## Task 4 — Prove it, end to end and against a real agent

**Files:** the integration suite, and a scratch real-agent run.

**Integration proofs, against a live stack:**

1. A delegation with `{project: alpha}` permits a request carrying it and denies
   one carrying `{project: beta}`.
2. The same delegation **denies a request that omits `project` entirely** —
   Task 2's load-bearing rule, over the wire.
3. A delegation with a classification cap denies a request whose resource has no
   classification, and the audit row's reason distinguishes "could not evaluate"
   from "cap exceeded".
4. A delegation with **no** caps and **no** constraints is unaffected by this
   phase — the regression guard, and the one that proves the change is targeted
   rather than a blanket tightening.

**Then a real-agent run**, same shape and same safety constraints as Phase 6
Task 4: scratch directory only, never a settings file outside it, never install
into the session doing the work, tear everything down afterwards.

Give the agent a delegation with a resource constraint scoping it to one
subdirectory, and let it try to read outside. **Report what it actually does**
— Phase 6 found the agent declined to fall back to its native tools when
denied, and Phase 3c found a scope without discovery tools left it guessing
filenames. Behaviour is the finding.

**Also re-check Phase 6's negative 1**: a `READ_ONLY` delegation still denies
every third-party MCP read, because `DefaultCatalog` is Claude Code-shaped.
This phase does not fix that. Confirm it is still true, and confirm this
phase's changes did not make it worse or mask it.
