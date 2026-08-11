# Phase 4a — Engine parity and the dead-policy guard

Remediates the findings Phase 4's two reviews left open. Five tasks.

Phase 4 shipped four policy engines and closed defect **D10**. Its two Criticals
— XACML's `<Target>` OR-ing where XACML 3.0 mandates AND, and Cedar/Rego
silently discarding evaluation failures — are already fixed in `8c32afe` and
`d84009d`. This plan takes the rest.

**The theme, and the reason this is one plan rather than eleven fixes.** Three
of the four engines independently discovered, and independently fixed, the same
class of defect: a policy that is *syntactically valid and semantically dead* —
accepted by `Validate`, compiled by `Prepare`, and structurally incapable of
ever producing the verdict its author intended.

- Rego: a module with a typo'd `package` declaration. Fixed by `checkPackage`.
- JSON: `"in": []`, and an `at_most` outside the tier lattice. Fixed in `schema.go`.
- XACML: out-of-vocabulary tier spellings, whitespace-padded values, repeated
  elements silently merged. Fixed across `schema.go` and `structure.go`.

Three fixes, in three packages, by three reviewers, and **zero changes to
`policytest.EngineContract`**. Nothing at the boundary every engine routes
through asks "can a policy this engine accepted ever fire?" So Cedar — which
predates the contract and was never audited — still accepts **thirteen** dead
forms, and a fifth engine would inherit none of the protection.

This is spec **§4.4.1**'s pattern for the fourth time: a property enforced at
one level rather than at the boundary everything routes through survives
exactly until someone adds a level. Task 1 fixes it structurally; Tasks 2 and 3
then fall out of the contract rather than being hand-audited.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- `internal/authz` stays pure: `internal/policy` may import `authz`, never the
  reverse. `authz.FoldVerdicts` is not modified by any task in this plan.
- **No engine implements combining.** One verdict per policy, nothing else.
- **Policy may only narrow.** Every change here must be fail-closed. If a change
  could turn a deny into an allow, stop and report rather than proceeding.
- **`Prepare` compiles once; `Evaluate` must not** (defect D5).
- **The verdict slice returned from `Evaluate` is freshly allocated per call** —
  `multiSet.Evaluate` appends it into its own slice.
- Every engine must still pass `policytest.EngineContract` at every commit.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Scratch work goes in the session scratchpad, never in the repository. Three
  Phase 4 agents left scratch Go files inside `internal/policy` where other
  processes saw them.

---

## Task 1 — Put the dead-policy guard in the contract

**Files:** `services/internal/policy/policytest/contract.go`, and each engine's
contract call site.

The contract cannot enumerate engine-specific dead shapes — it does not know
what a Rego package declaration or an XACML `<AnyOf>` is. What it can do is
require every engine to **declare its own dead forms and prove it rejects
them**, which is the part that generalises.

Extend `Fixtures`:

```go
// DeadForm is a policy text that is syntactically well-formed for this
// language but semantically incapable of ever producing its author's intended
// verdict — a typo'd package path, a vacuous empty set, an out-of-vocabulary
// enum spelling. Each must be rejected by BOTH Validate and Prepare, and
// Prepare's error must name the offending policy's ID.
type DeadForm struct {
    // Name identifies the shape in test output, e.g. "vacuous empty set".
    Name string
    // Dead is the text that must be rejected.
    Dead string
    // Live is the corrected form of the same intent. It must be ACCEPTED and,
    // when evaluated against LiveInput, must produce a verdict. Without this,
    // an engine could satisfy the contract by rejecting everything.
    Live string
    // LiveInput is the input Live is expected to match.
    LiveInput policy.EvaluationInput
}
```

`Fixtures` gains `DeadForms []DeadForm`, and `EngineContract` gains a subtest
per form asserting reject-dead **and** accept-and-match-live.

**An empty `DeadForms` slice must fail the contract**, with a message saying the
engine has not declared any. A silent zero-length slice is how this property
would quietly stop applying to a fifth engine — the same vacuous-pass failure
the D5 structural guards each defend against with a zero-call-sites tripwire.

**Then populate it for the three engines that already have the checks**, from
their existing tests: Rego's wrong package; JSON's `in: []` and out-of-lattice
`at_most`; XACML's out-of-vocabulary tier, padded value, and repeated element.
Those tests already exist — this is lifting the *property* to the contract, not
rewriting the checks. Cedar's list is Task 2 and will start empty, so **Cedar's
contract call must be the last thing you touch**: expect it to fail until Task
2 lands, and say so in your report rather than weakening the contract to make
it pass.

**Mutation-test:** make an empty `DeadForms` pass; drop the `Live` positive
control and confirm an engine that rejects everything then passes; make
`Prepare` accept a dead form for one engine and confirm only that engine fails.

---

## Task 2 — Cedar semantic validation, and its D5 guard

**Files:** `services/internal/policy/cedar/`, and its `DeadForms`.

Cedar accepts all thirteen of these today. Each validates, prepares, and can
never fire. Input for reference: `trust_tier=CERTIFIED`,
`derived_tier=DESTRUCTIVE`, `purpose=quarterly-close`, resource carrying `id`
and `classification`.

```
wrong-case enum          trust_tier == "Certified"
ordinal instead of name  trust_tier == "2"
name instead of ordinal  derived_tier == "DESTRUCTIVE"
typo'd context key       context.agent.trust_teir
typo'd nested record     context.delegaton.purpose
vacuous empty set        trust_tier in []
contradiction            1 == 2
unknown entity type      principal == Usr::"alice"
wrong principal type     principal is Resource
String vs Long compare   max_action_tier > 2
padded literal           " CERTIFIED "
out-of-lattice ceiling   derived_tier > 99
missing resource attr    resource.nonexistent == "x"
```

Every one is an already-fixed defect in another engine. The two most
consequential are `wrong-case enum` and `ordinal instead of name`: those are
exactly what an author gets by porting a working rule from XACML (which spells
tiers `DESTRUCTIVE`) or from Rego (which uses the ordinal `3`). XACML rejects
both by name at authoring time.

**Investigate cedar-go's schema support first and report what you find.**
`cedar-go` may expose schema-based validation; if it does, validating policies
against a schema describing the request context catches typo'd keys, wrong
types, and unknown entity types together, which is far better than thirteen
hand-written checks. If it does not, or if it is not usable from the current
version, fall back to targeted checks and **say so explicitly** — do not
silently hand-roll what the library would have done.

Whichever route, the closed vocabularies come from `models` — `ActionTier` and
`AgentTrustTier` already own `.String()` and their parse functions, as XACML's
`schema.go` does. Do not write a second copy of either lattice.

**Note what Critical 2 already covers.** `d84009d` made Cedar surface
`Diagnostic.Errors` as a deny verdict, which converts several of these from
silently-inert into loud denials **at evaluation time**. That is a different
guarantee from rejecting them at authoring time, and both are wanted: an
operator should learn at write time, not on the first request. Check which of
the thirteen are already loud after `d84009d` and report the split — you may
find fewer than thirteen still need authoring-time work.

**Also add Cedar's D5 structural guard.** Rego, JSON, and XACML each have one;
Cedar has none, so nothing stops a future edit moving
`cedarlib.NewPolicyListFromBytes` into `Evaluate`, and no behavioural test can
catch it. Model it on `rego/engine_test.go`'s, including the zero-call-sites
tripwire, and note the trap Task 4 of Phase 4 hit: if `Prepare` and `Validate`
share a parsing helper, a scan for the literal library call misses a decode
moved into `Evaluate` via that helper.

**Mutation-test each new rejection individually** and confirm a distinct test
catches it; split any test that catches two.

---

## Task 3 — Rego type safety

**Files:** `services/internal/policy/rego/`, and its `DeadForms`.

The one finding in Phase 4 where a wrong policy **widens** rather than going
inert. Rego totally orders values across types — number before string — so a
type mistake is not an error but an unconditional truth:

```
allow if { input.agent.trust_tier > 2 }    agent=UNVERIFIED  -> ALLOW
allow if { input.derived_tier <= "2" }     tier=DESTRUCTIVE  -> ALLOW
```

Neither `Validate` nor `Prepare` catches either. A rule ported from Cedar's
`context.derived_tier > 2` idiom onto the wrong field becomes an unconditional
principal-leg allow.

**The fix is an OPA input schema.** OPA supports type-checking policies against
a JSON schema for `input` via `rego.Schemas()` and `ast.NewSchemaSet()`. Write
a schema describing the input document `rego/input.go` actually produces —
every field, with its real type — and attach it at `Prepare`. `trust_tier` is a
string; comparing it to a number then fails compilation with a type error
naming the policy, instead of silently evaluating to true.

**The schema must be generated from or checked against `input.go`, not written
independently.** Two hand-maintained descriptions of the same document will
drift, and the drift is silent in exactly the direction that matters: a field
the schema omits goes unchecked. If you cannot generate it, add a test that
walks the built input document and asserts every key appears in the schema, so
adding a field to `input.go` without the schema fails.

Note the interaction with Phase 4's measurement: Rego's `Prepare` already costs
21.5 ms at 100 policies because it compiles each policy independently.
**Re-measure after adding the schema and report the delta** — type-checking is
not free, and this is the engine that can least afford it. If the cost is
material, say so plainly; it strengthens rather than weakens the case for the
batched-compile change noted below.

**Out of scope, recorded here so it is not lost:** the Task 6 review found that
`rego/engine.go` calls `regolib.New(...).PrepareForEval` **per policy**, so 100
policies is 100 independent OPA compiles. OPA accepts many `regolib.Module()`
calls in one `New()`, sharing a single compiler pass, at the cost of per-policy
verdict attribution. That trade needs its own measurement and decision. Do not
attempt it here.

---

## Task 4 — Delete what is dead, and decide the unread fields

**Files:** `services/internal/policy/configured.go`, `probe.go`, `engine.go`,
`input.go`, `services/internal/store/policy.go`, and their tests.

**Delete `policy.Configured`, `PolicySource`, `Unconfigured`, and
`store.LoadPolicies`.** All four are production-dead — `policy.Multi` replaced
them in Phase 4 Task 2 — and `Configured` is worse than merely unused: it is an
exported, wireable constructor whose behaviour **is defect D10**.
`Configured(source, cedar.New())` returns a `PrincipalPolicy` that loads one
language and silently ignores the rest, which is precisely what this phase
existed to eliminate. `TestNoExportedConstructorAllows` does not catch it,
because it guards against an unconditional *allow*, not against single-language
evaluation.

The decision was passed from Task 3 to Task 6 and then nowhere. Take it now.
Keep `store.loadAllPoliciesQuery` and `LoadAllPolicies`; delete only the
single-language pair and their now-orphaned tests.

**Three fields are loaded or plumbed and never read. Resolve each:**

- **`StoredPolicy.Effect`** — loaded from the database, read by no engine (all
  four derive effect from the policy text), and able to contradict it: a row
  stored `effect='deny'` whose text says `permit(...)` yields ALLOW. Any PAP
  listing policies by `policies.effect` would show the opposite of what the
  policy does. **Drop the field from `StoredPolicy` and from the load query.**
  Keep the database column — a future PAP write path may populate it — and
  record in `store/policy.go` that if anything ever does, it must validate
  agreement with the text at write time rather than being trusted at read time.
- **`StoredPolicy.Version`** — loaded, never read. Spec Y2 wants it as a cache
  key and no cache exists. **Keep it**, and say in its doc comment that it is
  loaded ahead of the cache decision Phase 4's measurement informs, so the next
  reader does not delete it as dead.
- **`GrantProbe.Environment` and `EvaluationInput.Environment`** — never
  populated by any caller, never mapped by any of the four engines, and
  separately declined in four package docs. **Delete both.** A field four
  engines have independently documented as unmapped is a field to remove, not
  to document a fifth time. If a later phase needs environment attributes it
  can add them with a caller that populates them and an engine that reads them.

**Confirm by grep, in your report, that nothing outside tests referenced any
deleted symbol**, and that the no-allow AST guard still passes and still bites
after `Configured` and `Unconfigured` are gone — that test enumerates exported
constructors, so removing two of them changes what it sees.

---

## Task 5 — Make D10 visible, and close the small gaps

**Files:** `services/internal/policy/multi.go`, `deploy/docker/`,
`services/internal/store/store_integration_test.go`,
`services/cmd/stratium-pdp/`, and the engine packages.

**The live proof-3 test.** Phase 4's Task 6 reported that proof 3 — the
orphan-language denial, D10's central demonstration — "cannot be produced
against the shared PDP at all." That claim is **false**, and its reviewer
produced the denial by hand:

```
effect=EFFECT_DENY  decided_source="rego"
principal_reason="principal: no rego engine registered; cannot evaluate policy IDs 3bc8a685-…"
```

The plumbing is correct and D10 is genuinely closed in production; what is
missing is a permanent test at the outermost layer. Add a second compose
service — a PDP with its own `STRATIUM_TENANT_ID` and a deliberately narrowed
`STRATIUM_POLICY_LANGUAGES` — and assert the denial over gRPC, including the
reason string and the audit row. Then **correct the false comment**, or it will
be inherited as fact by the next task that reads it.

Failure scenario this defends: someone changes how `FoldVerdicts`' chosen
reason is copied into `PrincipalReason` (`pdpgrpc/server.go`), the in-process
proof stays green, and operators silently stop being told which language went
unevaluated.

**`orphanVerdict` and `prepareFailureVerdict` leave `PolicyID` empty**
(`multi.go`), so `audit_chain.policy_id` is `''` on exactly the denials D10
exists to make visible; the orphaned IDs live only in free-text `Reason`.
`PolicyID` is singular and an orphan verdict concerns N policies, so **emit one
deny verdict per orphaned policy**, each naming its own ID. That matches the
one-verdict-per-policy shape every engine already follows, keeps the audit
column queryable, and is harmless under deny-overrides.

**Three small ones:**

- `STRATIUM_POLICY_LANGUAGES=cedar,cedar` silently dedupes to a one-entry
  registry. Harmless and arguably correct, but untested — pin it, whichever
  behaviour you keep.
- Cedar and Rego hardcode their `Source` string separately from `Language()`;
  JSON and XACML use one package-level const referenced by both. Make Cedar and
  Rego match. The contract's provenance property would catch a divergence, so
  this is consistency, not correctness.
- The JSON package doc documents the operators it deliberately omits
  (wildcards, regex, ranges) but not the absent **negation**, and says nothing
  about the resulting authoring trap: `at_most` is a match predicate with no
  `at_least`, so a tier ceiling can only be written as
  `{"effect":"allow","match":{"derived_tier":{"at_most":N}}}` — which is inert
  under deny-overrides whenever any other policy allows — while
  `{"effect":"deny",...}` denies tiers 0..N and permits everything above,
  the opposite of how it reads. Document both plainly. This is an
  expressiveness limit with a live trap attached, and the doc currently hides
  the trap.
