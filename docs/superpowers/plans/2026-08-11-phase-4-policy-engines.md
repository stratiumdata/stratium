# Phase 4 — The remaining three policy engines

Implements spec §3.3 **Y1**: OPA/Rego, XACML, and JSON alongside Cedar, all
four maintained. Six tasks.

**Scope.** Three new engines, plus the seam that lets a tenant hold policies in
more than one of them. Reference implementations, not to be copied blind:
`~/Development/stratium/go/pkg/policy_engine/{opa,json,xacml}_engine.go` (116,
310, and 175 lines). All three target the old 4-tuple `EvaluationInput` and
predate the agent and delegation dimensions — spec defect **D6** — so the
mapping is new work in every case; only the parsing and matching shapes carry
over.

**Two defects this phase closes.**

**D9 — the contract describes Cedar rather than constraining engines.**
`policytest.EngineContract` is documented as "the reusable conformance suite
every PolicyEngine implementation must pass," and its policy fixtures are
hardcoded Cedar:

```
contract.go:75  "permit(principal, action, resource) when { unbalanced ]["
contract.go:84  "permit(principal, action, resource);"
contract.go:93  Text: "permit(principal, action, resource);"
contract.go:94  Text: "forbid(principal, action, resource);"
```

No Rego, XACML, or JSON engine can pass it as written. A contract only one
implementation can satisfy has never been tested as a contract, and this is the
first phase that would find out.

**D10 — a policy in an unconfigured language is silently ignored.**
`configured.Evaluate` loads `LoadPolicies(ctx, engine.Language())` and
`main.go:111` hardcodes `cedar.New()`, while `policies.language` is a per-row
column accepting all four values. A tenant who authors a Rego policy against
today's PDP gets no error, no verdict, and no audit trace — the rule simply
never runs. The same single-language assumption is repeated independently at
`pdpgrpc/delegation.go:222`, so the delegation-creation clamp probes one
language while a later `Decide` would consult another.

## The decision (spec-level, record it)

**A PDP evaluates every language its tenant holds policies in, and a policy in
a language with no registered engine denies.**

Deny-overrides already makes a heterogeneous verdict list safe:
`authz.FoldVerdicts` neither knows nor cares which engine produced a verdict,
and `PolicyVerdict.Source` already carries the language for audit. Merging is
therefore free at the fold and needs no new combining rule — which matters,
because a second combining rule is what C12 moved into `authz` to prevent.

The orphan case is the load-bearing half. A policy row whose language has no
engine is not skipped and not ignored: it produces a deny verdict naming the
language. An operator who authors a rule the deployment cannot run must find
out from a denial, not from a system that quietly behaves as though they never
wrote it.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **`internal/authz` stays pure.** Engines live under `internal/policy/`, which
  may import `authz` for its types; `authz` must never import `policy`.
- **Policy may only narrow.** The three legs are independent AND terms, so an
  engine returning ALLOW cannot widen anything. Nothing in this phase may add a
  path by which a verdict raises a tier, adds a tool, or lifts a cap. If an
  implementation seems to need one, stop.
- **No engine implements combining.** Deny-overrides and default-deny belong to
  `authz.FoldVerdicts`, which every path already routes through. An engine
  returns one verdict per policy that matched and nothing else. Cedar's own
  `Evaluate` documents why it evaluates per-policy rather than letting the
  library fold — read it before writing a second engine that is tempted to
  shortcut.
- **`Prepare` compiles once; `Evaluate` must not.** Spec defect **D5** was
  engines recompiling per request. An engine that parses policy text inside
  `Evaluate` has reintroduced it.
- **A compiled set is used concurrently.** One prepared set serves every
  concurrent decision for a tenant. `EngineContract` runs 64 goroutines against
  it; the suite must be run under `-race` for that check to mean anything.
- Strict root `.golangci.yml`. `go build ./...`, `go vet ./...`,
  `go vet -tags integration ./...`, `go test -race ./...`,
  `golangci-lint run ./...`, and `make conformance` clean before each commit.

---

## Task 1 — Make `EngineContract` a contract

**Files:** `services/internal/policy/policytest/contract.go`,
`services/internal/policy/cedar/engine_test.go`.

Parameterise the fixtures so the suite is about behaviour rather than syntax:

```go
// Fixtures supplies the language-specific policy text EngineContract needs.
// Every field is required; a zero value is a programming error, not a skip.
type Fixtures struct {
	// Malformed must fail Validate and Prepare.
	Malformed string
	// WellFormed must pass Validate. It is the positive control without which
	// an always-erroring Validate would satisfy Malformed too.
	WellFormed string
	// AllowAll and DenyAll must each match every input and carry their
	// respective effects. The concurrency check needs two policies that both
	// always match, so that a set of two always yields exactly two verdicts.
	AllowAll string
	DenyAll  string
}

func EngineContract(t *testing.T, engine policy.PolicyEngine, f Fixtures)
```

Cedar's existing call passes its current strings verbatim, so its behaviour is
unchanged and the diff is provably a refactor.

**Then add the properties every engine must share.** The three the contract
checks today (empty prepare, validate, concurrency) are the least of what
Cedar proved individually; the rest live in `cedar/evaluate_test.go` where no
other engine can reach them. Move the engine-independent ones up:

- An `AllowAll` policy yields exactly one verdict with `EffectAllow`; `DenyAll`
  yields exactly one with `EffectDeny`.
- Every verdict carries `Source == engine.Language()` and the `PolicyID` of the
  `StoredPolicy` that produced it — not a name, not an index. Audit provenance
  depends on this and it is the field most easily got wrong.
- `Priority` round-trips from `StoredPolicy` into the verdict, and **changing
  only the priorities of a policy set does not change the verdicts** — same
  effects, same order, same count. Spec Y7 makes priority provenance-only and
  this is the guard that keeps it so per engine.
- `Prepare` on malformed text fails with a message naming the offending
  policy's ID. An engine that reports "parse error" without saying which of a
  tenant's forty policies broke is unusable at the PAP.

**Do not** move Cedar's context-mapping tests (agent trust tier, classification
caps). Those are about one engine's mapping choices and belong where they are.

**Prove the contract bites.** For each property added, mutate a copy of the
Cedar engine so it violates that property and confirm the contract fails —
report the list. A contract nobody has seen fail is a contract nobody has
tested. Specifically include: `Source` hardcoded to `"cedar"` in an engine
whose `Language()` returns something else, and a `Prepare` that sorts by
priority.

---

## Task 2 — The multi-engine seam

**Files:** `services/internal/store/policy.go`,
`services/internal/policy/multi.go` (new), `services/internal/pdpgrpc/`, and
their tests.

**Store.** Add a sibling to `LoadPolicies` that loads every enabled policy for
the tenant regardless of language, ordered by id. A separate exported method,
not a magic empty-string language — the existing per-language query keeps its
callers and its tests, and an empty string that silently means "everything" is
the kind of overload that reads as a bug at 3am.

Both queries share the scan loop. **No `WHERE tenant_id`** — RLS is the only
tenant boundary, as everywhere else, and the existing query's test that pins
this applies to the new one too.

**The multiplexer.**

```go
// Registry maps policies.language to the engine that evaluates it.
type Registry map[string]PolicyEngine

// Multi evaluates a tenant's policies across every registered engine. It
// satisfies PrincipalPolicy for Decide.
type Multi struct { ... }

func NewMulti(source PolicySource, engines Registry) Multi

// PrepareAll groups the tenant's policies by language, prepares each group
// with its engine, and returns a CompiledPolicySet spanning all of them. The
// delegation-creation gate uses this; Evaluate uses it too.
func (m Multi) PrepareAll(ctx context.Context) (CompiledPolicySet, error)
```

The returned set **satisfies `CompiledPolicySet`**, so `policy.Probe` and the
delegation gate consume it with no signature change: `Evaluate` runs each
sub-set and concatenates the verdicts.

**The rules, each with its own test:**

- A language with policies and a registered engine evaluates normally.
- A language with policies and **no** registered engine yields one deny verdict
  naming the language and the policy IDs it could not evaluate. Never skipped.
  This is D10 and it is the reason this task exists.
- A registered engine with no policies contributes nothing — not a deny. It has
  no opinion, which is different from denying, and `FoldVerdicts`' default-deny
  covers the case where nothing at all matched.
- Zero policies in any language keeps `configured`'s existing single deny,
  "no policies configured for this tenant". Drop the language from that string;
  it is no longer one language's absence.
- One engine failing to prepare or evaluate denies with a reason naming that
  language, and **does not suppress the other engines' verdicts**. A Rego
  outage must not turn a Cedar forbid into silence — deny-overrides means the
  extra deny is harmless and the lost forbid would not be.
- Verdict order is deterministic across calls: languages in sorted order,
  policies by id within a language. The fold is order-independent by design,
  but a non-deterministic audit reason string is untestable and unexplainable.

**Retire the duplicated load-and-prepare at `pdpgrpc/delegation.go:222-228`.**
It exists because the gate needed a compiled set and `configured` did not
expose one. `PrepareAll` is that, so the gate calls it and the single-language
assumption disappears from `pdpgrpc` entirely rather than being fixed twice.
`NewServer` should end up with fewer parameters, not more: `policySource` and
`policyEngine` collapse into the `Multi` that `principalPolicy` already is.

**The no-allow AST guard must keep passing.** `NewMulti` is a new exported
constructor in `package policy`; `TestNoExportedConstructorAllows` will see it.
Confirm it cannot return an unconditional allow, and that the guard still bites
(add an `AllowAll`, confirm it is named, remove it).

---

## Task 3 — The Rego engine

**Files:** `services/internal/policy/rego/` and its tests. Add
`github.com/open-policy-agent/opa` (the predecessor used v1.0.0; use the
current release and record which).

Rego is second because OPA is the most widely deployed of the three and its
Go API already separates compilation from evaluation, which is the shape
`PolicyEngine` was designed around.

`Prepare` compiles each policy with `rego.New(...).PrepareForEval` **once** and
stores the `PreparedEvalQuery`. The predecessor called `PrepareForEval` inside
`Evaluate`, once per policy per decision — that is spec defect D5 named
explicitly, and this task exists partly to not repeat it.

**The query convention, and record it in the package doc:** each policy is a
module whose package is `stratium.policy`, and the engine evaluates
`data.stratium.policy.allow` and `data.stratium.policy.deny` as boolean rules.
A policy defining neither did not match and yields no verdict. A policy
defining both with both true yields a deny — deny-overrides, consistent with
the fold, decided in the engine only because a single policy has produced two
contradictory answers and the engine is the only place that knows.

**The input document** is `EvaluationInput` mapped to plain JSON, with the
agent and delegation dimensions under `input.agent` and `input.delegation` so a
tenant can write Y3's "deny Unverified agents on financial tools". Mirror
Cedar's naming exactly — `trust_tier`, `max_action_tier`, `classification_caps`
— so a rule reads the same in both languages. Record any place the two
deliberately diverge.

**Tests:** `policytest.EngineContract` with Rego fixtures, plus agent trust tier
driving a deny, classification caps likewise, a module with a syntax error
failing `Prepare` with its ID in the message, and a policy defining neither
rule yielding no verdict.

**Mutation-test and report survivors:** move `PrepareForEval` into `Evaluate`
(the D5 regression — confirm a benchmark or a call-count assertion catches it,
because no behavioural test will); make an undefined `deny` yield an allow
verdict rather than no verdict.

---

## Task 4 — The JSON engine

**Files:** `services/internal/policy/jsonpolicy/` and its tests. No new
dependency — `encoding/json` and nothing else.

**This is a house DSL, so the plan defines it and the code does not get to
improvise.** The schema, complete:

```json
{
  "effect": "allow" | "deny",
  "match": {
    "subject":      {"attr": "department", "equals": "finance"},
    "tool":         {"in": ["Read", "Grep"]},
    "derived_tier": {"at_most": 2},
    "agent":        {"attr": "trust_tier", "equals": "Verified"},
    "delegation":   {"attr": "purpose", "equals": "quarterly-close"}
  }
}
```

- Every key inside `match` is ANDed. An absent key is not a constraint.
- An empty `match` object matches everything. `match` itself being absent is a
  **validation error**, not a match-all: a policy that matches everything must
  say so, because the difference between "I meant to match everything" and "I
  forgot the match block" is the difference between a working rule and an
  outage.
- The three operators are `equals` (exact string), `in` (membership), and
  `at_most` (integer ceiling, for tiers only). No wildcards, no regex, no
  ranges. Every one of those is a place a widening can hide, and the JSON
  engine exists for tenants who want auditability over expressiveness.
- Unknown keys anywhere fail `Validate`. A typo'd constraint that silently
  matches everything is the worst failure this engine could have.

`Prepare` unmarshals and validates each policy once into an evaluable struct;
`Evaluate` walks the struct. No `json.Unmarshal` in `Evaluate`.

**Tests:** `policytest.EngineContract` with JSON fixtures; each operator
matching and not matching; an empty `match` matching; a missing `match`
rejected by `Validate`; an unknown operator rejected; an unknown top-level key
rejected; and `at_most` on a non-integer rejected at `Prepare` rather than
silently failing to match at evaluation.

**Mutation-test and report survivors:** make a missing `match` match everything;
make an unknown key ignored; make `at_most` compare as a string.

---

## Task 5 — The XACML engine

**Files:** `services/internal/policy/xacml/` and its tests. `encoding/xml`, no
new dependency.

**Full XACML 3.0 is out of scope and the plan says so explicitly**, because the
alternative is an implementer discovering that halfway through. The supported
subset, and `Validate` must reject anything outside it with a message saying
which construct is unsupported — never accept-and-ignore:

- One `<Policy>` per stored row, with `RuleCombiningAlgId` of
  `deny-overrides` only. Any other algorithm is rejected: permit-overrides
  inside a policy would let one rule's permit mask another's deny, which
  contradicts the system's own fold and is exactly the kind of local
  combining rule this design has removed everywhere else.
- `<Target>` with `<AnyOf>`/`<AllOf>`/`<Match>` over the attribute designators
  listed below. String equality only.
- `<Rule Effect="Permit|Deny">` with an optional `<Target>`. No `<Condition>`,
  no functions, no obligations, no advice, no policy sets, no references.
- Attribute designators map onto `EvaluationInput`:
  `subject-id` and any principal attribute; `resource-id` and any resource
  attribute; `action-id` (the tool); and the Stratium-specific
  `agent-trust-tier`, `delegation-purpose`, `delegation-max-tier`, and
  `derived-tier`. Document the full list in the package doc — it is the
  engine's public surface.

An `<Indeterminate>` outcome — an unresolvable designator — yields a **deny**
verdict, not a skip. XACML's own spec leaves indeterminate handling to the
combining algorithm; deny is the only reading consistent with this system's
fail-closed posture, and it must be a deliberate, tested choice rather than a
fall-through.

**Tests:** `policytest.EngineContract` with XACML fixtures; a permit rule
matching; a deny rule matching; a non-matching target yielding no verdict; each
unsupported construct rejected by `Validate` **with its name in the message**;
a non-`deny-overrides` combining algorithm rejected; malformed XML failing
`Prepare` with the policy ID; and an unresolvable designator denying.

**Mutation-test and report survivors:** make an unsupported construct
accept-and-ignore; make indeterminate skip rather than deny; accept
permit-overrides.

---

## Task 6 — Wire, prove, and measure

**Files:** `services/cmd/stratium-pdp/main.go`, `services/internal/config/`,
the integration suite.

**Configuration.** The engine set is a deployment property: a config value
listing enabled languages, defaulting to all four. `main.go` builds the
`Registry` from it and passes one `Multi` where it passes `cedar.New()` today.
A language named in config that has no implementation is a **startup failure**,
not a warning — the same fail-fast rule the PDP already applies to required
config with no default.

**Prove end to end against a live stack**, extending the integration suite:

1. A tenant with a Cedar permit and a Rego forbid on the same request denies,
   with the audit row attributing it to `rego` — the merge working, and
   deny-overrides holding across engines.
2. A tenant with policies in all four languages produces four verdicts, each
   with the right `Source` and `PolicyID`.
3. **A policy in a language absent from the registry denies**, naming that
   language. This is D10's proof and the reason for the whole seam; assert the
   reason string, not merely the effect.
4. One engine failing does not suppress another's verdicts — seed a malformed
   XACML policy alongside a valid Cedar forbid and confirm both appear.
5. The delegation-creation clamp and a later `Decide` agree, now that both
   consult every language: a Rego policy restricting a tool clamps the
   delegation, where today only Cedar would.
6. Cross-tenant isolation still holds with multiple languages in play — a
   second tenant's policies never appear in the first tenant's verdicts.

**Measure and report the numbers**, against Phase 2c's Cedar-only baseline:

1. `Prepare` cost per engine for 1, 10, and 100 policies.
2. `Evaluate` cost against an already-prepared set, same sizes.
3. End-to-end decision latency with all four engines in the path, versus
   Phase 1c's ~2.5 ms and Phase 2c's Cedar-only figure. This is the number that
   says whether per-call preparation is still affordable now that it happens
   once per language, and it is the input to the caching decision Phase 2c
   deliberately deferred.
4. Concurrency unchanged: ten concurrent calls, one tenant, still 10/0.

**Then re-check the conformance tally.** No property in this phase's scope is
currently skipped for engine reasons, so it should stay 25 executed / 14 pass /
11 skip (and become 15/10 if C19 converts below). Report it either way; a number that moves unexpectedly is a finding.

**Also unskip C19 while here.** It reads "Phase 3: requires the PEP client",
but the PEP client shipped in Phase 3a and `cmd/stratium-pep/hook_test.go:174`
already proves unreachable-PDP-denies. Confirm that is what C19 asks for before
converting it — if the property is subtly different, say so and leave it
skipped with a corrected reason rather than forcing a pass.
