# Phase 2c — The first policy engine (Cedar)

Implements spec §3.3 **Y1** (Cedar as one of four engines), **Y2** (`Prepare()`
on the interface), and **Y3** (agent and delegation dimensions in the
evaluation input). Five tasks.

**Scope.** Cedar only. The other three engines follow in a later plan, against
the contract this one establishes. Reference implementation, not to be copied
blind: `~/Development/stratium/go/pkg/policy_engine/cedar_engine.go` (141
lines) and `~/Development/stratium/go/pkg/cedar/{mappers,entity_resolver}.go`.
That code targets the old 4-tuple input and predates the agent dimension.

**Caching is deliberately out of scope.** `Prepare()` is in the interface from
the start, so adding a cache later does not reshape it — but Task 5 measures
the real compile-versus-evaluate cost first. Designing a cache around a guessed
ratio is how the wrong thing gets optimised. When it lands, the key is the
tenant's row in `tenant_epoch`, which is already bumped on any policy change
(§4.8) — one invalidation mechanism for both the decision cache and compiled
policy sets.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- `internal/authz` stays pure. The engine lives in `internal/policy`, which may
  import `authz` for its types; `authz` must never import `policy`.
- **Policy may only narrow.** An engine returning ALLOW cannot widen anything,
  because the three legs are independent AND terms and the delegation leg is
  evaluated separately. Nothing in this plan may add a path by which a policy
  verdict raises a ceiling. If an implementation seems to need one, stop.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — `EvaluationInput` with the agent and delegation dimensions

**Files:** `services/internal/policy/input.go` and its test; the
`PrincipalPolicy` interface and `Unconfigured`; `internal/pdpgrpc/server.go`.

Spec defect **D6** was that the old `EvaluationInput` — Subject, Resource,
Action, Environment — had no agent or delegation dimension, which is the
structural reason the agent path could never call the engines.

```go
// EvaluationInput is what every engine receives. It carries the agent and
// delegation dimensions so a tenant can write "deny Unverified agents on
// financial tools" in their own policy language (spec Y3).
//
// Seeing these dimensions does not let a policy widen anything: the agent and
// delegation legs are evaluated separately as independent AND terms, so an
// ALLOW here can only ever be one of three required yeses.
type EvaluationInput struct {
	Principal   authz.Principal
	Action      authz.Action
	DerivedTier models.ActionTier
	Resource    map[string]string
	Environment map[string]string

	Agent      authz.AgentInfo
	Delegation DelegationContext
}

// DelegationContext is the acting delegation reduced to what a policy may
// reasonably condition on. It is not the delegation itself: no identifiers
// that would let a policy pin to one grant, and no fields the delegation leg
// already enforces structurally.
type DelegationContext struct {
	Depth              int
	MaxActionTier      models.ActionTier
	ClassificationCaps map[string]string
	Purpose            string
}
```

`PrincipalPolicy.Evaluate` takes an `EvaluationInput` instead of loose
arguments. `Unconfigured` ignores it and still returns its single deny verdict.

**Tests.** That the input carries every dimension; that `Unconfigured` still
returns exactly one deny verdict with the unchanged reason; and that the
existing no-allow AST guard still passes and still bites (add an `AllowAll`,
confirm it is named, remove it).

---

## Task 2 — The engine interface

**Files:** `services/internal/policy/engine.go` and its test.

```go
// PolicyEngine compiles policy text. Compilation is separate from evaluation
// because spec defect D5 was engines recompiling on every request: the old
// system called rego.New + PrepareForEval and Cedar's NewPolicySetFromBytes
// inside Evaluate, once per policy per decision.
type PolicyEngine interface {
	// Language is the value stored in policies.language.
	Language() string

	// Prepare compiles a tenant's policy set once. The returned value is safe
	// for concurrent use by many evaluations.
	Prepare(ctx context.Context, policies []StoredPolicy) (CompiledPolicySet, error)

	// Validate checks policy text without persisting or evaluating it, for the
	// PAP's authoring path.
	Validate(ctx context.Context, text string) error
}

// CompiledPolicySet evaluates a prepared set. Implementations must be
// goroutine-safe: one compiled set serves every concurrent decision for a
// tenant.
type CompiledPolicySet interface {
	Evaluate(ctx context.Context, in EvaluationInput) ([]authz.PolicyVerdict, error)
}

// StoredPolicy is one row of the policies table.
type StoredPolicy struct {
	ID       string
	Name     string
	Language string
	Text     string
	Effect   string // "allow" | "deny"
	Priority int
	Version  int64
}
```

**Where the contract lives.** Put `EngineContract` in a small
`services/internal/policy/policytest` package, in a **non-test** file. A
contract defined in `engine_test.go` is reachable only from test files inside
`package policy` itself — Go excludes `_test.go` files from what other packages
may import — so Cedar in a subpackage could not call it, and every engine would
end up writing its own tests. That is precisely the drift a shared contract
exists to prevent. The `httptest` package is the same pattern for the same
reason.

**Tests** are contract tests a later engine can reuse: a nil/empty policy list
prepares to a set that evaluates to zero verdicts (not an error — no policies
means nothing to say, and default-deny handles it downstream); `Validate`
rejects malformed text; and a prepared set is safe under concurrent
`Evaluate` (run it under `-race` from many goroutines).

---

## Task 3 — Tenant-scoped policy loading

**Files:** `services/internal/store/policy.go` and its test.

`func (s *Store) LoadPolicies(ctx context.Context, language string) ([]policy.StoredPolicy, error)`

Same discipline as every other store method: a transaction that sets
`app.tenant_id` first, no `WHERE tenant_id` in the Go query, RLS does the
isolation. Return only `enabled = true` rows. Order by `id` so the compiled set
is deterministic across calls — an unordered load makes a compiled set's
identity unstable and any future cache key meaningless.

**Tests** with sqlmock: tenant is set before the SELECT (ordered
expectations); disabled policies are excluded; results are ordered; an empty
result is not an error.

---

## Task 4 — The Cedar engine

**Files:** `services/internal/policy/cedar/` and its tests, which must run
against `policytest.EngineContract` rather than reimplementing it. Add
`github.com/cedar-policy/cedar-go` (the old repo used v1.6.0; use the current
release and record which).

Cedar is first because it is native Go with no CGO, it is typed and
statically analysable, and its template model maps closely onto scoped
delegation.

`Prepare` parses all policy texts into one `cedar.PolicySet`. `Evaluate` maps
the input to a Cedar request and returns one `PolicyVerdict` per policy that
matched, with `Source: "cedar"`, the policy's ID, and its priority recorded but
not acted on.

**Mapping.** Principal and resource become entities; the action becomes an
action UID; **agent and delegation become context attributes**, not entities.
Context is sufficient for the rules Y3 describes ("deny Unverified agents on
financial tools") and avoids inventing an entity hierarchy nothing needs yet.
Record that choice in the package doc so a later engine follows it or
deliberately diverges.

**Tests.** A permit policy yields an allow verdict; a forbid policy yields a
deny; a policy that does not match yields no verdict; agent trust tier is
readable from context and can drive a forbid; classification caps likewise; a
malformed policy fails `Prepare` with a message naming the policy; and
`Evaluate` never returns a verdict that widens anything — assert that no code
path produces a verdict able to raise a tier or add a tool, which is a
structural claim about the return type rather than a behavioural test.

---

## Task 5 — Wire it in, and measure

**Files:** the policy provider, `internal/pdpgrpc/server.go`, the integration
suite.

Add a provider that loads the tenant's Cedar policies, prepares them, and
evaluates. `Unconfigured` remains for a deployment with no policies configured;
**the no-allow AST guard must keep passing**, so the new provider needs wiring
into the constructor map with a test proving it cannot return an unconditional
allow.

**Measure, and report the numbers:**

1. `Prepare` cost for 1, 10, and 100 policies.
2. `Evaluate` cost against an already-prepared set, same sizes.
3. The ratio. This is the number that justifies or deflates the compiled-set
   cache, and it is the reason caching is not in this plan.
4. End-to-end decision latency with Cedar in the path, against the Phase 1c
   baseline of ~2.5 ms per call.
5. Concurrency unchanged: ten concurrent calls, one tenant, still 10/0.

**Also verify end to end:** a Cedar permit policy for a principal produces an
ALLOW on the principal leg — **the first ALLOW this system has ever been able
to produce** — and the audit row records `source: "cedar"` and the policy ID.
Then confirm the compound decision still denies when the delegation leg denies,
proving an allowing policy cannot exceed the ceiling.
