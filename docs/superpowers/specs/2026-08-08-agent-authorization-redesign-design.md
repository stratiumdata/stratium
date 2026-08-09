# Agent Authorization Platform — Ground-Up Redesign Design Spec

- **Date:** 2026-08-08
- **Status:** Approved for implementation planning
- **Scope:** Whole-system redesign. Stratium becomes a multi-tenant AI agent authorization platform; ZTDF is removed.
- **Owner:** Stratium
- **Supersedes:** the ZTDF-centric architecture described in `docs/CODEMAPS/architecture.md`

---

## 1. Context

Stratium began as a ZTDF/ABAC cryptographic platform (Platform PDP, Key Manager, KAS, PAP) and over
roughly two months pivoted into AI agent authorization (Agent Gateway, delegation chains, trust
tiers, DPoP, AAuth interop, Envoy ext-authz, MCP server). The agent layer was built *beside* the
original system rather than *through* it.

A full read of the codebase found the consequences of that:

**Three independent agent-authorization decision engines**, each with its own trust-tier and
classification logic:

- `go/services/platform/agent_auth.go` — `evaluateCompoundDecision`, `requiredTrustTierForAction`
- `go/services/agent-gateway/server.go:829` — `evaluateChainAuthorization`, `requiredTrustTier`
- `go/pkg/security/aauthengine/engine.go` — `Evaluate`, `agentTierCeiling`, `ClassificationDecision`

**Four client-side action classifiers** in four languages, on the untrusted side of the boundary:

- `demos/mcp/hooks/pre-tool-use.sh` (bash regex)
- `sdk/claude-hooks/src/tier-map.js` (JS map + CLAUDE.md overrides)
- `demos/codex/hooks/stratium_pre_tool_use.py` (Python `classify_command`)
- `go/internal/catalog/tier.go` (self-documented as a mirror of the gateway's copy)

**Four enforcement surfaces routing to three different decision implementations.** The Codex hook
calls PAP REST; everything else calls the gateway; the Envoy filter evaluates in-process.

### 1.1 The load-bearing defects

These are the findings the redesign exists to fix. Each is verified in the current code.

| # | Defect | Evidence |
|---|---|---|
| D1 | **Action tier is client-declared and trusted.** `ExecuteAction` reads `req.ActionTier` off the wire and feeds it to both gates. The server's own classifier `assessActionTier` is called *only* from `ValidateActionPlan`, a separate optional RPC. A hook reporting `action_tier: 1` for `rm -rf /` is authorized as tier 1. | `server.go:882`, `server.go:896`, `server.go:465`, `server.go:968` |
| D2 | **The principal leg never runs.** `InternalCompoundDecisionResult.UserDecision` is declared and read but never assigned. Every `ExecuteAction` response carries `user_decision: DECISION_UNSPECIFIED`. The advertised `principal ∧ agent ∧ delegation` is actually `agent ∧ delegation`. | `types.go:47`, `server.go:919`, `server.go:829` |
| D3 | **Delegation scope is unbounded by the principal's own authority.** `CreateDelegation` evaluates no policy. Any authenticated user can mint a delegation granting `max_action_tier: DESTRUCTIVE`, all tools, any classification cap. This is the privilege amplification the product claims to prevent. | `server.go:76-175`, `pap/delegation_handlers.go` |
| D4 | **Audit is not evidence.** `recordAudit` logs a warning on failure and the action proceeds. One mutable table, `GRANT ALL` to the application's own DB role. No hash chain, no signatures, no append-only enforcement. | `server.go:620`, `deployment/postgres/01-init-multiple-dbs.sh:14` |
| D5 | **Policy engines recompile on every evaluation.** `rego.New(...)` + `PrepareForEval(ctx)` inside `Evaluate()`; `NewPolicySetFromBytes(...)` inside Cedar's `Evaluate()`. `pdp.evaluatePolicies` loops the policy set, so it is M compilations per decision. | `opa_engine.go:27-33`, `cedar_engine.go:40`, `pdp.go:224` |
| D6 | **`EvaluationInput` cannot express agent context.** The Subject/Resource/Action/Environment 4-tuple has no agent or delegation dimension, which is the structural reason the agent path cannot call the engines. | `policy_engine/engine.go:22` |
| D7 | **No CI.** No pipeline of any kind. Prior review found a logger data race and TOCTOU races in provider code; nothing gates a merge. | no `.github/` |
| D8 | **Live credential in git.** `[REDACTED-old-RDS-password]` plus the RDS hostname, committed since the first commit (~9 months). Flagged as CRITICAL-1 in `docs/project-review.md`, unremediated. | `deployment/helm/stratium/values-rds.yaml:17,27,41` |

### 1.2 Relationship to the patent

The provisional (`docs/patent/`) is **intellectual property, not an architectural specification**.
Its component list (Fig. 1, elements 102–120) is not a build checklist, and "task" in the claim
language is generic patent-ese for an agent taking an action — not a domain object to be modelled.

The patent's *principles* do inform the design, because they describe the same system: compound
principal ∧ agent ∧ delegation decisioning, short-lived scoped artifacts, monotonic narrowing on
delegation, cascade revocation, and provenance from approval to action.

**No work is scheduled solely to support a claim.** Where a claimed element is also good
engineering (scope clamping, tamper-evident provenance), it is in scope on its own merits.

---

## 2. Scope

### 2.1 In scope

- Remove ZTDF entirely (~52k LOC, two services, two SDKs, one database).
- Collapse three decision engines and four client-side classifiers into one central PDP.
- Build the missing principal leg and the delegation-creation policy gate.
- Server-side action-tier derivation with raise-only tenant overrides.
- Full multi-tenancy enforced at the data layer.
- Hash-chained, append-only audit with crypto-shreddable inputs.
- Decision caching with per-tenant revocation epochs.
- Prepared/compiled policy sets across all four engines.
- CI with authorization conformance tests as a merge gate.

### 2.2 Out of scope

- ZTDF, KAS, Key Manager, HSM/PKCS#11, YubiKey/PIV, FIPS 140-3 mode, Kyber post-quantum.
  Preserved in an archive tag; may return as a separate product.
- AAuth-specific semantics (mission model, `aauth:local@domain` identity mapping).
  RFC 9421 HTTP Message Signatures and DPoP proof-of-possession are retained as durable
  OAuth/JWT primitives, independent of the AAuth draft.
- A risk engine, contextual risk scoring, and dynamic in-flight narrowing (patent claims 9–10).
  Not built; not scheduled.
- The `modify` decision outcome. `escalate` is in scope; `modify` is not.

---

## 3. Decision record

Every decision below was made explicitly during design. Recorded so implementation does not
relitigate them.

### 3.1 Product and strategy

| # | Decision |
|---|---|
| P1 | AI agent authorization is the product. ZTDF moves to the backlog, unimplemented. |
| P2 | **Superseded 2026-08-08 (see §3.7).** Originally: ZTDF deleted from main, preserved in an archive tag. The build is greenfield in a new repository instead, so there is nothing to delete. |
| P3 | The patent is IP; architecture is designed independently. |
| P4 | Stratium **replaces** the customer's PDP. It does not compose with an existing one. |
| P5 | Commercial model is a **hosted tier plus self-hosted enterprise**. |
| P6 | AAuth: keep RFC 9421 signature verification and DPoP; drop AAuth-specific semantics. |

### 3.2 Architecture

| # | Decision |
|---|---|
| A1 | **One remote PDP; all enforcement surfaces are network clients.** No decision logic outside the PDP. |
| A2 | Four enforcement surfaces are all first-class and all retained: gRPC proxy, MCP, hooks, Envoy ext-authz. |
| A3 | Three artifacts: `stratium-pdp`, `stratium-pap`, `stratium-pep`. |
| A4 | The PDP decides **and** issues tokens. One signing-key holder. |
| A5 | The PAP is admin-only: policy, entitlement, agent, and override CRUD; UI backend; JWKS. |
| A6 | `stratium-pep` is one distributable binary with four modes: `hook`, `mcp`, `extauthz`, `proxy`. |
| A7 | Fail **closed** everywhere when the PDP is unreachable. |
| A8 | Short-lived signed decision cache at the PEP, invalidated by a per-tenant revocation epoch. |
| A9 | Identity is **standard OIDC, bring your own IdP**. Keycloak and the unverified-JWT fallback are removed. |

### 3.3 Policy

| # | Decision |
|---|---|
| Y1 | Keep all four engines: OPA/Rego, Cedar, XACML, JSON. Migration breadth is the displacement story. |
| Y2 | Add `Prepare()` to the `PolicyEngine` interface; cache compiled sets by `(tenant, policy_version)`. |
| Y3 | Extend the evaluation input with agent and delegation dimensions; all four engines can see them. |
| Y4 | Policy gate at delegation creation. **Clamp** to the user's held authority; return the granted scope. |
| Y5 | Per-action principal evaluation against the concrete resource. |
| Y6 | Keep both grant models: entitlements are the simple path, policies the expressive one. |
| Y7 | Combining is **deny-overrides with default-deny**. Priority is no longer security-relevant. |
| Y8 | Decision outcomes: **allow, deny, escalate**. |
| Y9 | Client artifacts: PEP binary, Go and Python SDKs, admin UI, and a Cedar/Rego authoring experience. |

### 3.4 Enforcement semantics

| # | Decision |
|---|---|
| E1 | Action tier is derived **server-side** from raw tool input. |
| E2 | Tier tables are built-in defaults plus **raise-only** tenant overrides. Applies to the `action → tier` table (explicitly decided) and, by extension, to the `actionTier → requiredTrustTier` table (§4.3 — derived, same category, open to reversal). |
| E3 | A client-declared tier is cross-checked; **declared lower than actual denies**. Over-declaration is allowed. |
| E4 | Escalation is approved by the **delegating principal**; the agent blocks with a timeout; timeout denies. |
| E5 | On non-blocking surfaces (Envoy), escalate degrades to **deny plus a pending approval record**. |

### 3.5 Data

| # | Decision |
|---|---|
| D1 | **Full tenancy on every table**, enforced at the data layer, not by convention. |
| D2 | Audit is **hash-chained and append-only**; the audit DB role holds INSERT only. |
| D3 | **A failed audit write denies the action.** |
| D4 | The chain stores digests; raw inputs are encrypted per tenant so erasure crypto-shreds content. |
| D5 | Migrations via **golang-migrate**, embedded in the binary. |

### 3.6 Execution

| # | Decision |
|---|---|
| X1 | **Superseded 2026-08-08 (see §3.7).** Originally: new package tree alongside the old, cut over surface by surface. Greenfield removes the cutover entirely. |
| X2 | **Foundation first**: CI, tenancy schema, migrations, decision core. |
| X3 | Nothing is live. Clean build, no data migration, no compatibility window. |
| X4 | CI blocks on build, test, vet, lint, secret scan, `-race`, and **authorization conformance tests**. |
| X5 | Observability compiles into all builds; **build tags** produce instrumented and non-instrumented artifacts. |
| X6 | No external deadline. Sequence by technical dependency. |

### 3.7 Greenfield amendment (2026-08-08)

Decided after §3.1–§3.6, during execution planning. Supersedes P2 and X1.

| # | Decision |
|---|---|
| G1 | The system is built **greenfield in a new repository** at `~/Development/stratium-data`, not by refactoring the existing one. |
| G2 | `~/Development/stratium` is **left untouched** as the reference archive. No deletion, no archive tag — the repository *is* the archive. Its RDS credential still requires rotation (§5.6), independent of this build. |
| G3 | Layout is a **monorepo with an explicit Go workspace**: `go.work` at the root, `services/` holding the Go module, and `clients/`, `deploy/`, `proto/`, `docs/` alongside. |
| G4 | Module path stays **`stratium`**. |
| G5 | Domain types are **rewritten fresh**, not ported. The old `pkg/models` and `pkg/classification` are reference material. Rewriting is what lets tenancy and the new decision vocabulary be structural rather than retrofitted. |

**What G5 costs, and the mitigation.** `classification.CheckCap` in the old repo encodes carefully reasoned fail-closed behavior — a resource classification declared without a hierarchy denies as ambiguous; an unknown level or cap denies rather than comparing as equal. Those rules are not obvious and were not free to arrive at. Rewriting must reproduce them deliberately, with a test per rule, rather than rediscovering them after a gap ships. The old implementation is the reference; the tests are the contract.

**What G1 changes downstream.** §5 below described deleting ~52k LOC from an existing tree. Under G1 nothing is deleted — that section becomes the list of what is *not carried forward*, and is retained for that purpose. Phase 0 in §9 reduces to credential rotation in the old repository plus scaffolding the new one.

---

## 3.8 Phase 2 design decisions (2026-08-09)

Two questions deferred from §3.1–§3.7 and resolved after Phase 1 shipped. Both
were deferred because they depend on shapes the policy-engine work defines, and
both are now settled because Phase 2 cannot start without them.

### G6 — Principal authority is probed, not materialized

The delegation-creation gate (C6) clamps a requested scope to what the
principal actually holds. There is no `Authority` type and no stored
representation of a principal's authority.

**Why not materialize it.** Entitlements are rows and can be enumerated:
"which entitlements match alice?" returns a set. Policies cannot. Cedar, Rego,
XACML, and JSON policies are *functions* — they answer "may alice do X?" and
have no general way to answer "what may alice do?" That is the ABAC
enumeration problem, and it has no solution that holds across all four
engines. A materialized authority built from entitlements alone would be
silently incomplete for any principal whose authority comes from a policy,
which for a product that replaces a customer's PDP is a real hole rather than
a corner case.

**The mechanism.** For each dimension of the *requested* scope — each tool,
the max action tier, each classification cap, each resource constraint — the
gate asks the policy set whether the principal may hold it. Whatever is denied
is dropped. The artifact is issued with the surviving intersection, and the
granted scope is returned to the caller (§3.3 Y4).

Cost scales with the size of the request, not the policy space, and delegation
creation is orders of magnitude rarer than per-action evaluation.

**The asymmetry, stated deliberately.** The creation gate asks a coarser
question than the runtime gate. At creation there is no concrete resource, so
the question is "may alice use `Bash` at all?" rather than "may alice run this
command against this resource?" The two are different queries over the same
policy set, and a principal can pass the coarse question and fail the fine one
at action time. That is correct — the artifact is a ceiling, not a promise —
but it means a clamp that succeeds does not imply any particular action will.

**Fail-closed rule.** A probe that errors or is inconclusive drops the
dimension. An unanswerable question is not a grant.

### G7 — The engines' verdicts are combined inside `Decide`

`Request.PrincipalDecision LegResult` is replaced by
`Request.PrincipalVerdicts []PolicyVerdict`, and `Decide` performs the
deny-overrides fold itself.

**Why.** Today the PDP folds four engines into a single `LegResult` before
calling `Decide`, which puts C12 — "any deny, in any policy language, at any
priority, overrides every allow" — half outside the audited core. The
combining algorithm is a security property, and every other security property
in this system lives in `internal/authz` where it is mutation-tested. A
property enforced in a package nothing mutates is a property nobody has
checked.

`authz` stays pure: a `PolicyVerdict` is plain data (engine, policy identifier,
priority, effect, reason), carrying no engine dependency.

**The fold, preserving both C12 and C13:**

1. any verdict denying → DENY
2. otherwise no verdict allowing → DENY (default-deny)
3. otherwise any verdict escalating → ESCALATE
4. otherwise → ALLOW

Step 2 is what keeps the zero value safe. `PrincipalDecision`'s zero value was
`EffectDeny`; a nil `[]PolicyVerdict` has no allow and therefore denies by the
same reasoning. The invariant that an unevaluated principal leg denies survives
the type change — and must be re-pinned by a test, because the mechanism
producing it is now different.

**Provenance follows.** Because the core sees each verdict, `Result` can record
which engine, policy, and priority decided, and the audit entry can carry it.

**Consequence for the audit chain.** `audit.Entry` gains at least one field for
provenance. `Hash()` covers every field and `TestHash_CoversEveryField` asserts
the mutation table's length against `reflect.TypeOf(Entry{}).NumField()` — so
adding a field will fail that test until the table and the serialization are
both updated. That is the guard working as designed; do not weaken the
assertion to accommodate the change.

---

## 4. Architecture

### 4.1 Artifacts

```
┌────────────────────────────────────────────────────────────┐
│  stratium-pep    (distributable — anywhere the action is)  │
│                                                             │
│   modes:  hook │ mcp │ extauthz │ proxy                    │
│   holds:  PDP client cert, decision cache, credentials      │
│   holds NO: policy, DB access, signing key, tier tables     │
└───────────────────────────┬────────────────────────────────┘
                            │  Decide(request) — the only call
                            ▼
┌────────────────────────────────────────────────────────────┐
│  stratium-pdp    (central — the only decider)              │
│                                                             │
│   • compound decision: principal ∧ agent ∧ delegation       │
│   • server-side action-tier derivation                      │
│   • four policy engines, prepared & cached                  │
│   • delegation issuance (sole signing-key holder)           │
│   • audit chain writes                                      │
└───────────────────────────┬────────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────────┐
│  PostgreSQL  — tenant-scoped, RLS-enforced                 │
└───────────────────────────┬────────────────────────────────┘
                            │
┌───────────────────────────┴────────────────────────────────┐
│  stratium-pap    (central — admin plane)                   │
│                                                             │
│   • policy / entitlement / agent / override CRUD            │
│   • authoring, validation, dry-run replay                   │
│   • UI backend, JWKS                                        │
└────────────────────────────────────────────────────────────┘
```

**The invariant that makes this safe:** the PEP holds cached *answers*, never decision *logic*.
The moment a PEP classifies, compares tiers, or evaluates scope, the drift problem returns. The
revocation epoch is what lets the edge be fast without being authoritative.

### 4.2 Why the PEP is separate

The current agent-gateway is already a PEP, not a PDP — `server.go:404` forwards the authorized
request to the target service via `proxy.Forward`. `ExecuteActionRequest` carries `target_service`,
`method`, and `payload` precisely so it can sit on the path between agent and target.

Distribution earns its keep:

- **Blast radius** — a compromised edge PEP yields a client cert and nothing else.
- **Latency** — colocate with the workload; only the decision crosses the network.
- **Network reality** — an agent in a segmented network reaches a local PEP when it cannot reach the PDP.
- **Already distributed** — a hook on a laptop is an edge PEP regardless of what it is called.
- **The proxy function requires it** — a central service cannot sit between an agent and its target.

### 4.3 The decision

```
allow = principal_allowed ∧ agent_allowed ∧ delegation_allowed
```

Each leg is an independent AND term. Because the structural legs are separate terms, a policy
returning ALLOW can never exceed the delegation artifact — the ceiling holds by construction.

#### Principal leg — policy-driven

Entitlement rows and policies in four languages, combined **deny-overrides with default-deny**:

1. Nothing is permitted unless something grants it — an entitlement or an allow-policy.
2. Any deny, in any language, at any priority, wins.

Priority ordering is retained for authoring ergonomics but has no security significance. This
removes the class of bug where adding a policy at the wrong priority silently changes outcomes.

#### Agent leg — structural, one policy knob

- `agent.TrustTier >= requiredTrustTier(actionTier)`
- `toolName ∈ agent.AllowedTools`

The comparison is compiled Go. The `actionTier → requiredTrustTier` **table** is data, subject to
the same raise-only tenant override mechanism as the action-tier table. Policies may add denials
on agent attributes; they may not grant.

#### Delegation leg — structural, non-configurable

- `actionTier <= delegation.MaxActionTier`
- `toolName ∈ delegation.ApprovedTools`
- classification caps satisfied for every hierarchy
- every delegation in the chain active (not expired, not revoked)
- chain depth within bound

Not policy-configurable, at any tenant, ever. This is the ceiling; if policy could raise it, the
signed artifact would mean nothing.

**Design rule, applied throughout:** *policy may only narrow, never widen.* If a careless or
malicious policy author could use a mechanism to **gain** authority, that mechanism is structural
and belongs in Go. If the worst they can do is lock themselves out, it is policy.

The same monotonicity appears three times: raise-only tier overrides, child ⊆ parent on delegation,
and policy-narrows-only.

### 4.4 Action-tier derivation

Resolution order, evaluated server-side:

```
1. tenant override for this tool/verb      (policy data, raise-only)
2. registered catalog entry                (signed at registration)
3. built-in classifier                     (today's assessActionTier)
4. unknown → configured default            (deny, or a floor tier)
```

The client may **declare** a tier. The PDP always re-derives. Declared > actual is permitted;
**declared < actual denies** and is recorded as a spoofing attempt. This is the semantic
`catalog.GuardTier` already implements and `ValidateActionPlan` already performs — it moves onto
the enforcement path.

Overrides are admin-role-gated, versioned, and audited on change. A tier override is never accepted
from an agent-writable source.

#### Residual risk: shell-command classification is a heuristic, not a boundary

Deriving a tier for a `Bash` action means classifying an arbitrary command string. That is
best-effort and cannot be made complete: an adversary who controls the text can always reach a
payload the matcher does not recognise — `echo <base64> | base64 -d | sh` is the trivial existence
proof. Known evasions found in review and since closed (quoted verbs, `${IFS}` in place of a space,
compound commands whose leading token looks benign, `DROP` on object types outside the original
alternation) are pinned by tests, but closing named holes does not make the class of attack go away.

Scoping the SQL keyword patterns to a SQL context traded one gap for another. Matching
`DROP`/`REVOKE`/`ALTER`/etc. unconditionally rated ordinary English as DESTRUCTIVE
(`git commit -m "revoke stale session tokens"`); requiring one of a fixed list of database CLIs
(`psql`, `mysql`, `sqlite3`, …) alongside the keyword closes that false positive but opens a
measured false-negative class: any tool that reaches a database without shelling out to one of the
recognised CLIs is invisible to this check. `python -c "db.execute('DROP TABLE users')"`,
`rails db:drop`, and any application-specific or custom CLI wrapping a driver all rate no higher
than INTERNAL_MODIFY. This is a larger surface than the base64-pipe-to-sh example above —
base64 obfuscation requires deliberate evasion, while an ORM call or a framework task is how
destructive SQL is *ordinarily* issued outside a terminal.

**This is stated so an evaluator learns the limit from us rather than discovering it.** The
controls that do carry weight are structural and not string-dependent: the delegation ceiling
(`max_action_tier`), the agent's tool allowlist, the classification caps, and escalation. A tenant
that considers shell access materially risky should withhold the `Bash` tool from the delegation
rather than rely on per-command tiering — and the tier tables let them raise its floor if they
grant it anyway.

`CheckDeclaredTier` does not mitigate this. It defends against a dishonest *client*, not an
incorrect *server* derivation, and escalation keys off the same derived tier — so it inherits the
blind spot rather than catching it. The existing `stratium.tool_tiers` block in `CLAUDE.md` may survive
as a *request* the server can honor; it is never a fact the client asserts.

### 4.5 Policy evaluation points

Two different questions at two different times.

**At delegation creation** — no resource exists yet, so the question is about the grant:

> May this user grant this agent this class of authority?

Policy evaluates `(principal, agent, requested_scope)`. The result **clamps** the artifact to the
intersection of requested and held authority. The response reports the granted scope so the agent
knows its real bounds rather than assuming it received what it asked for.

This is what makes the artifact a ceiling and closes D3.

**At every action** — the resource is concrete:

> May this principal perform this action on this resource?

Plus the agent and delegation legs. Re-evaluated per action because entitlements change, policies
change, and revocation must take effect immediately.

### 4.6 Engine interface

```go
type PolicyEngine interface {
    Prepare(ctx context.Context, policy *models.Policy) (CompiledPolicy, error)
    ValidatePolicy(ctx context.Context, content string, lang models.PolicyLanguage) error
    TestPolicy(ctx context.Context, content string, lang models.PolicyLanguage, in *EvaluationInput) (*EvaluationResult, error)
}

type CompiledPolicy interface {
    Evaluate(ctx context.Context, in *EvaluationInput) (*EvaluationResult, error)
}
```

The PDP holds compiled sets keyed by `(tenant, policy_version)`, pre-warmed at startup and on
policy change. `Evaluate` becomes lookup-and-run. This closes D5.

`EvaluationInput` gains agent and delegation dimensions, with a mapping per engine:

| Engine | Mapping |
|---|---|
| Cedar | agent and delegation as entities with attributes and parent relationships |
| Rego | additional keys under `input` |
| XACML | additional attribute categories |
| JSON | schema extension |

This closes D6.

### 4.7 Decision outcomes

| Outcome | Meaning |
|---|---|
| `ALLOW` | Proceed. Forward if in proxy mode. |
| `DENY` | Refuse. The response names which leg denied and, in a chain, at which depth. |
| `ESCALATE` | Human approval required before proceeding. |

**Escalation.** The **root principal** of the delegation chain approves — at depth > 0 the immediate
delegator is an agent, so approval routes to the human at the root, not the parent agent. Blocking
surfaces (`hook`, `mcp`, `proxy`) hold the call until approval or timeout; timeout denies.

Non-blocking surfaces (`extauthz`) cannot wait for a human — ext_authz timeouts are measured in
milliseconds. There, escalate degrades to a denial plus a pending approval record, so a retry after
approval succeeds. One decision semantic, per-surface delivery.

Escalation outcomes are never cached.

### 4.8 Caching and revocation

Cache-key granularity differs sharply by leg:

| Leg | Key | Hit rate |
|---|---|---|
| Agent | (agent, tool, tier) | high |
| Delegation | (delegation, tool, tier, resource class) | high |
| Principal | (user, action, **resource instance**) | near zero |

Caching therefore buys outage tolerance and speed on the structural legs; it does not avoid
per-action principal evaluation. The lever there is prepared policy sets and in-memory entity
resolution, not cache hits.

**Revocation epoch.** A monotonic per-tenant counter. Every cached decision records the epoch it was
computed under; a cache hit is valid only if the epochs match. Any revocation, agent suspension,
delegation expiry sweep, or policy change bumps the counter. One cheap read per action, instant
global invalidation.

This keeps "revoke root → cascade to all sub-delegations on the next action" literally true, which
a plain TTL would not — under a TTL, cache lifetime *is* revocation latency.

`pkg/cache` already carries the Redis pub/sub channel this needs; today it distributes policy
invalidations only.

### 4.9 Audit and provenance

Closes D4.

- **Hash-chained.** Each row carries the digest of its predecessor. Any edit or deletion is
  detectable by re-walking the chain.
- **Append-only.** The audit DB role holds `INSERT` only. The PDP's application role cannot
  `UPDATE` or `DELETE` audit rows.
- **Write-gated.** A failed audit write **denies the action**. This is an explicit availability
  trade: if the audit store is unavailable, authorization stops. It is the only posture under which
  completeness can be claimed.
- **Crypto-shreddable.** Server-side tier derivation requires the PDP to see raw tool inputs —
  shell commands, file paths, URLs, and whatever credentials happen to sit in arguments. Those
  cannot be written verbatim into an undeletable chain.

  The chain stores a **digest** of the full input. The plaintext is stored encrypted under a
  per-tenant key. Destroying the key renders the content unrecoverable while the chain remains
  verifiable — reconciling tamper-evidence with erasure obligations.

- **Tenant-scoped.** Every audit row carries a tenant; chains are per tenant.

The audit table is purpose-built for agent authorization. It is not the current shared table that
`04-init-agent-auth.sql` grew by dropping and re-adding CHECK constraints and bolting on seven
nullable columns.

### 4.10 Multi-tenancy

Every table carries a tenant. Isolation is enforced by the data layer — repository-level scoping
plus PostgreSQL row-level security — not by remembering a `WHERE` clause.

Today `tenant_id` exists only on `agents`, `delegations`, and Cedar namespaces. Policies,
entitlements, overrides, audit, and approvals all gain it.

Tenancy is foundational rather than incremental because retrofitting isolation into a security
product after it holds customer data is significantly harder, and because a hosted tier is in scope.

### 4.11 Identity

Standard OIDC. Stratium verifies tokens from whatever IdP the customer runs. No bundled IdP, and
**no fallback path** — the `MockValidateToken` / `jwt.ParseUnverified` fallback flagged as CRITICAL-2
is deleted, not gated.

Keycloak, its realm configuration, and the Java dependency leave the system.

The hosted tier's own signup identity and the demo environment's IdP are open items (§8).

---

## 5. What is not carried forward

> Under G1 this is an exclusion list, not a deletion list. Nothing is removed
> from `~/Development/stratium`; the sizes below record what the new build
> declines to bring across, and why.

### 5.1 ZTDF

| Component | LOC |
|---|---|
| `go/services/key-manager` | 36,849 |
| `go/services/key-access` | 7,158 |
| `go/pkg/ztdf` | 3,283 |
| `go/pkg/validators` | 4,357 — already dead, zero importers |
| `go/pkg/crypto` | 848 — already dead, zero importers |
| **Total** | **52,495** (~39% of the Go codebase) |

Also: `proto/models/ztdf.proto`, `proto/models/stanag4774.proto`,
`proto/services/key-{access,manager}`, the `stratium_keymanager` database,
`deployment/postgres/03-init-keymanager.sql`, HSM/PKCS#11, YubiKey/PIV, FIPS 140-3 mode, and
Kyber post-quantum support.

`go/pkg/classification` (253 LOC) **stays** — imported by the gateway, the PAP, and `aauthengine`.

> `pkg/validators` and `pkg/crypto` have no importer anywhere in the repo, including tests, `cmd/`,
> and the SDKs. The only reference is a comment at `models/delegation.go:157` noting the hierarchy
> matcher *should* be used. Between them they carry 3,364 lines of tests inflating coverage for code
> nothing calls.

### 5.2 Duplicated decision logic

- `go/services/platform/agent_auth.go`
- `evaluateChainAuthorization` / `evaluateAgentAuth` / `evaluateDelegationScope` in the gateway
- `pkg/security/aauthengine.Evaluate`'s decision path (signature verification is retained)
- `go/internal/catalog/tier.go`'s `AssessTier`

All replaced by one implementation in the PDP.

### 5.3 Client-side classifiers and hook implementations

- `demos/mcp/hooks/pre-tool-use.sh`
- `demos/codex/hooks/stratium_pre_tool_use.py` and `_dpop.py`
- `sdk/claude-hooks/` in its entirety, including `tier-map.js`, `scope-validator.js`,
  `claude-md-parser.js`, and the hand-rolled DPoP implementation

Replaced by `stratium-pep hook` plus per-agent shims of a few lines each. This consolidates DPoP
signing — currently implemented independently in Go, Python, and JavaScript — into one audited
implementation.

### 5.4 Dead SDKs

`sdk/java` and `sdk/js` contain zero agent-authorization code; they are pure ZTDF clients. Both are
deleted with the ZTDF archive. `sdk/go` and `sdk/python` retain their agent clients.

### 5.5 Other

- Keycloak realm configuration and dependency
- The `MockValidateToken` unverified-JWT fallback
- Customer-build variants that strip observability (replaced by build tags — §3.6 X5)
- `coverage_after.out`, `coverage_final.out`, `ka.out`, `pap.out`, and `terraform.tfstate`
  from git tracking
- The vendored Gin fork in `third_party/`, unless a specific reason to keep it is documented

### 5.6 Immediate security remediation (not a design decision)

Rotate `[REDACTED-old-RDS-password]`, audit RDS access logs, and scrub the credential from git history during
the archive-tag rewrite. It has been committed since the first commit.

---

## 6. What is built

### 6.1 Foundation (first)

1. **CI pipeline** — build, test, `go vet`, lint, secret scan, `-race`, conformance suite.
2. **Tenancy schema + `golang-migrate`** — every table tenant-scoped, RLS policies, embedded migrations.
3. **Audit chain** — hash-chained append-only table, INSERT-only role, per-tenant encryption keys.
4. **Decision core** — the single compound-decision implementation, pure and I/O-free, exhaustively
   unit-tested against the conformance properties.

### 6.2 PDP

5. Engine `Prepare()` across all four languages; compiled-set cache keyed by `(tenant, version)`.
6. Extended evaluation input with agent and delegation dimensions, mapped per engine.
7. Deny-overrides combining with default-deny.
8. Server-side action-tier derivation with the four-step resolution order.
9. Delegation-creation policy gate with scope clamping and granted-scope response.
10. Token issuance (sole signing-key holder), JWKS published by the PAP.
11. Escalation: pending-approval records, blocking wait with timeout, root-principal routing.

### 6.3 PEP

12. One binary, four modes. PDP client, decision cache with epoch validation, DPoP signing,
    credential storage. No decision logic.
13. Per-agent shims for Claude Code and Codex.

### 6.4 PAP

14. Policy, entitlement, agent, and tier-override CRUD, admin-gated and audited.
15. Authoring experience: validation, test-against-sample-input, dry-run replay against recorded
    decisions.
16. Admin UI (retained React/Vite/shadcn, re-scoped to agent authorization).

### 6.5 Retained from the current system

- RFC 9421 HTTP Message Signature verification (`pkg/security/aauthedge`, decision path removed)
- DPoP proof-of-possession (`pkg/security/dpop`) and the replay store
- ES256 token signing (`pkg/security/tokensign`) and JWKS
- `pkg/cedar` — schema manager, template manager, entity resolver, namespace manager, hierarchy
- `pkg/classification`
- Cascade revocation and `ScopeNarrows`
- OpenTelemetry instrumentation, Prometheus metrics

---

## 7. Conformance properties

These are the CI merge gate (X4). Each is a named test that must pass. They double as the
acceptance criteria for the redesign and as diligence evidence.

| ID | Property |
|---|---|
| C1 | A client-declared action tier lower than the server-derived tier is denied. |
| C2 | A client-declared tier higher than actual is permitted and recorded. |
| C3 | The server-derived tier is used for every gate; the declared value never reaches a comparison. |
| C4 | A tenant override may raise a tier; an attempt to lower one is rejected. |
| C5 | A tier override from an agent-writable source is never honored. |
| C6 | A delegation cannot be issued granting authority the principal does not hold; the artifact is clamped and the granted scope returned. |
| C7 | A child delegation cannot widen any dimension of its parent: tools, actions, tier, caps, resources, expiry. |
| C8 | Chain depth beyond the configured maximum is refused. |
| C9 | Revoking a root delegation denies the next action on every descendant, with no TTL delay. |
| C10 | A suspended or disabled agent is denied on the next action, even mid-session. |
| C11 | All three legs are evaluated; a response never carries an unspecified leg decision. |
| C12 | Any deny, in any policy language, at any priority, overrides every allow. |
| C13 | With no grant present, the decision is deny. |
| C14 | A policy cannot grant beyond the delegation artifact's ceiling. |
| C15 | The audit chain verifies end to end; a mutated row is detected. |
| C16 | An action whose audit write fails is denied. |
| C17 | Crypto-shredding a tenant's key renders inputs unrecoverable while the chain still verifies. |
| C18 | A cross-tenant read is impossible at the data layer, not merely absent from queries. |
| C19 | With the PDP unreachable and no valid cache entry, every surface denies. |
| C20 | A cache entry from a superseded revocation epoch is never served. |
| C21 | Escalation routes to the root principal, not an intermediate agent. |
| C22 | Escalation timeout denies. |
| C23 | On a non-blocking surface, escalate returns deny plus a pending record. |
| C24 | An expired delegation token is denied even if a cache entry exists. |
| C25 | A delegation token without a valid DPoP proof is denied when the token is sender-constrained. |

---

## 8. Open items

Decided during implementation unless raised sooner.

| Item | Note |
|---|---|
| Go version | Currently `go 1.25` in `go.mod`. Confirm and pin. |
| Package layout | The new tree's structure under X1. |
| Escalation notification transport | How an approver learns approval is pending. UI polling is the minimum; webhook and Slack are candidates. |
| Hosted-tier rate limiting and quota | Per-tenant limits on decisions and delegations. Rate limiting exists but defaults off. |
| Hosted-tier signup identity | Bring-your-own-IdP has no answer for the hosted tier's own account creation. |
| Demo IdP | With Keycloak gone, demos and local development need an OIDC provider. |
| Default for unknown tools | Deny, or a configured floor tier (§4.4 step 4). Likely tenant-configurable. |
| Per-tenant encryption key management | §4.9 depends on per-tenant keys for crypto-shredding, but where they live, how they rotate, and who can destroy them is unspecified. Destroying a key is irreversible data loss, so the authorization model around that operation matters. |
| Trust-tier table overrides | §4.3 extends raise-only overrides to `actionTier → requiredTrustTier` by analogy with the action-tier table. Confirm or reverse. |

### 8.1 Known tensions

Three places where two sound decisions rub. None blocks implementation; each needs a call.

1. **Dry-run replay vs. crypto-shredding.** Policy authoring replays recorded decision inputs.
   Erased tenants lose replay for shredded records. Likely resolution: replay operates on redacted
   or digest-only inputs, with full-fidelity replay available only within the retention window.

2. **Build tags multiply the release matrix.** Instrumented and non-instrumented × three services
   is six artifacts to build, sign, and scan. The air-gapped rationale is sound; CI absorbs the
   cost, but release signing and provenance get more work.

3. **Write-gated audit couples availability to the audit store.** Correct for evidentiary
   integrity, and an explicit trade: the audit store becomes a hard dependency of authorization.
   Its availability target must match the PDP's.

---

## 9. Sequencing

Ordered by technical dependency; no external deadline (X6).

> **This spec spans multiple implementation plans.** It is too large for one. Each phase below gets
> its own plan, written when the preceding phase lands so it can absorb what was learned. Phases 0
> and 1 are close enough in character to plan together; the rest are separate.

**Phase 0 — Remediate and scaffold.** *(Revised under G1.)*
Rotate the leaked credential in `~/Development/stratium`. Scaffold the new repository: workspace
layout, module, and the directory structure of §3.7 G3. Nothing is deleted anywhere; the old
repository is left as-is.

**Phase 1 — Foundation.**
CI with the conformance suite scaffolded. Tenancy schema and `golang-migrate`. Audit chain. The
decision core as a pure, I/O-free package with conformance tests passing against it. Nothing is
demoable at the end of this phase; everything after it depends on it.

**Phase 2 — PDP.**
Prepared engines, extended input, deny-overrides combining, server-side tier derivation, the
delegation-creation gate with clamping, issuance, escalation.

**Phase 3 — First surface, end to end.**
One PEP mode — `hook` — wired to the PDP, with caching and epoch invalidation. Proves the
architecture before it is replicated three more times.

**Phase 4 — Remaining surfaces.**
`mcp`, `proxy`, `extauthz`. Each is a mode of the same binary against the same decision.

**Phase 5 — Admin plane.**
PAP CRUD, authoring, validation, dry-run, UI.

**Phase 6 — Hosted tier.**
Signup identity, quota, rate limiting, operational tooling.

Old code is deleted as each surface cuts over (X1), not accumulated for a big-bang removal at
the end.

---

## 10. References

- Current architecture: `docs/CODEMAPS/architecture.md` (superseded by this document)
- Prior security review: `docs/project-review.md`
- Competitive positioning: `docs/COMPETITIVE_ANALYSIS.md`
- Patent package: `docs/patent/` — IP reference, not an architectural specification
- AAuth alignment: `docs/AAUTH_ALIGNMENT_PLAN.md` (Track 1 Phases 1–2 retained; Phase 3 dropped)
