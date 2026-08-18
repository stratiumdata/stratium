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

**Amended 2026-08-10 — the clamp covers resource-independent dimensions only.**
Implementing G6 surfaced that probing existing action policies with no resource
under-grants severely: `permit(principal == alice, action == read, resource in
Folder::"hr")` does not match a probe carrying no resource, so `read` would be
clamped away even though alice plainly holds it. Most real authority is
resource-conditional, so a naive probe clamps nearly everything.

The gate therefore probes only what is answerable without a resource — the
**action-tier ceiling** and the **tool set** — and leaves resource scope and
classification to the runtime principal leg, which has the concrete resource
and evaluates on every action regardless.

**What the clamp is for, stated precisely.** It is defence in depth, not the
only barrier. An over-broad artifact does not by itself let an agent act beyond
its principal: the principal leg still evaluates at runtime and denies. What
the clamp buys is an artifact that is honest about what it permits (so offline
verification and audit mean something), a cheaper and earlier denial, and a
backstop if the principal leg is ever misconfigured. D3's concrete case — any
authenticated user minting `max_action_tier: DESTRUCTIVE` with every tool — is
closed by exactly this.

A dedicated grant-action namespace (`action == Action::"grant_tool"`) was
considered and deferred. It removes the under-granting problem entirely and
recognises that "what alice may delegate" is genuinely a different question
from "what alice may do" — but it requires every tenant to author grant
policies before anything can be delegated at all. Revisit if a real authority
model needs it.

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

## 3.9 Phase 7 design decisions (2026-08-12)

Phase 6's real-agent run found two of the delegation leg's controls inert in
production, both downstream of one root cause: nothing ever populated
`DecideRequest.resource`, so every leg that reasons about the concrete
resource — the runtime principal leg (§3.8), `CheckCap`, and
`ResourceConstraints` — evaluated against an empty map on every real decision
ever made. Three rulings, recorded here in the register §3.8, §4.1.1, §4.3.1,
§4.4.1, and §4.6.1 already use: what was believed, what was actually true, and
why the ruling is what it is.

### 3.9.1 Resource labelling: per-tenant prefix rules (2026-08-18)

**R3** recorded that nothing supplies a resource's classification, so **R2**
denies every capped decision. This closes it. The shape is **§4.4.2 T1's**,
applied to resources: per-tenant rows, written through the admin plane, read
by the PDP on the decision path — the PAP holds the write grant, the PDP holds
`SELECT` alone.

**R4 — a label comes from a per-tenant rule mapping a resource-id prefix to a
hierarchy and a level.** Not from the PEP (**R1** forecloses it on principle),
not from the resource itself (that was ZTDF, removed in §5.1 and backlogged),
and not from an external service at decision time — that would put a third
system's availability and honesty on the authorization path, which is the
opposite of what §4.8 and **W6** are built for.

A row-per-resource table was rejected outright: the resource space is
unbounded, and a scheme that requires enumerating every file cannot be
operated.

**Why an agent-influenced identifier is a safe thing to label.** The resource
id is derived server-side (**T2**) but from client-supplied `raw_input`, via
the tenant's own `resource_field`. An agent therefore influences it — and that
is sound here, because **the id is what the tool actually acts on**. Naming a
different resource changes what you get, not merely what you are permitted;
lying does not pay. That argument holds exactly as far as the catalog's
`resource_field` really names the field the tool operates on, which is tenant
configuration. **A tenant that mis-catalogs `resource_field` labels the wrong
thing**, and no mechanism here can detect that.

**R5 — prefix matching. Not regex, not glob.** Resource ids here are
path-shaped, and prefixes are the shape their hierarchies take. Regex on the
decision path is a denial-of-service surface: the input is attacker-influenced
per R4 above, and catastrophic backtracking would be reachable by anyone who
can name a resource. Prefix matching is linear, has no pathological case, and
an operator can predict what a rule does by reading it. Suffix or glob
matching is a later extension if evidence demands it, not a guess now.

**R6 — the longest matching prefix wins, and this deliberately departs from
the raise-only pattern.** §4.4.3 **T5** makes tier overrides raise-only, and
the reflex here would be "the highest classification wins." That is wrong for
labels, and the distinction is worth stating because the two rules look alike:
**a tier override adjusts a control; a classification states what the resource
is.** A public file inside a secret directory is genuinely public, and an
operator carving out `/data/public/` beneath a `/data/` SECRET rule is
recording a fact. Highest-wins would make that carve-out inexpressible.

The mirror risk is real: a mistyped narrow rule silently lowers a subtree.
**The PDP logs when a longest-prefix match resolves lower than the rule it
overrides** — that log line is the operator's only signal that a carve-out is
doing something, and a lowering carve-out is the one case worth seeing.

**R7 — an unlabelled resource still denies, and operators must be told
plainly.** **R2** is unchanged: a cap that cannot be checked denies. So
enabling caps means labelling everything reachable, or registering a catch-all
— which prefix matching gives for free, since the empty prefix matches
everything. No new mechanism, but a tenant that enables a cap without a
catch-all will see every action on an unmatched resource denied, and that
belongs in the operator documentation rather than in a support ticket.

**R8 — two things this deliberately does not do**, recorded so the gap is not
read as closed:

- **Hierarchies stay hardcoded** (`nato`, `commercial`, in
  `pkg/classification`). A tenant-defined hierarchy needs an *ordering* to
  make a cap meaningful, which is its own subsystem, not a table. A tenant
  whose scheme is neither of these still cannot use caps.
- **Delegation constraints over a directory** — Phase 7's Finding A — reuse
  this matcher but are a different table. A small follow-on, kept out so this
  phase stays one mechanism.

**R9 — a label naming a hierarchy the system does not know must deny, and
today it silently allows.** Found by the Task 1 review, 2026-08-18.

`CheckCap` resolves a delegation's cap for the resource's hierarchy and, on
not finding one, returns **allow** (`pkg/classification/classification.go`,
the `if !hasCap` branch). That is correct for a *known* hierarchy a cap simply
does not mention: a delegation capping `nato` says nothing about `commercial`,
and silence is not a denial. It is wrong for a hierarchy that does not exist.
Because **R8** keeps hierarchies hardcoded, `Index` already returns `-1` for
one — the system can tell the two cases apart and currently does not, because
`Index` is consulted only *after* the `!hasCap` return.

The consequence is a fail-open reachable by one typed character:

```
rules: /data/    nato    SECRET
       /data/x/  natoo   UNCLASSIFIED     <- typo
caps:  {"nato": "CONFIDENTIAL"}
```

The carve-out wins on length, the resource is labelled `natoo`, no cap matches
`natoo`, and `CheckCap` allows — turning a capped resource into an
unconditional allow. **R6**'s lowering log does not fire either, since an
unrankable hierarchy has no rank to compare, so the operator's one signal is
silent precisely when it is most needed. `checkResourceConstraints` does not
catch it: it compares only keys the constraints name.

This is **D10** — an unevaluable policy denies — applied to classification: a
label the system cannot rank is not a permissive label, it is an unreadable
one. It is also the exact shape of a defect this codebase already closed once,
recorded in `internal/authz/delegation.go`: `CheckCap` formerly read a resource
with *no* classification as an unconditional allow. Same failure, one field
over.

**The requirement:** an unknown hierarchy, or a level unknown within its
hierarchy, denies with a reason naming the unknown value — checked before any
`!hasCap` early return. Write-time validation in the PAP is worth having so an
operator learns at the point of the typo rather than at a denial, but it is a
better error message, not the enforcement: the enforcement is that an
unreadable label never reaches a permissive branch.

**Not reachable before resource labelling ships.** Nothing populates a
resource `hierarchy` attribute today — **R1**'s extraction guard blocks it from
`raw_input` — so `CheckCap` denies at the empty-classification check first.
Resource labelling is what makes an operator-typed hierarchy reach this code,
which is why the fix belongs to this phase and not to a backlog entry.

*Closed 2026-08-18, in the same task that made it reachable.* `CheckCap` now
validates the label — hierarchy, then level within it — ahead of the cap
lookup entirely, so every branch after it asks a rank question about a label
already established as rankable. The still-allows half is unchanged and
pinned separately (`TestCheckCap_NoCapForThisHierarchyAllows`): a *known*
hierarchy the caps do not mention allows, because silence is not a denial,
and that test is what distinguishes this fix from a blanket denial.

---

### R1 — the PEP sends resource identity, never classification

A PEP knows a tool call's arguments well enough to extract an identifier from
them by field name — a file path, a command string — the same structural
lookup `normalize`'s own extraction already performs and the PDP already
trusts for `tool`. It cannot know whether the file that path names is
CONFIDENTIAL. Deciding what a resource's classification *is* is classification
itself, and belongs to the PDP exactly as much as deciding an action's tier
does. A PEP that supplied a `classification` or `hierarchy` attribute would be
spec defect **D1** relocated — a client asserting a security-relevant fact the
server has no independent way to check, and would simply believe — and worse
than the original, which was only a tier. Implemented in Task 1: `hook` and
`mcp` both now populate `DecideRequest.resource` with an `id`, and a `type`
where the field name makes one unambiguous; a structural allowlist test
asserts `classification` and `hierarchy` are never among the keys either mode
can produce.

*Implementation note, corrected 2026-08-18: the `type` half of that sentence
is stale. §4.4.2 **T2**/**T3** moved extraction server-side and retired
`normalized_input`, and the resource map is now built by
`internal/authz.resourceFromID`, which produces exactly `{"id": …}` and no
`type`. The **ruling** is unaffected — the PEP still supplies identity and
never classification, and the allowlist test still holds — but the map is
narrower than this paragraph describes.*

### R2 — a classification cap that cannot be checked denies

`CheckCap` returned `true` immediately whenever the resource carried no
`classification` attribute — which, before R1, was every classified decision,
because nothing ever supplied one. A configured cap is a restriction an
operator deliberately declared; a resource that says nothing about its
classification cannot be shown to satisfy that restriction, and reading
absence-of-information as compliance is a silent fail-open on the platform's
core authorization primitive. Defect **D10** (ruled during Phase 4's
policy-engine work, enforced throughout `internal/policy` — discovered after
§1.1's defect table was written, so it does not appear there) already ruled
that a policy which cannot be evaluated denies rather than being silently
ignored. A cap that cannot be evaluated is the same fact about a different
control: **it denies.**

This is a deliberate behaviour change, not a bug fix that happens to alter
output. Any tenant with a classification cap configured, on any hierarchy,
will begin seeing denials on resources it was never actually restricting
before — because it was never restricting them. That is correct: the cap's
intended semantics were always "resources above this level are refused," and
a deployment that saw only allows was not observing a working cap, it was
observing one that had never once fired. Operators need to know this before
they see it in production, not after — `docs/pep.md` says what to do about
it, and "supply a classification" is deliberately not one of the options
(R3).

The change is deliberately narrow. `len(caps) == 0` still returns `true`
immediately: a delegation with no classification cap configured at all places
no restriction on this axis and never did, so nothing about R2 touches it.
Only a *configured* cap becomes strict. `pkg/classification`'s
`TestCheckCap_NoCapsAllowsEvenWhenResourceHasNoClassification` and
`internal/authz`'s
`TestDelegationLeg_NoClassificationCapsUnaffectedByUnlabelledResource` pin
this boundary directly and separately from the denial tests, because it is
the entire difference between this change and one that denies every action.

The audit trail carries the distinction in `Entry.Reason` (`pkg/audit`) as
different prose, not a different field. "The resource was CONFIDENTIAL and
the cap allowed it" is `Decision = ALLOW`, `Reason = ""`. "We could not tell
what the resource was" is `Decision = DENY`, `Reason` stating the cap could
not be evaluated. An ordinary cap violation is also `Decision = DENY`, with a
reason naming the level that exceeded the cap — deliberately different
wording from the uncheckable case, pinned by
`TestCheckCap_UncheckableReasonDiffersFromExceedsCapReason` so the two can
never again read alike. No schema change was needed: `Entry.Hash` already
covers `Reason` as one more opaque, order-sensitive string, the same
mechanism every other denial reason in this system already relies on to stay
distinguishable from its neighbors.

### R3 — resource labelling is an unresolved design gap, recorded rather than papered over

R2 makes a cap that cannot be checked loud. It does not make it checkable. No
component in this system today has a source for a resource's classification:
ZTDF was where labels lived, ZTDF was removed (§5.1), and nothing replaced
it. R1 forecloses the PEP as a source on principle — a labelling PEP would be
D1 relocated, and the worst-case instance of it, since a classification the
server has no independent source for would simply be believed outright, with
nothing to check it against. Neither §8 (Open items) nor §9 (Sequencing)
named this gap before now, an omission this section corrects; §8 gains a row
below.

Closing it needs a tenant-configured labelling source — a resource registry,
tags synced from wherever the underlying storage already classifies content,
or an equivalent the tenant controls — and is out of scope for Phase 7. Until
one exists, a tenant that needs a classification cap enforced has no path to
enforcement through this system. Recording that honestly is what this ruling
is for; R2 is what stops the limit from reading as a working control in the
meantime.

### Two claims elsewhere in this spec were untrue until this phase

**§3.8** states the delegation-creation clamp may skip resource scope and
classification because it is "left to the runtime principal leg, which has
the concrete resource and evaluates on every action regardless." The wiring
behind that claim is real: `pdp.proto:77` declares the field,
`pdpgrpc/server.go` threads it into `EvaluationInput`, and all four policy
engines map it. But "has the concrete resource" is a claim about what
arrives at runtime, not what the plumbing can carry, and nothing arrived —
no PEP populated `DecideRequest.resource` until Task 1. The sentence
described the code's shape accurately and its behaviour not at all, for the
entire span between being written and Task 1 landing.

**§4.4**'s residual-risk paragraph names four controls as carrying weight
because they are "structural and not string-dependent: the delegation
ceiling (`max_action_tier`), the agent's tool allowlist, the classification
caps, and escalation." Of the delegation leg's actual mechanisms, two did not
carry weight. The classification caps are named in that list and are R2's
subject above. `ResourceConstraints` is not named in that list at all — and
was equally inert, from before this document existed until Task 2 closed it
— which is itself part of what the paragraph overstated: it undercounted the
delegation leg's own controls, not only mischaracterized one of them. The
ceiling, the tool allowlist, and escalation were accurately described; two of
the leg's real controls, one named and one not, were not.

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

### 4.1.1 The four surfaces split by trust model (2026-08-12)

**A10.** A2 lists four enforcement surfaces as equally first-class, and A1 says
each is a network client of one PDP. That is true of the decision path and
obscures a difference in the *identity* path that determines what each surface
can be built on.

**`hook` and `mcp` are locally invoked.** The harness launches them alongside
the agent, so they read a delegation reference out-of-band — today a session
file written by `stratium-pep session-start`, which the agent never writes and
does not control. The reference never crosses a boundary the policed party can
influence.

**`proxy` and `extauthz` are network intermediaries.** The request arrives *from
the agent being policed*, so a delegation reference can only ride in a header
that same agent sets. An agent choosing its own delegation id is an agent
choosing its own authority — spec defect **D1** relocated, and worse than the
original: D1 was a client asserting a tier the server re-derived anyway, whereas
a delegation id is a bearer reference to a scope someone else was granted.

**Consequence: sender-constrained tokens (A4, C24, C25) are a prerequisite for
`proxy` and `extauthz`, not an independent later concern.** Building either on a
bare header would ship the defect the compound decision exists to prevent. `mcp`
has no such prerequisite and can be built on the trust model `hook` already
uses.

This does not weaken A1 or A2. All four remain first-class and all four are
network clients of one PDP; they differ in how the *caller* is identified to the
PEP, which A1 never addressed.

---

### 4.6.1 Escalation mechanics (2026-08-12)

§4.6 fixes the semantics — the root principal approves, blocking surfaces wait,
timeout denies, extauthz degrades to deny plus a pending record, escalation
outcomes are never cached. Four mechanics were left open and are settled here.

**E6 — the PEP blocks, not the PDP.** `Decide` returns `ESCALATE` with an
approval id immediately; the PEP polls `GetApproval` until resolved or its own
timeout, and the agent blocks there. The PDP keeps its per-call shape: no
goroutine or connection parked for the minutes a human takes, and a PDP restart
cannot drop a pending escalation, because the state is a Postgres row rather
than an in-flight RPC. The cost is a second RPC and polling traffic.

**E7 — the PDP never grants an approval, it only reads one.** There is no
`Approve` RPC. Approvals are written to the `approvals` table by the control
plane, which already owns operator identity; the PDP loads the record and
enforces that its approver is the chain's **root** principal (C21). This is a
consequence of A1: the PDP authenticates no callers today, since the tenant
comes from configuration, so an approval endpoint on it could not verify who
was calling. An unauthenticated approve is a privilege-escalation path, not a
feature.

**E8 — pending records only; no notification transport.** The open item in §9
stays open deliberately. Anything that wants to notify reads the table. This
phase ships the enforcement semantics C21 and C22 test and does not commit the
PDP to outbound messaging, which would be its first egress surface.

**E9 — escalation keys off the derived tier, and the threshold lives on the
delegation.** §4.4 already says escalation keys off the same derived tier as
everything else. The threshold sits on the delegation beside `max_action_tier`:
at or above it and within the ceiling, the decision escalates; above the
ceiling it still denies, because deny-overrides.

It is deliberately **not** a policy verdict. Cedar and XACML have exactly two
effects and could never express one, so a policy-driven escalation would be
available in Rego and JSON only — reintroducing precisely the per-engine
capability gap Phase 4a existed to remove. Keying off the tier is
language-independent, and it inherits `ScopeNarrows`: a child may lower the
threshold (escalating sooner is narrower) and never raise it, under the same
rule §4.3.1 states for every other dimension.

---

### 4.7.2 Sender-constrained tokens — DPoP (2026-08-16)

§4.1.1 states that **sender-constrained tokens are a prerequisite for `proxy`
and `extauthz`, not an independent later concern**. Both surfaces shipped —
Phases 10 and 11 — and that prerequisite was never met. C25 remains `notBuilt`
because delegation tokens are presented as bearer credentials with no
proof-of-possession binding. This section closes it.

**What is already closed, so the remaining gap is stated accurately.** Tokens
are ECDSA-signed JWTs the PDP both issues and verifies (**K1**, **K2**), and a
token is an authenticated *reference* whose delegation the PDP loads and
evaluates in full (**K3**). An agent therefore cannot mint a token naming a
delegation it was not granted — the defect §4.1.1 worried about most, an agent
choosing its own authority, is already prevented by the signature. **What
remains is replay after theft**: a bearer token that leaks from a log, a proxy,
or a compromised sidecar is fully usable by whoever holds it, on exactly the two
surfaces where the request arrives from the party being policed.

**K5 — binding is required on `proxy` and `extauthz`, and not used on `hook` or
`mcp`.** The two network surfaces refuse a token carrying no `cnf.jkt`. This
follows §4.1.1's own reasoning rather than extending it: on the local surfaces
the caller already holds the session file containing a real token, so binding
grants nothing, and requiring a keypair per session would be cost without a
threat-model gain. A per-tenant toggle was rejected — a tenant that never sets
it keeps bearer tokens on the internet-facing surfaces, which is the exact gap
this work exists to close.

**K6 — `IssueToken` accepts the caller's public JWK and binds the token to its
RFC 7638 thumbprint** as `cnf.jkt`. A network-surface agent generates a keypair
and presents the public half when it asks for a token; it is the only party that
can subsequently produce a valid proof.

**The JWK is optional at issuance, and the refusal lives at the surface, not
here.** `IssueToken` cannot know which surface will present the token it mints,
so it cannot decide whether binding is required — a JWK yields a bound token, no
JWK yields a bearer token exactly as today. **K5** is what makes an unbound
token useless on `proxy` and `extauthz`: those surfaces refuse it. An agent that
intends to use either must therefore supply a JWK, and discovers otherwise on
its first call rather than at issuance.

*(Corrected 2026-08-16, while planning: this ruling first said an `IssueToken`
call "for a network-surface token" with no JWK is refused. There is no such
thing at issuance — the surface is not known until the token is presented. The
requirement is real but it belongs to K5, which already carries it.)*

**K7 — the PDP verifies the proof; the PEP forwards it along with the request
metadata it binds to.** A DPoP proof binds to the HTTP request via `htm` and
`htu`, and the PDP never sees that request — it sees a `Decide` call. The PEP
therefore forwards the proof JWT *and* the method and URI it observed, and the
PDP checks the signature, the `cnf.jkt` match, `htm`/`htu`, and freshness.

This keeps **K2** intact: *"verification is a decision about whether a credential
is genuine, so it belongs where every other decision does."* Splitting the check
— PEP validates `htm`/`htu`, PDP validates the signature — would put half of
"is this credential genuine" outside the PDP, and a PEP that decides a proof is
valid is a PEP making an authorization decision (**D1**). The PEP reporting the
method and URI it saw is the same category as it serializing `raw_input`, which
it already does.

**`htu` on the gRPC proxy is the proxy's own address plus the full method
path**, `/package.Service/Method`, with `htm` as `POST` — gRPC is HTTP/2 POST.
That is what the agent addressed and what the PEP observes. Binding to the
*target's* address instead would let a proof for one target be replayed at
another behind the same proxy.

**K8 — a proof's `jti` is single-use, enforced in the database.** A
tenant-scoped table with a uniqueness constraint and a TTL; a replayed proof
collides and denies. This is the stronger of the two options RFC 9449 permits,
and it was chosen deliberately over relying on a short freshness window alone,
which leaves a stolen token and its captured proof replayable within that window
against the same method and URI.

The cost is a write on every network-surface decision. That is not a new class
of cost — the PDP already writes an audit row per decision (**C16**) — and
sharing one database means it holds across horizontally-scaled PDPs, which an
in-memory cache would not. **A failed `jti` write denies**, exactly as a failed
audit write does; a replay check that fails open is not a replay check. Expired
rows are reaped on a schedule, and the reaper's failure must be visible rather
than silently letting the table grow.

**The PDP needs `INSERT` on this table, and that does not contradict E7, T1, or
T6.** Those rulings withhold writes on *authorization configuration* —
approvals, the tool catalog, tier overrides — because a PDP that could write
them would be adjusting its own authority. Replay state is not configuration: it
records that a specific proof was spent, it is written only by the component
that spends it, and no value in it can widen any decision.

**K9 — the freshness window is required configuration with no default.** An
operator states how much clock skew between an agent and the PDP is tolerable.
No default is right for every deployment, and a wrong one is either useless or
too permissive — the same reasoning §4.8.2 **W3** applies to the cache staleness
window.

**K10 — a DPoP proof never reaches `raw_input` or the audit chain.** The same
rule the `authorization` header already has (§4.1.1, Phases 10 and 11): raw
input is hashed into an append-only record designed to be retained, and a
credential-bearing artifact written there cannot be edited out. Strip by
omission and case-insensitively, and assert the absence structurally.

**K11 — a sender-constrained call does not block on `proxy`; it degrades to a
denial plus a pending approval, exactly as `extauthz` does (2026-08-17).**

§4.6 splits the surfaces into blocking and non-blocking, and puts `proxy` in the
blocking class: unlike `extauthz` it can hold a call open while a human approves.
**That is not achievable for a bound token, and the reason is structural rather
than an implementation gap.** A DPoP proof is single-use (**K8**) and short-lived
(**K9**); a human approval is neither. The escalation retry resends the same
request — it must, because the approval binds to `input_digest` — so it resends
the same proof, whose `jti` the PDP has already spent. Even were it not spent,
the freshness window would have closed. And the proxy cannot mint a replacement:
the client holds the private key, and a blocking surface has by definition not
returned to the client.

So on `ESCALATE` with a bound token, `proxy` returns a denial carrying the
approval id, and the client retries with a **fresh** proof once the approval is
granted — minted by the only party that can mint one. Proof-of-possession stays
intact end to end; nothing is waived and no approval is consumed without a live
proof.

This covers every case `proxy` actually serves, because **K5** already refuses an
unbound token there. `extauthz` never met this problem only because **E5** had
already made it non-blocking for an unrelated reason — Envoy's millisecond
timeouts. The right reading of §4.6's split is therefore narrower than it looked:
a surface can block only while the credential it would wait with outlives the
wait. A sender-constrained credential does not.

*Found in Phase 15 Task 6 by an integration test, not by reading. The
alternative — letting an approved retry skip the proof check — was rejected:
approvals are not consumed, so a token plus an approval id would re-execute the
approved action for the approval's whole TTL with no proof of possession at all.*

**K11 has a wider consequence than it first appeared, settled the same day:
`proxy` no longer blocks at all, and §4.6's blocking class is now `hook` and
`mcp` only.**

An unbound escalation was initially left on the blocking path, on the reasoning
that **K5** would refuse its outcome anyway so the path was inert. It is not
inert: the surface holds the caller's stream and a polling goroutine for the
full approval timeout, and then refuses the resolved ALLOW regardless — so a
legacy bearer-token caller hitting an escalating action hangs for the timeout
and is answered as though it had run out of time rather than as though its
credential was wrong. Refusing on arrival removes the held stream, the
goroutine, and the misleading answer, and tells the caller something it can act
on.

**What it does *not* remove, corrected 2026-08-17:** this ruling first claimed
the change stopped a human being paged, and that any holder of an unbound token
could otherwise generate unbounded human interrupts. **Both are false.** `Decide`
creates the pending approval row itself, inside `resolveEscalation`, *before* the
tail sets `sender_constrained` — so the row a human acts on already exists by the
time either surface can read that field. Polling `GetApproval` is not what pages
anyone. An unbound-token holder can still mint one pending approval per
escalating call, and closing *that* would mean refusing before the PDP is asked,
which no enforcement surface may do (**D1**). The behaviour is right; only this
justification was wrong, and it was wrong in the direction of claiming more.

So an unbound escalation is refused immediately. The justification is K11's own
argument turned around: `sender_constrained` carries the real answer on an
`ESCALATE`, because escalations reach the tail of `Decide` where it is set — so
`false` there unambiguously means unbound, and refusing is a **narrowing**,
always permitted.

Both `ESCALATE` outcomes on `proxy` therefore return, and `resolveApproval`
became unreachable from this surface — mechanically, not by preference: Go's
`unreachable` analyzer rejects a call below two returning branches, and an
uncalled helper fails the unused-code lint. `resolveApproval` itself is
unchanged and still serves `hook` and `mcp`, including both reshapes `proxy`
forced on it when it was a caller. **C22's proven-elsewhere pointer narrowed to
those two surfaces accordingly**, which the conformance gate caught rather than
a reader.

The rule §4.6 was reaching for is the one K11 states: *a surface can block only
while the credential it would wait with outlives the wait.* On `proxy` no
credential does — bound ones expire and are single-use, unbound ones are refused
on arrival.

**C25 then means two things, and both must be tested.** Its wording — *"a
delegation token without a valid DPoP proof is denied when the token is
sender-constrained"* — covers a bound token presented without a proof. **K5**
adds the converse: on `proxy` and `extauthz`, an *unbound* token is also denied,
because binding is required there. A test covering only the first leaves the
migration hole open.

---

### 4.7.1 Token issuance mechanics (2026-08-13)

**A4** says the PDP decides and issues tokens as the sole signing-key holder;
**A10** makes sender-constrained identity a prerequisite for `proxy` and
`extauthz`. Four mechanics were open.

**K1 — the signing key is a PEM file named by an environment variable.** The
env holds the path, never the secret, so the key stays out of process
environments, orchestrator manifests, and crash dumps. Rotation mounts a new
file; a previous key stays loaded for verification only, so a token issued
moments before a rotation still verifies.

**K2 — the PEP forwards a token; the PDP verifies it.** This is **A1**: no
decision logic outside the PDP. Verification is a decision about whether a
credential is genuine, so it belongs where every other decision does. The
consequence is that **JWKS is not on the enforcement path at all** — the PDP
issues and verifies with the same key. **A5**'s assignment of JWKS to the PAP
stands for when a PAP exists and a third party wants to verify independently;
nothing in this phase needs it.

**K3 — a token is an authenticated reference, never a capability.** It names a
delegation; it does not carry one. The PDP still loads the delegation and all
three legs still evaluate, exactly as they do for a bare id today. A token that
outlives a revoked delegation is denied by the delegation leg, not by the token
check. This is the same shape as **E7**'s approval: a fourth condition, never a
bypass.

**K4 — once tokens exist, the bare `delegation_id` path is removed.** This is
the load-bearing consequence and it is not optional. If `Decide` continues to
accept a bare delegation id, a token adds no security whatsoever against the
attacker A10 describes: that attacker simply omits the token and sends the id.
The PDP cannot distinguish a trusted local `hook` from a hostile network client,
because under A1 and E7 it authenticates no callers at all.

So **all four surfaces use tokens**, including `hook` and `mcp`, whose session
file comes to hold a token instead of a delegation id. One authentication
mechanism with no alternative is the only version of this that is worth
building; two, where one is unauthenticated, is the weaker of the two
everywhere.

**What this does not close.** **C24** — an expired token denied even when a
cache entry exists — still requires the PEP decision cache, which does not
exist. It stays skipped with an accurate reason. **C25** requires DPoP, which is
deferred to its own phase: a PDP-signed bearer token already satisfies A10's
requirement that an agent cannot choose its own authority, since it cannot mint
one; DPoP additionally resists replay of a stolen token, which is a different
threat and needs a replay store.

---

### 4.4.3 The override read path, and what raise-only compares against (2026-08-15)

§4.4 has resolved a tier by override, then catalog, then built-in since the
baseline. **The override step has never run in production.**
`internal/authz.TierTable.Overrides` is read at exactly one place — the first
loop of `deriveTierByName` — and is assigned nowhere outside `tier_test.go` and
`catalog_test.go`. The PDP builds its table with `Catalog` alone, under a
comment that recites all three steps. Consistent with that, `stratium_app` holds
no grant on `tier_overrides` at all, not even `SELECT`.

This is the **eighth** instance in this project of a mechanism plumbed and never
populated; `tenant_epoch` was the seventh. It is the one that made a whole
shipped feature inert: Phase 14 Task 3 built full CRUD over `tier_overrides` and
gave `ValidateOverride` its first production caller, so an operator can create,
update, and delete overrides, and be correctly refused a lowering one — and none
of it reaches a decision. Found while planning the phase's own proof that it
works.

**T4 — the PDP loads tier overrides and populates `TierTable.Overrides`.**
Tenant-scoped through `beginTenantTx`, loaded on the decision path exactly as
policies and catalog entries already are, and keyed by the same `lookupKeys`
the catalog uses. Phase 12's trigger already fires on `tier_overrides` writes,
so invalidation needs nothing new.

**T5 — raise-only means "at or above the tier resolution beneath it", not "at
or above built-in".** `ValidateOverride` compares against the built-in tier
because it predates the per-tenant catalog. With built-in `READ`, a catalog
entry of `DESTRUCTIVE`, and an override of `WRITE`, the write-time check passes
— `WRITE ≥ READ` — and then the override wins the resolution and lowers the
effective tier from `DESTRUCTIVE` to `WRITE`. A tenant's own catalogued
judgement is undercut by a correction that was validated as a raise.

The baseline is therefore the catalog entry where one exists and the built-in
otherwise, **enforced at both ends**:

- **At write time**, so an operator gets an error rather than a row that
  silently does nothing. This requires the PAP to resolve the tenant's catalog
  when validating, which it can already do.
- **At read time**, when the PDP builds the table, because a direct `INSERT` as
  a database superuser never passes through the PAP at all. A row failing this
  check is **dropped and surfaced, never silently honored** — dropping falls
  back to the higher tier beneath it, which is the safe direction, whereas
  failing the whole decision would let one bad row deny an entire tenant.

The exposure this closes is an operator footgun rather than an agent escape: no
agent can write either table, and `destructiveEvidence` (§4.4.1) still binds
above all three sources, so destructive raw input cannot be masked by any
override. What a lowering override can do is drop a *catalogued* tier beneath a
delegation's cap.

**T6 — the PDP gets `SELECT` on `tier_overrides` and nothing else.** The same
reasoning that keeps `UPDATE` on `approvals` and `tool_catalog` away from
`stratium_app` (**E7**, **T1**, **N3**): the absent grant *is* the enforcement.
A PDP that could write an override would be the component being policed
adjusting its own classification — spec defect **D1**, and precisely what
**C5** exists to forbid.

**C5 becomes assessable only after T4.** "A tier override from an
agent-writable source is never honored" is satisfied trivially while *no*
override is honored, and converting it on that basis would be forcing a pass.
Once overrides are live, the property rests on four mechanisms that must be
pointed at together: no PEP sends `declared_tier` (asserted on all four
surfaces); `CheckDeclaredTier` cross-checks a declared tier rather than
trusting it; `tier_overrides` is writable only by `stratium_pap`, which
requires an operator's OIDC token; and the PDP holds `SELECT` alone.

---

### 4.4.2 The per-tenant tool catalog, and extraction moves server-side (2026-08-12)

§4.4 resolves an action's tier by tenant override, then tool catalog, then the
built-in classifier. The catalog has been a hardcoded map of **Claude Code's own
tool names** since Phase 3c, whose plan said so explicitly and named a
database-backed per-tenant catalog as the eventual home. That debt has now
blocked three separate controls, all for third-party tools, all found by
real-agent runs rather than by tests:

- a `READ_ONLY` delegation denies every third-party MCP read, because
  `read_file` has no catalog entry and falls through to the classifier's
  `INTERNAL_MODIFY` default (Phase 6);
- `Delegation.ResourceConstraints` cannot discriminate on the MCP surface at
  all, because the PEP's `resourceIDFields` knows only Claude Code's tool names
  (Phase 7);
- and classification caps inherit the same gap, since they read the same
  never-populated resource attributes.

**T1 — the catalog is per-tenant, PDP-owned, and control-plane-written.** It
slots in exactly where §4.4's resolution order already places a catalog:
override, then catalog, then built-in. The built-in map remains as the fallback
for a tenant with no rows, so no existing deployment changes behaviour until it
adds one.

The serving role gets `SELECT` and **not** `INSERT` or `UPDATE`. This is **E7**'s
reasoning applied to a second table: the PDP authenticates no callers, so an
endpoint that writes authorization configuration could not verify who was
calling. The absent grant *is* the enforcement.

**T2 — field extraction moves from the PEP to the PDP.** Phase 3b placed
extraction at the edge, reasoning that *"the PEP knows its agent framework's
schema and the PDP deliberately does not."* A per-tenant catalog makes that
premise false: the PDP now knows the schema, per tenant, for every tool the
tenant has catalogued. So the catalog names each tool's resource field and
command field, and the PDP extracts them from the `raw_input` it already
receives.

**Phase 3b's safety argument survives untouched**, and is worth restating
because it is the load-bearing half: raw input is always scanned, and a positive
destructive-or-external pattern match on it is never lowered (§4.4.1). Moving
extraction server-side only *strengthens* that — there is no longer an extracted
field a PEP could under-report, because the PEP no longer extracts.

**T3 — `normalized_input` is retired.** It existed so a PEP could hand the PDP a
best-effort extraction. With T2 the PDP derives it, so the wire field, the
PEP's `normalizedInputFields` and `resourceIDFields` tables, and its `toolVerbs`
map all go. Three parallel per-tool tables that had to be edited together become
one row per tool in one place.

**What this does not fix.** A tool absent from a tenant's catalog is still
unextracted and still takes the classifier's default — the failure is narrower
and now has a remedy an operator can apply, rather than requiring a code change.
Resource *labelling* remains the open gap §3.9 records: the catalog says which
field holds the resource identity, never what that resource is classified as.

---

### 4.4.1 Input evidence outranks every name-keyed lookup (2026-08-10)

§4.4 resolves an action's tier by tenant override, then tool catalog, then the
built-in classifier. Phase 3b added a rule inside the built-in classifier: a
positive destructive-or-external pattern match on **raw** input is evidence and
is never lowered, which is what stops a lying or buggy PEP from hiding
`rm -rf /` behind a bad extraction.

Phase 3c then wired the tool catalog, which sits **above** the built-in
classifier — and the rule silently stopped applying to every catalogued name.
Measured after that phase:

```
Read  {"command":"rm -rf /"}   -> READ_ONLY         catalog masked the evidence
Write {"command":"rm -rf /"}   -> INTERNAL_MODIFY   same
Bash  {"command":"rm -rf /"}   -> DESTRUCTIVE       correct (no catalog entry)
```

Overrides, sitting above the catalog, had the same gap. Both lookups are keyed
on a tool **name**, so a PEP could pick a benign name for a hostile call and
in effect choose its own tier — defect **D1** by another route, in the one
place the design says D1 cannot reach.

**Ruling: the evidence rule binds `DeriveTier`, not `BuiltinTier`.** It is
applied once at the boundary every caller routes through, above all three
lookups, so a fourth lookup layer cannot repeat the regression. Evidence only
ever raises: an override or catalog entry higher than the evidence stands, and
the raise-only override rule is unaffected.

Evidence reads raw input only, never `normalized_input`. A PEP willing to
mislabel a call is equally willing to extract wrongly; raw is the field it
cannot launder, which is the whole basis of Phase 3b's argument.

**The general lesson, third instance in this project.** A security property
enforced at one level rather than at the boundary everything routes through
survives exactly until someone adds a level. C12's fold moved into `authz` for
this reason; `ScopeNarrows` is called rather than reimplemented for this
reason; this is the same failure with a lookup table instead of a function.

---

### 4.3.1 A child may narrow only dimensions the parent constrains (2026-08-10)

`ScopeNarrows` treated two dimensions inconsistently: a child capping a
classification hierarchy the parent left open was **rejected**, while a child
adding a resource constraint the parent lacked was **accepted**. Both are
narrowing, so one of them was wrong.

**Ruling: reject both.** A child may narrow a dimension the parent already
constrains; it may not introduce one the parent leaves open.

This is stricter than logic alone requires — adding a constraint genuinely does
restrict the child further — and it is chosen for a structural reason rather
than a security one. It makes a child's *shape* derivable from its parent's,
not merely its values. Reasoning about a chain then means comparing values
across a fixed set of dimensions, rather than tracking which hop introduced
which dimension and on what authority. A delegation chain that can grow new
constraint dimensions at every hop is harder to audit and harder to explain,
even though every individual step narrows.

Consequence: `TestScopeNarrows_AcceptsAddedResourceConstraint` inverts. A
parent that wishes a child to be constrained on a dimension must constrain it
itself, however loosely.

---

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

#### Normalized input: the PEP extracts, the PDP classifies both (2026-08-10)

Added after the first real-agent run found the classifier inert at the only
surface that matters. Claude Code sends `tool_input` as JSON, and the read-only
pattern is anchored, so every read-only operation fell through to
`INTERNAL_MODIFY`. Destructive detection was unaffected — those patterns are
unanchored — so it failed safe, but the read/write distinction did not work.

**The PEP sends both the raw `tool_input` and a normalized extraction.** Raw's
positive pattern matches win and are never lowered; otherwise a normalized
input that classifies is used; otherwise raw's default applies.

An earlier formulation said simply "take the more severe," which does not work:
raw JSON's `INTERNAL_MODIFY` comes from the classifier's *default* branch — "I
do not recognise this" — so taking the max let absence of evidence override a
correct read-only extraction, leaving the defect unfixed. A positive match is
evidence; a default is not.

The PEP knows its agent framework's schema and the PDP deliberately does not,
so extraction belongs at the edge. Extraction is nonetheless interpretation,
and D1 exists to keep interpretation out of the component being policed — so
the raw input travels alongside it. A PEP that extracts wrongly, or lies, can
only under-report the extracted field; the raw JSON is still scanned, so a
destructive command cannot be hidden by a bad extraction.

Extracting a named field from a JSON object is a structural lookup, not a
judgement about sensitivity — the same category as deriving `verb` from a tool
name. Tier logic, allowlists, and severity reasoning remain forbidden in the
PEP.

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

### 4.8.2 Decision cache mechanics (2026-08-14)

§4.8 establishes that caching buys **outage tolerance** first and speed second,
and that the principal leg's hit rate is near zero because its key includes the
resource instance. §4.8.1 built the epoch. Five mechanics remain.

**W1 — whole decisions are cached, never individual legs.** §4.8's per-leg key
table describes where hit rates *would* differ, not a caching unit. Caching legs
separately would require the PEP to combine partial results into a verdict —
decision logic outside the PDP, which is spec defect **D1**, the hole this
system exists to close. The near-zero principal hit rate is accepted as the
honest cost: this is an availability feature, not a latency one.

**W2 — the key is (delegation id, tool, input digest).** The digest is
`sha256(raw_input)`, the same value the audit chain already records, rather than
a second notion of request identity. Keying on the **delegation id** and not the
token is deliberate: a token rotates while the delegation persists, so keying on
the token would discard the whole cache on every re-issue.

Everything else a decision depends on — the agent, policies, catalog, tier
overrides — is covered by the epoch. Everything time-dependent is covered by
W3. Nothing else belongs in the key.

**W3 — four independent validity conditions, all required.** A cached entry
serves only if:

1. its epoch equals the last epoch the PEP saw from the PDP — **C20**;
2. the delegation has not expired, per the expiry recorded in the entry — the
   time half of **C24**, and the reason §4.8.1 **V2** keeps expiry out of the
   epoch;
3. the caller's token is itself still valid — the credential half of **C24**. A
   cache hit must never let an expired credential through, and a token can only
   be refreshed by reaching the PDP, so during an outage an expired token
   denies;
4. it is within a configured staleness window since the last successful PDP
   contact — **C19**'s bound. Required config with no default: an operator
   states how long an unverifiable decision may keep working, because no default
   is right for every deployment.

**W4 — escalation outcomes are never cached.** §4.6 already says so; it is
restated here because it is easy to miss when implementing and the failure is
silent. An escalation is a decision about a moment, and a cached `ESCALATE` would
either re-block a call already approved or serve an approval that was never
granted.

**W5 — on disk, beside the session file, with the same integrity posture.**
The `hook` is a subprocess that exits after every tool call, so an in-memory
cache is worthless on the surface most likely to be offline. Written
`os.CreateTemp` + `os.Rename` at `0600` set at creation, matching
`writeSessionFile` exactly, because tool calls run in parallel and a torn cache
file is a corrupted authorization record.

The cache holds decisions, not credentials — and an attacker who can write it
can already write the session file, which holds a bearer token. **The cache
therefore does not lower the security bar**, and its integrity requirement is
the session file's, not a new one.

---

### 4.8.3 The cache serves only locally-invoked surfaces (2026-08-14)

**W6.** The decision cache is consulted by `hook` and `mcp` only. `extauthz` and
`proxy` always call the PDP.

**Phase 15 made W6 permanent rather than provisional, and closed the obvious
argument for lifting it (2026-08-17).** The exclusion below is justified by a
forged token being served a cached ALLOW without the PDP ever seeing it — a risk
sender-constrained tokens might look like they answer. They do not, and the
reason is structural:

The cache key is `(delegation id, tool, input digest)` (**W2**,
`cacheKeyFor`), and **K10** keeps the DPoP proof out of `raw_input` altogether.
So the proof is not part of the key. Extend the cache to a network surface and a
second request bearing a *different* proof — or a replayed one, or none — hits
the same entry and is served an ALLOW **without that proof ever being verified**.
Caching there would not merely risk bypassing DPoP; it would bypass it by
construction.

Nor can the key be widened to include the proof. A proof is single-use
(**K8**), so every request would produce a distinct key and the hit rate would
be exactly zero — a cache that never hits is not a cache.

**Sender-constrained tokens therefore make W6 more necessary, not less.** Anyone
proposing to lift it for latency should read this paragraph first: the
performance argument is real, and there is no version of it that keeps
proof-of-possession intact.

**Why, and it is not a performance judgement.** A cache hit is defined by *not*
calling the PDP — and the PDP is the only component that verifies a token's
signature (**K2**). The PEP holds no verification key and reads the token with
`ParseUnverified`, which is sound precisely while the signature "has already
been checked elsewhere in the stack". A hit removes the only place it was ever
checked.

On a network surface the caller **is** the party being policed. A forged token —
arbitrary signature bytes, claims naming a known delegation and a far-future
expiry — would decode cleanly, build a cache key, satisfy all four **W3**
conditions, and be served a cached ALLOW without the PDP ever being contacted.
The attacker needs a delegation id, a tool, and the matching input, all
observable or guessable for routine operations.

`hook` and `mcp` are not exposed to this: the caller is local and already holds
the session file, which contains a real token. Reading it is strictly easier
than forging one, so the cache grants an attacker nothing they did not have.

**This is the A10 split again, one layer down.** A10 divided the surfaces by
whether a delegation reference arrives from a party the PEP can trust; W6
divides them by whether a decision may be replayed without re-authenticating
that party. Same boundary, same reason.

**C19 still closes.** "Every surface denies when there is no valid cache entry"
is trivially satisfied by a surface that has no cache: it always calls the PDP,
and an unreachable PDP already denies on all four surfaces.

**The consequence to document rather than hide:** outage tolerance exists only
on the locally-invoked surfaces. That is also where it is worth most — a laptop
losing connectivity — and least needed on a sidecar colocated with the PDP. An
operator must not infer from §4.8 that all four surfaces ride out an outage.

Reopening this needs the PEP to verify signatures itself, which means
distributing the public key and revisiting **K2**'s sole-verifier ruling
deliberately, not by omission.

---

### 4.8.1 Revocation epoch mechanics (2026-08-14)

§4.8 describes a monotonic per-tenant counter that every cached decision records
and validates against. **`tenant_epoch` has existed as a table since the
baseline migration and nothing has ever read or bumped it** — the invalidation
story the caching design rests on was never built. Four mechanics are settled
here, ahead of the cache that consumes them.

**V1 — the bump is a database trigger, not application code.** Any write to
`policies`, `agents`, `delegations`, `tool_catalog`, or `tier_overrides` bumps
that tenant's epoch **in the same transaction**.

Application-level bumping is the wrong layer here for a specific reason: under
**E7** and **T1** the control plane writes authorization configuration and the
PDP only reads it. So the bump would have to live in a component that does not
exist yet, and could be omitted by any future writer, any migration, or any
manual `UPDATE`. A trigger makes it atomic by construction and unforgettable —
the same move already made with `UNIQUE (tenant_id, tool_name)` and with
`GRANT`-as-enforcement. The cost is that it is invisible to a reader of Go, so
it is documented where a Go reader will look.

**V2 — expiry is deliberately not an epoch bump.** §4.8 lists a "delegation
expiry sweep" among the bump events. A delegation expiring is a state change
nobody writes: there is no event for a trigger to fire on, and adding a sweep
purely to manufacture one is machinery in service of the mechanism rather than
the goal.

Expiry is predictable from data a cache entry already holds, so it is checked
against the clock at serve time. **The split is what C24 tests**: the epoch
handles unpredictable *writes*, the recorded expiry handles predictable *time*.
Two kinds of invalidation, two mechanisms, neither pretending to be the other.

**V3 — `Decide` reads the epoch first, before any other read.** This is a
correctness property and it is easy to get backwards:

```
read policies at N -> bump to N+1 (a revocation) -> read epoch = N+1
   => the decision ignored the revocation but is labelled current.  UNSAFE.
```

Reading the epoch first means a decision can only ever be labelled **older**
than the state it reflects, so a consumer invalidates at least as eagerly as it
should and never less. Conservative in the safe direction.

**V4 — revocation enforcement already exists; only the write path is absent,
and that is by design.** `delegations.revoked` and `revoked_at` date from the
baseline migration, `idx_delegations_active` indexes on them, `DelegationLeg`
checks `Revoked` at every hop of the chain — so cascade revocation is already
literally true — and `IssueToken` refuses a revoked delegation. Nothing *sets*
`revoked`, because setting it is a control-plane write under **E7**/**T1**, not
a PDP one. The epoch's job is to make **cached** decisions honour a revocation
that the live path already honours.

---

### 4.10.3 The admin UI (2026-08-15)

§6.4 item 16 retains a React/Vite/shadcn UI, re-scoped to agent authorization.
It is the first non-Go artifact in this repository, which is most of what makes
it different from every other task.

**N12 — the operator's token lives in memory only.** Authorization code with
PKCE; never `localStorage`, never `sessionStorage`. A refresh loses it and
re-authenticates.

Implicit flow is deprecated and returns tokens in the URL fragment, where they
reach history and referrers. Storage APIs are readable by any XSS in the admin
UI, and **this token can revoke every delegation and approve any escalation in
the tenant** — the blast radius that makes the usual pragmatic answer wrong here.
The cost is real and accepted: silent renewal by hidden iframe is increasingly
blocked by third-party cookie restrictions, so a refresh means re-authenticating.

**Corrected 2026-08-15, during Task 6.** This paragraph originally said a
refresh "may mean a visible redirect." That is not achievable alongside
memory-only, and the contradiction was found by the implementer and confirmed
in review. A top-level redirect unloads the JS context, which destroys the PKCE
`code_verifier` — and the verifier must survive from the authorization request
to the token exchange. **Memory-only and top-level-redirect are mutually
exclusive**; the options are a popup, a storage API, or abandoning PKCE.

The flow is therefore a **popup**: a same-origin `callback.html` returns the
code to the opener by `postMessage` with an explicit `targetOrigin`, and the
opener validates origin, source, and `state` before believing it. No storage,
no fallback, and a blocked popup fails with an actionable error rather than
degrading. This carries one non-obvious dependency, recorded here because it is
invisible at the point where it would be broken: the flow **requires the
absence of a `Cross-Origin-Opener-Policy` header**. Adding `COOP: same-origin`
during a future hardening pass severs `window.opener` and every sign-in fails.

**N13 — the UI is embedded in the PAP binary, and its build, lint, and tests
join the standard gate.** One artifact, matching how the PDP and PEP ship.

The gate part is not optional. Nothing in `build`, `test`, `vet`, `lint`,
`conformance`, or `integration` would notice a UI that stopped compiling, and
this project has repeatedly found that an unexercised thing is a broken thing.
Embedding also introduces a build-order dependency, and with it a specific trap:
a placeholder that lets `go build` succeed against an empty directory ships an
empty admin UI silently. **A test must assert the embedded filesystem contains a
real build**, so an unbuilt UI fails the gate rather than deploying blank.

**N14 — the UI carries no authorization.** Hiding a button is not enforcement.
Every action is already refused server-side for an operator lacking the role,
and the UI only reflects that. Proven by a test that exercises the API directly
as a `viewer`, bypassing the client entirely.

**The policy screen does not display `effect` as truth.** This is precisely the
screen Phase 4a named when it removed `StoredPolicy.Effect` from the read path —
*"trusting this column at read time would let a PAP screen listing policies show
the opposite of what the policy does."* Since `effect` is meaningful only for
Cedar and JSON and a fixed sentinel for Rego and XACML, the UI shows it only
where it means something and shows the derived effect otherwise.

---

### 4.10.2 Authoring endpoints (2026-08-14)

§6.4 item 15 promises validation, test-against-sample-input, and dry-run replay.
**N6** already deferred replay behind **C17**. Three mechanics settle the rest.

**N9 — a test evaluates the candidate both alone and alongside the tenant's
existing policies, and returns both.** Deny-overrides makes isolation
misleading in exactly one direction: a candidate **deny** tested alone is
accurate, because a deny always wins the fold, while a candidate **allow**
tested alone is not — an existing `forbid` anywhere in the tenant makes it
irrelevant, and the endpoint would report success.

Authoring needs both answers. "Did I write this rule correctly" is the isolated
result; "will it change anything" is the folded one. `PolicyVerdict` already
carries `Source` and `PolicyID`, so attributing each verdict costs nothing.

**N10 — the response returns principal-leg verdicts and says so structurally.**
Policies produce only that leg; the agent and delegation legs are structural and
policy-independent. The response therefore states in its own payload that those
two were not evaluated, rather than in prose an operator will not read. An
`ALLOW` here means "no policy denied", never "this request would be permitted",
and the shape has to carry that distinction on its own.

**N11 — the derived tier is derived, not declared.** By default the tier comes
from the supplied raw input through the tenant's own catalog, so a test
exercises the same path production does, including the catalog and §4.4.1's
evidence rule. An explicit override remains available for hypotheticals — "what
happens at `DESTRUCTIVE`" is a legitimate question that should not require
crafting an input that derives there — and the response labels which was used.

A declared tier is spec defect **D1** on the decision path. On an authoring
endpoint it is a hypothesis, not an assertion, and the labelling is what keeps
those apart.

**Neither endpoint writes.** A dry-run that mutates is not a dry-run, and it is
asserted rather than documented. The response shape is deliberately not a
`DecideResponse`: this is the admin plane, unreachable by any agent, and a test
result must not be mistakable for an authorization even in a log.

---

### 4.10.1 Granting requires identity; taking away requires only a role (2026-08-14)

The admin plane performs three writes that look alike and are not. The epoch
trigger already encodes the difference: it fires on `tool_catalog` and on
`delegations` UPDATE/DELETE, and **deliberately not on `approvals`**, because an
approval does not change what an existing decision would evaluate to.

- **Tool catalog** — configuration; changes future decisions.
- **Revocation** — **reduces** authority, cascading to every descendant.
- **Approval** — **grants** authority, for one specific action.

**N7 — an approval requires the operator's identity to equal the approval's
`root_principal`. A role is necessary and never sufficient.**

**C21** routes an escalation to the chain's *root* principal precisely so a
chain cannot approve itself: at depth > 0 the immediate delegator is an agent,
and approval must reach the human at the root. If an `admin` role were enough,
that routing would be decorative, and an admin approving on another user's
behalf is the privilege amplification this product positions against.

Revocation carries no such requirement. **Taking authority away should require
less than giving it**, so a role check suffices there — the worst outcome of a
wrongly-scoped revocation is that something stops working, which fails closed.

**There is no override.** An escalation whose approver is unavailable times out
and denies, which is **C22**'s designed behaviour, not a gap. An override would
make C21 advisory rather than structural, and an override that exists is used
routinely rather than exceptionally.

**N8 — the operator's principal subject comes from a configured OIDC claim, and
when that claim is `email`, `email_verified` must be true.**

`approvals.root_principal` is a free-text subject populated from
`DecideRequest.Subject`, which a PEP sends from its own configuration — an email
in practice. An IdP's `sub` is opaque and will not match it, so a claim must be
nominated, exactly as roles are (**N2**).

The `email_verified` requirement closes a specific and otherwise invisible path:
some IdPs permit a self-asserted `email`, which would let an operator name
themselves any root principal and approve their own escalations. The resulting
audit row would look like a legitimate approval. One check, one config value,
and an impersonation path that would never have surfaced as a failure.

---

### 4.10 The admin plane (2026-08-14)

**A3** names `stratium-pap` as one of three artifacts and **A5** makes it
admin-only: policy, entitlement, agent, and override CRUD; UI backend; JWKS.
It does not exist. Four rulings made since — **E7** (approvals), **T1** (tool
catalog), **V1** (epoch bumps), **V4** (delegation revocation) — all defer
writes to "the control plane", so all four currently point at nothing and are
exercised only by tests writing directly to the database.

**N1 — single-tenant per process, tenant fixed at startup.** Exactly as every
PDP already works. A cross-tenant write becomes structurally impossible rather
than a check that must be right on every request — the same reasoning that made
RLS the only tenant boundary and an absent `GRANT` the enforcement. The cost is
operational: one admin plane per tenant.

This matters more here than anywhere else in the system. The PAP holds the write
credentials every other component is deliberately denied, and it is the
internet-facing plane. A per-request tenant resolution would make the boundary a
code path for the first time, with the widest possible credentials behind it.

**N2 — operator roles come from OIDC claims, never a table.** Identity is
standard OIDC against whatever IdP the customer runs, with **no bundled IdP and
no fallback** (§8) — the deleted `MockValidateToken` path is not to return in
any form. Roles (`viewer`, `editor`, `admin`) are read from a configured claim.

A roles table would need a bootstrap seed, and "who creates the first admin" is
the classic way an admin plane locks a tenant out of itself on day one. The
customer's IdP already knows who its administrators are; duplicating that into a
table creates a second source of truth that will drift.

**N3 — the PAP holds the writes the PDP is denied, and the PDP's grants do not
change.** It gets its own database role with `INSERT`/`UPDATE` on the
configuration tables. `stratium_app` keeps `SELECT` only on `approvals` and
`tool_catalog`; the absent grants there remain the enforcement of E7 and T1.

**N4 — every PAP write is audited into the same hash chain**, as new
`EventType` values beside `decision` and `delegation_created`. `audit_chain` is
owned by `stratium_audit_owner` with `INSERT`/`SELECT` granted to writers and
`UPDATE`/`DELETE` neutered by rules, so the append-only property holds for a
second writer exactly as it does for the first. A configuration change that is
not in the chain is a change nobody can attribute later.

**N5 — REST/JSON.** The UI is a browser client; the PDP stays gRPC. Two
protocols for two audiences, rather than one protocol serving neither well.

**N6 — dry-run replay against recorded decisions is deferred behind C17.**
§6.4 promises it, but §4.9 stores only `InputDigest` and never raw input, for a
stated reason: writing raw shell commands into an undeletable table before
per-tenant key management exists would be worse than not storing them.

So a replay can reuse a recorded **derived tier** but cannot **re-derive** one.
"Would this new policy have changed that past decision?" is answerable only for
decisions that did not turn on tier derivation. Validation and
test-against-sample-input need no recorded data and ship; replay does not, and
the gap is recorded rather than half-built.

---

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
| C17 | A decision's raw input is never retained; only its digest is recorded. (Restated 2026-08-18 — see §8.) |
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
| ~~Per-tenant encryption key management~~ **Resolved 2026-08-18 — not needed** | This entry read: *"§4.9 depends on per-tenant keys for crypto-shredding."* It does not, and the premise was overtaken by the build. §4.9 records `input_digest`, a SHA-256, and **never the raw input** — so there is no stored plaintext to encrypt, no key to hold, and none to destroy. Never recording is a stronger guarantee than encrypt-then-shred: no ciphertext to mishandle, no key-destruction procedure to get wrong, no window in which a leaked key exposes history. Building the original C17 would have required **first adding the retention it then protected against**. C17 is restated accordingly (§7); the drift guards that hold it are named in `internal/authz/conformance_test.go`. |
| Erasure of a tenant's audit history | The audit chain retains `actor`, `tool_name`, `action`, and `reason` per decision. That is the tenant-identifying content a real erasure request targets, and **nothing addresses it** — the old C17 did not either, since its wording only ever covered *inputs*. Surfaced by C17's restatement (2026-08-18) rather than absorbed by it. Hash-over-digest makes selective erasure feasible in principle: the chain covers `input_digest`, not those columns. The hard part is not the cryptography but the authorization model — who may erase, and how an append-only chain records that an erasure happened. |
| Trust-tier table overrides | §4.3 extends raise-only overrides to `actionTier → requiredTrustTier` by analogy with the action-tier table. Confirm or reverse. |
| Resource classification source | §3.9 R2/R3. No component supplies a resource's classification today; ZTDF was the prior source and was removed (§5.1). `CheckCap` now denies rather than silently passing when one is absent (correct — see R2), but that only makes the gap loud. Closing it needs a tenant-configured labelling mechanism — a resource registry, tags synced from wherever the underlying storage already classifies content, or an equivalent the tenant controls — not built here. |

### 8.1 Known tensions

Three places where two sound decisions rub. None blocks implementation; each needs a call.

1. **Dry-run replay has no inputs to replay (2026-08-18).** This item anticipated a conflict
   between replay and shredding. There is no conflict, because there is nothing shredded and
   nothing retained: §4.9 stores only `input_digest`. **N6 (dry-run replay) is therefore blocked
   by a deliberate retention choice, not by a missing subsystem** — a replay can reuse a recorded
   derived tier but cannot re-derive one. Unblocking it means deciding to retain inputs, which is
   a posture change and belongs in its own design, not a task. The original text follows.
   ~~Policy authoring replays recorded decision inputs.
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
