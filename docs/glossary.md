# Glossary

Short definitions, each linking to where the term is explained properly. Where
two terms are commonly confused, the entry says so.

## Planes

**PDP (Policy Decision Point)**
:   `stratium-pdp`. Answers one RPC, `Decide`. Derives the action tier,
    resource identity, and classification itself, and verifies every token.
    One process serves exactly one tenant for its whole life.
    [Concepts §3](concepts.md#3-three-planes)

**PAP (Policy Administration Point)**
:   `stratium-pap`. The admin plane and admin UI: policies, agents, tool
    catalog, label rules, approvals, audit. Authenticates humans over OIDC. The
    only internet-facing component.

**PEP (Policy Enforcement Point)**
:   `stratium-pep`, or the Python SDK. Runs beside the agent, forwards the tool
    call verbatim, and enforces the answer. **Untrusted by design**: it decides
    nothing. [The six surfaces](pep/README.md)

## The decision

**Three legs**
:   Every decision is `allow = principal ∧ agent ∧ delegation`. Because they are
    ANDed, an ALLOW from a policy engine can never override the other two.
    [Concepts §4](concepts.md#4-what-a-decision-is-made-of)

**Principal leg**
:   May this *person* do this at all? Answered by the tenant's policies, written
    in Cedar, Rego, XACML, or JSON, side by side.

**Agent leg**
:   Is this *agent* enabled, trusted enough for this action, and allowed this
    tool?

**Delegation leg**
:   Does the authority the person granted reach this far, at every hop of the
    chain?

**Fail closed**
:   Anything ambiguous denies: an unset field, a policy that could not be
    evaluated, a label that cannot be ranked, a chain that is not well formed.

## Tiers

!!! warning "Two scales, easily confused"
    The *action tier* measures how dangerous a call is. The *trust tier*
    measures how much an agent is trusted. Almost every misunderstanding starts
    by merging them.

**Action tier**
:   How dangerous a call is, derived by the PDP from the arguments on each call:
    `REASONING` (0), `READ_ONLY` (1), `INTERNAL_MODIFY` (2), `EXTERNAL_COMMS`
    (3), `DESTRUCTIVE` (4). [Concepts §5](concepts.md#5-agent-trust-tiers--depth)

**Trust tier**
:   How much an agent is trusted, set by an operator on the registered agent:
    `UNVERIFIED` (0), `REGISTERED` (1), `CERTIFIED` (2), `PLATFORM_TRUSTED` (3).
    It is asserted, not attested.

**Trust table**
:   Maps each action tier to the minimum trust tier allowed to attempt it. An
    action tier missing from the table requires the *highest* trust.

**Tool catalog**
:   Per-tenant rows assigning tiers to tool names. One input to the action
    tier, alongside tenant overrides, a built-in command classifier, and a
    floor. Evidence of a destructive or external call in the raw input is only
    ever raised, never lowered.

**Tool allowlist**
:   An optional per-agent list of permitted tools. **An empty list means
    unrestricted**, not "no tools".

## Delegation

**Delegation**
:   A grant of authority from a person to an agent, bounded on every dimension:
    tools, maximum action tier, escalation threshold, classification caps,
    resource constraints, and expiry.

**Root delegation**
:   The first hop, minted from an authenticated human and clamped to what that
    person's own policies show they hold. Copies the agent's classification
    caps. The PDP verifies the person's OIDC token at session start and reads
    the principal from it, not from the request.

**Delegation chain**
:   Root → child → grandchild, each a subset of the one above. Verified
    root-first on every decision, so revoking any hop denies everything below
    it immediately. Maximum depth is configurable (default 5).
    [Concepts §7](concepts.md#7-the-delegation-chain--depth)

**Narrowing**
:   A child may equal or tighten its parent on every dimension, never widen
    one. Leaving out a constraint the parent set counts as widening, and so does
    adding a dimension the parent left open.

**Delegation token**
:   A small signed JWT whose subject is a delegation id. It identifies which
    delegation is being presented. It does not carry the chain, and it is
    authentication, never authorization.

**DPoP / sender-constrained token**
:   A delegation token bound to a key its holder must prove possession of
    (RFC 9449), so a stolen token is useless alone. Required on the network
    surfaces. [Release note](releases/2026-08-17-sender-constrained-tokens.md)

**Session**
:   What `stratium-pep session-start` creates: a root delegation for one agent
    session, written to a local session file that `hook` and `mcp` read.
    [session-start](pep/session-start.md)

## Classification

**Hierarchy**
:   An ordered list of levels. Two ship: `nato` (`UNCLASSIFIED` …
    `TOP-SECRET`) and `commercial` (`PUBLIC` … `HIGHLY-CONFIDENTIAL`).

**Label rule**
:   A tenant rule mapping a resource-identity prefix to a `(hierarchy, level)`.
    The longest matching prefix wins. There is no default level; write an
    empty-prefix catch-all. [Concepts §6](concepts.md#6-classification-caps--depth)

**Classification cap**
:   A per-hierarchy ceiling carried by a delegation. Set by an administrator on
    the agent, copied onto the root, narrowed by each child. Under a cap, an
    unlabelled resource **denies**.

**Resource identity**
:   The resource a call touches, as the PDP extracts it from the arguments,
    never as the caller names it. For a shell tool, every path in the command
    is an identity, and the strictest label decides.

**`id_prefix`**
:   The one resource constraint with prefix semantics: a child may go deeper
    into its parent's prefix. Every other constraint narrows by exact match.

## Operations

**Escalation**
:   A threshold at or above which a call waits for a human rather than being
    allowed. An admin sets it on the agent, and each session copies it; a
    session may lower it, never raise or remove it. A call in the band creates
    a pending **approval** the person the agent acts for resolves in the PAP,
    layered on top of a fresh three-leg evaluation, never instead of one.
    [Require approval for risky actions](journeys/require-approval.md)

**Epoch**
:   A per-tenant counter, bumped by a database trigger on every configuration
    write, that invalidates every cached decision at once.

**Decision cache**
:   Gives outage tolerance on `mcp`. It lives in the `mcp` process's memory for
    the life of that process. Never used for escalations, on `hook`, or on the
    network surfaces.

**Tenant**
:   Startup configuration, never a request field. Isolated by Postgres
    row-level security on every table. "Belongs to another tenant" and "does
    not exist" look the same by design.

**Audit chain**
:   Every decision, recorded whatever the outcome, in an append-only,
    hash-linked log. A failed audit write fails the call. Raw tool inputs are
    stored only as a digest. Readable through `GET /v1/audit`.

**Containment**
:   `POST /v1/containment`: does a candidate permission set allow anything a
    baseline forbids? Read-only. An agent-grant write that widens is allowed
    but recorded as a `containment` audit event.
    [User guide §5.11](user-guide.md#511-containment--what-a-change-widens)

**Effective permissions**
:   `GET /v1/principals/{id}/effective`: the union of everything a person's
    concurrent delegations can reach. A report, not enforced, because separate
    delegations are not checked against each other.
