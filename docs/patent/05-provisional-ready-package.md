# Provisional-Ready Package: Agent Authorization Workflow

## Purpose

This document repackages the current invention materials into a provisional-oriented format for rapid attorney review and filing preparation. It is designed to support an early priority filing around Stratium's task-bound and delegated agent authorization architecture.

## USPTO-Oriented Framing

For a U.S. provisional application, the USPTO states that a provisional application is not required to include formal claims or an oath or declaration, but it must include a written description that satisfies the disclosure requirement and should include any drawings necessary to understand the invention. The USPTO also states that the provisional must name all inventors and include a cover sheet and filing fee. This package is drafted to maximize disclosure support while keeping the package fast to finalize for filing.

Official references:

- https://www.uspto.gov/patents/basics/apply/provisional-application
- https://www.uspto.gov/patents/basics/types-patent-applications

## Recommended Provisional Filing Set

Use the following as the filing-oriented package:

1. `docs/patent/01-patent-specification-draft.md`
2. `docs/patent/03-figure-descriptions.md`
3. Drawings based on the figures described in `docs/patent/03-figure-descriptions.md`
4. Inventor and administrative details from `docs/patent/04-invention-disclosure-form.md`
5. This checklist document

Optional but recommended for internal preservation of claim concepts:

6. `docs/patent/02-claim-set.md`

## Provisional Filing Checklist

### Administrative Items

- confirm all inventors are identified
- confirm title of invention
- confirm correspondence address
- confirm inventor residence information
- confirm whether any U.S. government funding statement is required
- confirm whether any public disclosure has already occurred
- confirm target filing date

### Disclosure Sufficiency Items

- include full written description of the delegated authorization workflow
- include the double-hop or compound decision model
- include delegation artifact fields and scope boundaries
- include child delegation and scope narrowing behavior
- include runtime enforcement flow
- include revocation and dynamic narrowing behavior
- include provenance and audit lineage
- include alternative embodiments and implementation variations

### Drawings Items

- prepare at least one architecture diagram
- prepare at least one sequence diagram for delegation issuance
- prepare at least one sequence diagram for runtime enforcement
- prepare at least one sequence diagram for child delegation
- prepare at least one diagram for revocation or lineage

### Bar-Date and Priority Items

- confirm no public disclosure older than one year in the United States
- confirm whether any foreign filing strategy is contemplated
- confirm whether immediate filing is needed before demos, customer distribution, or repository publication
- confirm date by which nonprovisional follow-on must be filed to claim benefit

## Provisional-Style Draft Text

### Title

Systems and Methods for Task-Bound Authorization of Autonomous Software Agents

### Technical Field

The disclosure relates to computer security, identity and access management, distributed systems, and runtime control of autonomous or semi-autonomous software agents.

### Problem Addressed

Autonomous agents increasingly perform actions on behalf of users, tenants, services, and other principals. Existing user-centric and service-account-centric authorization models do not adequately constrain agents to a particular approved task, execution scope, or delegation boundary. This can result in privilege amplification, overbroad tool access, poor containment of downstream delegation, and limited forensic traceability.

### Summary of the Invention

In one embodiment, a platform receives a task request associated with a principal and identifies an agent authorized to act on the principal's behalf. The platform evaluates principal permissions, agent permissions, and explicitly delegated scope using a compound policy decision. The platform issues a short-lived authorization artifact that is bound to the delegated context and defines a bounded permission envelope for the agent.

At runtime, a gateway or similar mediation layer intercepts each attempted tool or service invocation by the agent and validates the invocation against the authorization artifact. If the action is within scope and the compound decision resolves to allow, the request is forwarded to a protected service. If not, the request is denied, modified, or escalated.

In some embodiments, a first agent delegates a subtask to a second agent only through issuance of a derivative authorization artifact that is equal to or narrower than the parent artifact. In some embodiments, the platform dynamically narrows or revokes authorization in response to anomaly detection, policy changes, trust-tier changes, or other execution conditions. The platform also records provenance linking approval, authorization issuance, delegation events, executed actions, and resulting outputs.

### Representative Embodiments

#### Embodiment 1: Compound Authorization

Authorization is computed from the intersection of:

- authority of the principal
- authority of the acting agent
- explicitly delegated scope

This model prevents either the principal or the agent from unilaterally expanding effective permission.

#### Embodiment 2: Delegation Artifact

The system issues a machine-readable artifact containing one or more of:

- principal identifier
- agent identifier
- tenant identifier
- delegation identifier
- root delegation identifier
- parent delegation identifier
- approved tools
- approved actions
- maximum action tier
- classification caps
- resource constraints
- declared purpose
- session or conversation identifier
- issued-at and expiration timestamps
- chain depth and chain lineage fields

#### Embodiment 3: Runtime Enforcement

Each agent action is intercepted before execution. The system validates:

- integrity and authenticity of the delegation artifact
- expiration and revocation status
- allowed tool and action scope
- resource and classification boundaries
- compound authorization outcome

#### Embodiment 4: Child Delegation

The system allows multi-agent workflows by issuing child artifacts that remain within a subset of the parent scope. In some embodiments:

- tools can only be removed, not added
- action sensitivity can only narrow
- resource access can only narrow
- classification caps can only narrow
- delegation depth is bounded

#### Embodiment 5: Revocation and Provenance

The system supports revocation, narrowing, and post-hoc verification. Audit records may connect:

- principal approval
- agent registration
- policy evaluation
- artifact issuance
- runtime invocation
- child delegation
- revocation
- generated outputs

### Example Use Cases

- A research agent can search internal documents and produce summaries but cannot export source material.
- A coding agent can inspect and modify specified repositories but cannot perform destructive actions above its delegated action tier.
- A support agent can query records for a particular tenant and case but cannot access unrelated customer data.
- A planning agent can create a narrowed child delegation for an execution agent.

## Information to Fill Before Filing

- inventor legal names
- inventor residences
- filing entity status
- exact title to be used
- any government-interest statement
- public disclosure history
- target filing date
- whether draft figures will be line drawings or converted attorney figures

## Internal Recommendation

For speed, file the provisional with the broad technical narrative, detailed architecture, and figures first. Preserve the richer claim ideas and prosecution variants from `docs/patent/02-claim-set.md` for follow-on nonprovisional work.
