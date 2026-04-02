# Invention Disclosure Form: Agent Authorization Workflow

## Invention Title

Task-Bound Runtime Authorization for Autonomous Software Agents

## Inventor Information

- Inventor name(s): `[insert legal names]`
- Residence / citizenship: `[insert as needed by counsel]`
- Primary contact: `[insert name, email, phone]`

## Business Context

- Product / platform: `Stratium`
- Functional area: agent authorization, delegated access control, platform security
- Related internal document: `docs/PRD_AGENT_AUTHORIZATION.md`

## Problem Statement

Autonomous and semi-autonomous agents need to act on behalf of users and other principals, but conventional authorization systems are user-centric or service-account-centric. Those systems do not reliably constrain an agent to a specific approved task, delegated scope, runtime context, or downstream delegation boundary.

This causes several technical problems:

- privilege amplification when an agent's standing privileges exceed the user's intended authority
- inability to distinguish user authority from agent authority in a single runtime decision
- uncontrolled propagation of permissions across sub-agents
- weak linkage between approval, delegated token issuance, executed actions, and resulting outputs
- limited ability to revoke or narrow authorization during live agent execution

## Core Invention

The invention issues a task-bound, machine-readable authorization artifact for an agent acting on behalf of a principal and enforces that artifact at runtime for each attempted action. Authorization is evaluated using a compound decision that includes at least principal authority, agent authority, and delegation authority. Child delegation is supported through derivative artifacts that cannot exceed parent scope. Audit and provenance records link approval, issuance, execution, delegation, and revocation.

## Key Novel Features

- double-hop or compound authorization combining principal, agent, and delegated scope
- short-lived delegation artifacts bound to a user-agent-session or task context
- runtime gateway enforcement for each tool or service invocation
- reduced-scope child delegation for multi-agent workflows
- per-hierarchy classification caps and resource constraints
- configurable maximum delegation depth
- dynamic narrowing or revocation during execution
- provenance linking approval, delegation chain, actions, and outputs

## High-Level Workflow

1. A principal authenticates or otherwise approves a task.
2. An agent authenticates using platform-recognized credentials.
3. The platform evaluates policies using principal attributes, agent attributes, and requested delegated scope.
4. The platform issues a bounded delegation artifact.
5. The agent presents the artifact when invoking tools or protected services.
6. A gateway or enforcement layer validates each request against the delegated scope and computes a compound authorization decision.
7. The platform optionally issues narrowed child artifacts for downstream agents.
8. The platform records provenance and supports revocation, expiration, or narrowing.

## Technical Components

- principal interface
- identity service
- agent registry
- policy engine
- authorization issuer
- gateway or enforcement layer
- delegation manager
- risk engine
- audit subsystem

## Example Scope Fields in the Delegation Artifact

- principal identifier
- agent identifier
- tenant identifier
- delegation identifier
- parent delegation identifier
- root delegation identifier
- approved tools
- approved actions
- maximum action tier
- classification caps
- resource constraints
- declared purpose
- conversation or session identifier
- issued-at and expiration timestamps

## Example Use Cases

- A research agent may search and summarize approved tenant documents but may not export original source content.
- A coding agent may inspect source files and generate proposed code changes while remaining prohibited from destructive operations.
- A support agent may access only records associated with a single tenant, case, or account.
- A planning agent may delegate a subtask to an execution agent using a narrower child delegation artifact.

## Technical Advantages

- enforces least privilege for autonomous agents
- prevents privilege amplification across user and agent identities
- enables safe multi-agent coordination
- supports real-time containment when behavior changes
- improves compliance, forensics, and explainability through lineage records

## Alternative Embodiments

- signed JWT-like artifact
- server-side capability record with opaque reference token
- gateway-based enforcement
- sidecar or middleware-based enforcement
- centralized revocation service
- distributed enforcement adapters for individual tools

## Potential Claim Focus Areas

- task-bound delegated authorization
- compound principal-agent-delegation decisioning
- derivative child authorization artifacts
- classification-aware delegated scope
- revocation propagation through delegation chains
- provenance graphs linking approval to action execution

## Closest Known Approaches to Distinguish

- role-based access control systems
- attribute-based access control systems
- OAuth and bearer-token delegation
- service-account authorization
- generic API gateway policy enforcement
- workflow approval systems without per-action delegated runtime checks
- agent frameworks without platform-enforced delegated scope lineage

## Distinguishing Characteristics

- authorization is bound to a specific task or delegated context rather than only identity or role
- every agent action is revalidated at runtime before execution
- child delegation is generated as a scope-reduced derivative, not a copy of broad credentials
- authorization decisions preserve lineage across multi-agent chains
- audit records connect policy issuance to resulting actions and outputs

## Development and Reduction to Practice

- Earliest concept date: `[insert date]`
- Prototype date: `[insert date]`
- First internal demo: `[insert date]`
- Production readiness: `[insert status]`
- Relevant repos / prototypes / demos: `[insert references]`

## Public Disclosure and Bar-Date Review

- Any public disclosure? `[yes/no]`
- If yes, date and venue: `[insert details]`
- Any public code repository exposure? `[yes/no]`
- Any customer demo, beta, or offer for sale? `[yes/no]`
- Need immediate filing before additional disclosure? `[yes/no]`

## Commercial Relevance

- enterprise AI governance
- agentic workflow orchestration
- regulated-industry automation
- zero-trust delegated execution
- secure tool-use platforms for LLM agents

## Supporting Materials to Gather

- architecture diagrams
- delegation token examples
- policy examples
- audit log samples
- screenshots or demos
- sequence diagrams for issuance and execution
- trust-tier documentation

## Filing Notes

- A provisional filing can usually be prepared quickly from the specification and figures if an early priority date is the immediate goal.
- A later nonprovisional can expand claim coverage after prior-art review and attorney refinement.
- Recommended USPTO references:
  - https://www.uspto.gov/patents/basics/apply/provisional-application
  - https://www.uspto.gov/patents/basics/types-patent-applications
