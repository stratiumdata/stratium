# Attorney-Style Nonprovisional Package: Agent Authorization Workflow

## Purpose

This document organizes the existing patent materials into a nonprovisional-oriented handoff package for patent counsel. It is intended to streamline preparation of a U.S. utility application based on Stratium's agent authorization workflow.

## USPTO-Oriented Framing

The USPTO states that the elements of a nonprovisional utility application generally include an application transmittal form, fee transmittal form, application data sheet, specification, drawings, and executed oath or declaration. The USPTO also states that the specification should include, in order, the title, any cross-reference to related applications, any government-support statement, background, summary, brief description of drawings, detailed description, at least one claim, and an abstract.

Official references:

- https://www.uspto.gov/patents/basics/types-patent-applications
- https://www.uspto.gov/patents/basics/apply/provisional-application

## Proposed Assembly Order

### Administrative Filing Materials

- application transmittal form
- fee transmittal form
- application data sheet
- executed inventor oath or declaration

### Technical Filing Materials

- specification based on `docs/patent/01-patent-specification-draft.md`
- claims based on `docs/patent/02-claim-set.md`
- drawings based on `docs/patent/03-figure-descriptions.md`
- abstract drawn from the specification summary

### Counsel Support Materials

- invention disclosure in `docs/patent/04-invention-disclosure-form.md`
- provisional-oriented summary in `docs/patent/05-provisional-ready-package.md`
- product and architecture context in `docs/PRD_AGENT_AUTHORIZATION.md`

## Suggested Nonprovisional Specification Structure

Patent counsel can assemble the nonprovisional specification in this order:

1. Title
2. Cross-reference to related applications
3. Statement regarding federally sponsored research or development, if applicable
4. Names of parties to any joint research agreement, if applicable
5. Background
6. Brief summary
7. Brief description of drawings
8. Detailed description
9. Claims
10. Abstract

## Attorney Handoff Summary

### Invention Theme

The invention concerns task-bound authorization of autonomous or semi-autonomous agents, with runtime enforcement and delegation containment. The core novelty emphasis is not merely authorizing an AI agent, but enforcing a bounded, machine-readable delegation scope during actual execution and across downstream agent chains.

### Likely Novelty Anchors

- compound authorization requiring principal authority, agent authority, and delegated authority
- short-lived delegation artifacts tied to a task, session, or conversation context
- gateway-mediated runtime enforcement for each agent action
- derivative child delegation with strict subset enforcement
- per-hierarchy classification caps and resource constraints
- delegation lineage through root and parent delegation identifiers
- dynamic narrowing and revocation during execution
- provenance linking approval, action, delegation, and output

### Implementation Context

The current Stratium model includes:

- registered agents with trust tiers
- short-lived, platform-minted delegation tokens
- compound policy evaluation
- bounded action sensitivity tiers
- classification caps by hierarchy
- delegation chain depth limits
- gateway-mediated forwarding to protected services
- audit logging and chain lineage

## Draft Claim Strategy

### Primary Independent Method Claim

Focus on receiving a task request, identifying principal and agent, generating a bounded authorization artifact, intercepting agent actions, computing a compound decision, and selectively permitting or denying runtime execution.

### Primary System Claim

Focus on a system including policy engine, issuer, gateway, delegation manager, risk engine, and audit subsystem that collectively enforce the delegated scope.

### Primary Medium Claim

Focus on instructions causing a processor to generate task-bound authorization, validate runtime action requests, issue derivative child scope, and record provenance.

### Dependent Claim Clusters

- cryptographic signing and artifact integrity
- classification caps and resource constraints
- trust-tier-based action limits
- derivative child authorization
- maximum delegation depth
- dynamic revocation and narrowing
- audit lineage and tamper-evident records
- denial attribution identifying which policy component denied

## Counsel Questions to Resolve

### Priority and Disclosure

- Has any public disclosure already occurred?
- Is there a need to claim priority to an earlier provisional?
- Are there foreign filing considerations that affect timing?

### Inventorship

- Which contributors conceived of the compound authorization model?
- Which contributors conceived of child delegation narrowing and lineage?
- Which contributors conceived of classification-cap delegation and chain-depth controls?

### Claim Breadth

- Should claims emphasize AI agents specifically or remain software-agent neutral?
- Should the gateway be claimed as a required component or as one optional enforcement embodiment?
- Should classification caps be core claim language or a dependent fallback position?

### Prior-Art Positioning

- What prior internal or external systems used delegated tokens before this concept?
- How should OAuth, ABAC, and API-gateway prior art be distinguished most aggressively?
- Are there known agent frameworks with tool gating but without compound delegated runtime authorization?

## Open Fact Fields for Counsel to Populate

- inventor legal names
- residence information
- entity status
- assignee information
- government rights statement, if any
- related applications, if any
- earliest conception date
- earliest reduction-to-practice date
- disclosure history

## Recommended Drawing Set

- system architecture block diagram
- delegation issuance sequence diagram
- runtime enforcement sequence diagram
- multi-agent derivative delegation sequence diagram
- revocation or narrowing sequence diagram
- provenance lineage graph

## Recommended Next Drafting Moves

1. Convert `docs/patent/01-patent-specification-draft.md` into full nonprovisional section ordering.
2. Expand `docs/patent/02-claim-set.md` into a broader prosecution set with multiple fallback trees.
3. Generate formal line-drawing figures from `docs/patent/03-figure-descriptions.md`.
4. Complete inventor and disclosure facts in `docs/patent/04-invention-disclosure-form.md`.
5. Run counsel-led prior-art review and revise claims before filing.

## Internal Packaging Recommendation

For internal use, treat the following as the current attorney packet:

- `docs/patent/01-patent-specification-draft.md`
- `docs/patent/02-claim-set.md`
- `docs/patent/03-figure-descriptions.md`
- `docs/patent/04-invention-disclosure-form.md`
- `docs/patent/05-provisional-ready-package.md`
- `docs/patent/06-nonprovisional-attorney-package.md`
- `docs/PRD_AGENT_AUTHORIZATION.md`

## Drafting Notes

- Keep the specification broad enough to cover non-LLM agents, enterprise workflow agents, and service-side orchestration agents.
- Preserve alternative embodiments so counsel can support broader claims and fallback positions.
- Tie every claimed feature back to adequate written-description support in the specification and drawings.
