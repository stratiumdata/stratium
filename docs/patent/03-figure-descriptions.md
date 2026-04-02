# Figure Descriptions: Agent Authorization Workflow

## Figure List

- `Fig. 1` — System architecture for task-bound agent authorization
- `Fig. 2` — Delegation issuance workflow
- `Fig. 3` — Runtime action enforcement workflow
- `Fig. 4` — Multi-agent delegated authorization chain
- `Fig. 5` — Dynamic narrowing and revocation workflow
- `Fig. 6` — Provenance and audit lineage graph

## Detailed Figure Descriptions

### Fig. 1 — System Architecture for Task-Bound Agent Authorization

`Fig. 1` depicts an example system including a principal device or principal-facing interface, an identity service, an agent registry, a policy engine, an authorization issuer, an agent gateway, one or more protected platform services, a delegation manager, a risk engine, and an audit store.

The figure should show that a principal submits or approves a task, an agent authenticates to the platform, and the platform issues a delegation artifact that is later enforced by the gateway before the gateway forwards permitted requests to protected services. The figure should also show that audit events and delegation lineage are preserved.

Suggested drawing callouts:

- `102` principal interface
- `104` identity service
- `106` agent registry
- `108` policy engine
- `110` authorization issuer
- `112` agent gateway
- `114` protected services
- `116` delegation manager
- `118` risk engine
- `120` audit subsystem

### Fig. 2 — Delegation Issuance Workflow

`Fig. 2` depicts a flow in which a principal and an agent authenticate, a delegated authorization request is received, policy inputs are evaluated, requested scope is compared against permitted scope, and a short-lived delegation artifact is issued.

Suggested sequence:

1. Principal authenticates
2. Agent authenticates
3. Request for delegation is submitted
4. Policy engine evaluates principal, agent, and requested scope
5. Optional trust-tier and classification checks are applied
6. Scoped delegation artifact is minted
7. Delegation record is stored
8. Artifact is returned to the agent runtime

The figure should emphasize that the artifact is bound to a specific delegated context rather than broad standing permissions.

### Fig. 3 — Runtime Action Enforcement Workflow

`Fig. 3` depicts the runtime path for an agent-initiated action. The agent presents the delegation artifact with an action request. The gateway intercepts the request, validates token integrity and scope, computes a compound authorization decision, and either denies the action or forwards it to a protected service.

Suggested decision branches:

- validate signature or integrity
- validate expiration and revocation status
- validate action against approved tools and actions
- validate resource and classification boundaries
- compute principal, agent, and delegation decisions
- allow, deny, modify, or escalate
- record audit event

The figure should make clear that enforcement occurs before the target service executes the requested action.

### Fig. 4 — Multi-Agent Delegated Authorization Chain

`Fig. 4` depicts a parent agent delegating a subtask to a child agent through issuance of a derivative authorization artifact. The figure should show a root delegation identifier, parent delegation identifier, reduced child scope, and bounded delegation depth.

Suggested elements:

- root principal approval
- parent delegation artifact
- child delegation request
- scope-subset validation
- child delegation artifact
- child agent execution
- lineage record written to audit store

The figure should emphasize that child scope cannot exceed parent scope and that delegation chains remain traceable.

### Fig. 5 — Dynamic Narrowing and Revocation Workflow

`Fig. 5` depicts runtime risk monitoring and revocation. The figure should show an active delegation artifact being monitored by a risk engine or policy update path. Upon detection of an anomaly, policy change, trust-tier downgrade, or explicit revocation, the system marks the artifact as revoked or narrowed and distributes that state to enforcement points.

Suggested flow:

1. Active artifact is in use
2. Risk or policy event is detected
3. Revocation or narrowing decision is computed
4. Artifact state is updated
5. Child delegations are revoked or frozen
6. Future actions are denied or constrained
7. Revocation event is logged

### Fig. 6 — Provenance and Audit Lineage Graph

`Fig. 6` depicts a graph or linked-record structure connecting:

- principal approval
- agent registration
- delegation artifact issuance
- tool invocation events
- child delegation events
- target-service responses
- output generation
- revocation or expiration

The figure should show that each node is linked by identifiers such as principal ID, agent ID, delegation ID, parent delegation ID, and root delegation ID, allowing reconstruction of the full authorization-to-execution chain.

## Drafting Notes for Counsel or Illustrator

- Prefer sequence diagrams for `Fig. 2` through `Fig. 5`.
- Prefer a component block diagram for `Fig. 1`.
- Prefer a graph or lineage diagram for `Fig. 6`.
- Keep labels technology-neutral enough for claim flexibility, but preserve the core concepts of task-bound scope, compound decisioning, derivative delegation, and audit lineage.
