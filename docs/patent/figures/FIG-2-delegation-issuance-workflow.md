# Fig. 2 — Delegation Issuance Workflow

```mermaid
sequenceDiagram
    participant Principal
    participant Agent
    participant Gateway as Agent Gateway
    participant Identity as Identity Service
    participant Registry as Agent Registry
    participant Policy as Policy Engine
    participant Issuer as Authorization Issuer
    participant Audit as Audit Subsystem

    Principal->>Identity: Authenticate principal
    Agent->>Identity: Authenticate agent credentials
    Principal->>Gateway: Approve task / request delegation
    Agent->>Gateway: CreateDelegation(requested scope)
    Gateway->>Registry: Load agent metadata and trust tier
    Gateway->>Policy: Evaluate principal + agent + delegated scope
    Policy-->>Gateway: Compound decision and allowed bounds
    Gateway->>Issuer: Mint short-lived delegation artifact
    Issuer-->>Gateway: Signed delegation artifact
    Gateway->>Audit: Record delegation creation
    Gateway-->>Agent: Return scoped artifact
```

## Draft Notes

- Emphasizes issuance of a short-lived delegated artifact after compound evaluation.
- Can be converted into a formal sequence figure with numbered callouts.
