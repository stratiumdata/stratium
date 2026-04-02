# Fig. 5 — Dynamic Narrowing and Revocation Workflow

```mermaid
flowchart TD
    A[Active Delegation Artifact in Use]
    B[Monitor Runtime Signals]
    C{Risk / Policy Event?}
    D[Continue Execution]
    E[Compute Narrow or Revoke Decision]
    F{Narrow or Revoke?}
    G[Update Artifact State]
    H[Propagate Status to Gateway / Child Delegations]
    I[Block or Constrain Future Actions]
    J[Record Revocation / Narrowing Event]

    A --> B --> C
    C -->|No| D --> B
    C -->|Yes| E --> F
    F -->|Narrow| G
    F -->|Revoke| G
    G --> H --> I --> J
```

## Draft Notes

- Captures dynamic behavior during execution rather than only issuance-time control.
- Works well as the basis for a patent sequence or flow figure.
