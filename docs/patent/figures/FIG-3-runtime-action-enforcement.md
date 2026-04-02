# Fig. 3 — Runtime Action Enforcement Workflow

```mermaid
flowchart TD
    A[Agent Sends Action Request<br/>with Delegation Artifact]
    B[Gateway Intercepts Request]
    C[Validate Artifact Integrity]
    D[Check Expiration / Revocation]
    E[Validate Tool, Action, Resource,<br/>and Classification Scope]
    F[Compute Compound Decision<br/>Principal AND Agent AND Delegation]
    G{Allow?}
    H[Forward Request to Protected Service]
    I[Return Deny / Modify / Escalate]
    J[Record Audit Event]
    K[Return Service Response]

    A --> B --> C --> D --> E --> F --> G
    G -->|Yes| H --> K
    G -->|No| I
    H --> J
    I --> J
```

## Draft Notes

- Focuses on inline mediation before the protected service executes the action.
- Preserves the core technical distinction from static bearer-token validation.
