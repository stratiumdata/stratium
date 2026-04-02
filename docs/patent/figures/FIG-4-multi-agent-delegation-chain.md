# Fig. 4 — Multi-Agent Delegated Authorization Chain

```mermaid
flowchart LR
    P[Principal Approval]
    A1[Parent Agent]
    G[Delegation Manager / Gateway]
    D1[Root Delegation Artifact<br/>Root ID = R1]
    A2[Child Agent]
    D2[Child Delegation Artifact<br/>Parent ID = D1<br/>Root ID = R1]
    A3[Grandchild Agent]
    D3[Grandchild Artifact<br/>Parent ID = D2<br/>Root ID = R1]
    AU[Audit / Lineage Store]

    P --> A1
    A1 -->|Request Delegation| G
    G -->|Issue Root Scope| D1
    D1 --> A1
    A1 -->|Request Narrowed Child Scope| G
    G -->|Subset Validation| D2
    D2 --> A2
    A2 -->|Request Further Narrowed Scope| G
    G -->|Depth + Subset Validation| D3
    D3 --> A3
    D1 --> AU
    D2 --> AU
    D3 --> AU
```

## Draft Notes

- Illustrates root and parent identifiers, reduced-scope derivation, and chain lineage.
- Formal drawings can add explicit subset labels for tools, actions, and classification caps.
