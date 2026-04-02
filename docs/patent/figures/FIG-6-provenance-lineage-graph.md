# Fig. 6 — Provenance and Audit Lineage Graph

```mermaid
flowchart LR
    PA[Principal Approval]
    AR[Agent Registration]
    DI[Delegation Issuance]
    TI1[Tool Invocation 1]
    TI2[Tool Invocation 2]
    CD[Child Delegation]
    TI3[Child Agent Invocation]
    OR[Output / Result]
    RV[Revocation or Expiration]

    PA --> DI
    AR --> DI
    DI --> TI1
    DI --> TI2
    DI --> CD
    CD --> TI3
    TI1 --> OR
    TI2 --> OR
    TI3 --> OR
    DI --> RV
    CD --> RV
```

## Draft Notes

- Shows how approval, delegation, execution, child delegation, outputs, and revocation remain linked.
- Patent drawings can later convert this into a node-link lineage figure with identifiers.
