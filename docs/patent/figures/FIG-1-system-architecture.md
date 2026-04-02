# Fig. 1 — System Architecture for Task-Bound Agent Authorization

```mermaid
flowchart LR
    P[Principal Interface 102]
    I[Identity Service 104]
    AR[Agent Registry 106]
    PE[Policy Engine 108]
    AI[Authorization Issuer 110]
    AG[Agent Gateway 112]
    TS[Protected Services 114]
    DM[Delegation Manager 116]
    RE[Risk Engine 118]
    AU[Audit Subsystem 120]
    AGT[Agent Runtime]

    P -->|Task Request / Approval| AG
    AGT -->|Agent Authentication| I
    P -->|Principal Authentication| I
    I --> AG
    AG --> AR
    AG --> PE
    PE --> AI
    AI -->|Scoped Delegation Artifact| AGT
    AGT -->|Tool / Service Invocation| AG
    AG -->|Runtime Enforcement| TS
    AG --> DM
    DM --> AG
    RE --> AG
    AG --> AU
    DM --> AU
    PE --> AU
    TS --> AU
```

## Draft Notes

- Shows the principal, agent runtime, policy controls, issuer, gateway, protected services, and audit path.
- The main invention points are task-bound artifact issuance and runtime enforcement at the gateway.
