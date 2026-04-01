# PRD: AI Agent Authorization

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-03-27
**Feature Flag:** `agent-auth`

---

## Design Decisions

Key architectural decisions made during PRD development:

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| Delegation tokens | Stratium-minted (JWT, short-lived) | External tokens, hybrid model |
| Gateway architecture | New gRPC service (`:50054`) | Middleware in existing services, sidecar/proxy |
| Policy evaluation | Single compound policy (extend `GetDecision`) | Two sequential calls, chained RPC with short-circuit |
| Agent ecosystem | Open (any agent can register) | Internal-only, internal + partner |
| Agent registration | Admin-only via PAP API | Self-service API, self-service + automated certification |
| Trust tiers | 4-tier model (Unverified → Platform-trusted) | Binary trust, continuous trust scoring |
| Response disclosure | No filtering — auth happens pre-action | Field-level filtering, classification-based gating |
| SDK scope | All 4 SDKs (Go, Java, Python, JavaScript) | Python-only initially, API-first with SDK later |
| Approval workflow | Policy-only for V1 (no interactive approvals) | Synchronous approval gates, async approval queue |
| Intent normalization | Hybrid — agent normalizes, Stratium validates | Agent-only responsibility, Stratium Plan Normalizer |
| Feature flag | Single toggle (`AGENT_AUTH_ENABLED`) | Granular per-feature flags, per-tenant flags |
| Audit trail | Extend existing `audit_logs` table | Separate agent audit ledger, both summary + detail |
| Action tiers | 5-tier sensitivity model (reasoning → destructive) | 3-tier simplified, custom per-tenant |
| ZTDF delegation scope | Per-resource classification caps (per-hierarchy) | Inherit user classification, single max_classification |
| Deployment | Same model as existing services (Docker, mTLS, shared DB) | Co-located with Platform, standalone with own DB |
| Delegation chain model | Linked chain tokens (`parent_delegation_id`) | Single token with embedded chain, nested signed tokens (matroyshka) |
| Max delegation depth | 5 (configurable via env var) | Depth 3, unlimited (policy-controlled) |
| Child delegation auth | Full policy evaluation for each child creation | Gateway-only scope narrowing check, parent agent decides |
| In-flight token expiry | Point-in-time authorization (action completes once ALLOW granted) | Grace period window, pre-flight TTL check, both combined |

---

## 1. Problem Statement

AI agents are increasingly acting on behalf of users — making API calls, accessing data, and executing workflows through tool invocations. When an AI agent calls Stratium's services (KAS, Key Manager, Platform), the platform currently treats the request as coming from a single authenticated identity. There is no mechanism to distinguish between a user acting directly and an AI agent acting on the user's behalf.

This creates a **delegated authorization gap**:

- If only the agent's service identity is authorized, the user can borrow the agent's privileges (privilege amplification).
- If only the user is authorized, the platform ignores that the agent itself may not be trusted for certain actions, tools, or data classifications.

The platform needs a **double-hop authorization model** where every agent action is evaluated against both the user's permissions and the agent's permissions within a delegation context.

### Core Principle

> An AI agent may only act within the cryptographically verifiable intersection of user authority, agent authority, delegated scope, and contextual policy.

---

## 2. Goals

1. **Authorize the double hop** — evaluate both user and agent permissions in a single compound policy decision for every agent-initiated action.
2. **Prevent privilege amplification** — an agent acting on behalf of a user cannot exercise authority beyond the user's effective rights (unless operating under explicit system authority).
3. **Support an open agent ecosystem** — any agent can be registered and governed, with a 4-tier trust model controlling autonomy.
4. **Feature-flagged deployment** — the entire capability is gated behind `AGENT_AUTH_ENABLED` (build-time ldflags, consistent with existing feature flags).
5. **Extend all 4 SDKs** — Go, Java, Python, and JavaScript clients gain agent authentication and delegation token flows.
6. **Maintain backward compatibility** — when disabled, agent requests are treated as regular user requests with zero behavioral change.

### Non-Goals (V1)

- Interactive human approval workflows (Phase 2).
- Response disclosure filtering (authorization is pre-action; once allowed, the response flows unfiltered).
- Stratium-hosted LLM or prompt parsing (agent frameworks handle intent decomposition).
- Real-time trust scoring (V1 uses static trust tiers, not behavioral scoring).

---

## 3. Architecture Overview

### 3.1 New Service: Agent Gateway (`:50054`)

A new gRPC service that sits between AI agents and Stratium's existing services. All agent-initiated actions route through it.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        AI Agent Frameworks                          │
│         (LangChain / CrewAI / AutoGen / Custom)                     │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             │ gRPC + Delegation Token
                             │
                    ┌────────▼──────────┐
                    │  Agent Gateway    │
                    │  Service          │
                    │  (gRPC:50054)     │
                    │                   │
                    │  • Delegation     │
                    │    Token Minting  │
                    │  • Action         │
                    │    Validation     │
                    │  • Compound       │
                    │    Policy Eval    │
                    │  • Agent Registry │
                    │  • Audit Logging  │
                    └──┬────┬────┬──────┘
                       │    │    │
            ┌──────────┘    │    └──────────┐
            │               │               │
       ┌────▼───────┐  ┌────▼──────┐  ┌─────▼──────┐
       │ Platform   │  │ Key Mgr   │  │ Key Access │
       │ :50051     │  │ :50052    │  │ :50053     │
       └────────────┘  └───────────┘  └────────────┘
```

### 3.2 Authorization Flow

```
AI Agent                    Agent Gateway              Platform Service
   │                             │                          │
   ├─1. Authenticate ────────────►                          │
   │    (user OIDC + agent creds)│                          │
   │                             │                          │
   │◄─2. Delegation Token ───────┤                          │
   │    (user_id, agent_id,      │                          │
   │     scopes, classification  │                          │
   │     caps, ttl)              │                          │
   │                             │                          │
   ├─3. Tool Call ───────────────►                          │
   │    (action, resource,       │                          │
   │     context, delegation     │                          │
   │     token)                  │                          │
   │                             ├─4. GetDecision ──────────►
   │                             │    (subject_attrs +       │
   │                             │     agent_attrs +         │
   │                             │     delegation_attrs)     │
   │                             │                          │
   │                             │◄─5. Compound Decision ───┤
   │                             │    (ALLOW/DENY +          │
   │                             │     user_decision +       │
   │                             │     agent_decision +      │
   │                             │     delegation_decision)  │
   │                             │                          │
   │                             ├─6. If ALLOW: Forward ────►
   │                             │    to target service      │
   │                             │                          │
   │◄─7. Response ───────────────┤                          │
   │                             │                          │
   │                             ├─8. Audit Log ────────────►
   │                             │                          │
```

### 3.3 Double-Hop Policy Evaluation

The existing `GetDecision` RPC is extended to accept agent attributes alongside subject attributes. The policy engine evaluates a **single compound decision**:

```
Effective Permission = user_allowed AND agent_allowed AND delegation_allowed
```

All three must be `ALLOW` for the action to proceed. If any is `DENY`, the entire decision is `DENY`. The response includes which component denied and why.

### 3.4 Delegation Token Model

Stratium mints short-lived delegation tokens (extending existing OIDC/JWT infrastructure). Tokens are scoped and bound to a specific user-agent-session triple.

**Token claims:**

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | User ID (from OIDC) |
| `agent_id` | string | Registered agent ID |
| `agent_trust_tier` | int | Agent trust tier (0-3) |
| `tenant_id` | string | Tenant binding |
| `delegation_id` | string (UUID) | Unique delegation identifier |
| `approved_tools` | []string | Tools this agent may invoke |
| `approved_actions` | []string | Action types allowed |
| `max_action_tier` | int | Maximum action sensitivity tier (0-4) |
| `classification_caps` | map[string]string | Per-hierarchy classification caps (e.g., `{"nato": "CONFIDENTIAL", "commercial": "INTERNAL"}`) |
| `resource_constraints` | map[string]string | Resource type/tag restrictions |
| `purpose` | string | Declared purpose of delegation |
| `conversation_id` | string | Originating conversation/session |
| `parent_delegation_id` | string (UUID) | Parent delegation in chain (null for root) |
| `root_delegation_id` | string (UUID) | Root delegation ID (always present) |
| `depth` | int | Chain depth (0 = root, 1 = first subagent, ...) |
| `chain_agent_ids` | []string | Ordered agent IDs from root to this node |
| `iat` | int64 | Issued at |
| `exp` | int64 | Expiration (short TTL, default 15min) |

**Per-resource classification caps** allow a user with SECRET clearance to delegate only CONFIDENTIAL-level access to an agent, and to set different caps per hierarchy domain (NATO vs. Commercial).

**Chain depth** is bounded by `DELEGATION_MAX_DEPTH` (default 5). Child delegations must be a strict subset of their parent's scope — classification caps can only narrow, action tiers can only decrease, and tools can only be removed.

---

## 4. Data Models

### 4.1 Agent (New)

```go
type Agent struct {
    ID              uuid.UUID
    Name            string
    Description     string
    Provider        string                 // e.g., "openai", "anthropic", "custom"
    ModelIdentifier string                 // e.g., "gpt-4", "claude-sonnet-4-20250514"
    TrustTier       AgentTrustTier         // 0-3
    AllowedTools    []string               // Tools this agent can invoke
    AllowedActions  []ActionTier           // Action sensitivity tiers permitted
    TenantID        string                 // Tenant binding
    CertStatus      AgentCertStatus        // PENDING, CERTIFIED, SUSPENDED, REVOKED
    Credentials     AgentCredentials       // Auth credentials (client_id/secret or mTLS)
    Metadata        map[string]interface{} // Extensible metadata
    Enabled         bool
    CreatedAt       time.Time
    UpdatedAt       time.Time
    CreatedBy       string                 // Admin who registered
}
```

### 4.2 Agent Trust Tiers

```go
type AgentTrustTier int

const (
    TrustTierUnverified     AgentTrustTier = 0  // Read-only, sandboxed
    TrustTierRegistered     AgentTrustTier = 1  // Read + limited write, approval for sensitive
    TrustTierCertified      AgentTrustTier = 2  // Full read/write within delegation scope
    TrustTierPlatformTrusted AgentTrustTier = 3 // System-level actions (compliance, security)
)
```

| Tier | Name | Capabilities | Max Action Tier |
|------|------|-------------|-----------------|
| 0 | Unverified | Read-only, sandboxed, no external actions | Tier 1 (read-only) |
| 1 | Registered | Read + limited write, no external comms | Tier 2 (internal modifications) |
| 2 | Certified | Full read/write within delegation scope | Tier 3 (external comms) |
| 3 | Platform-trusted | System-level actions under system authority | Tier 4 (destructive/financial) |

### 4.3 Action Sensitivity Tiers

```go
type ActionTier int

const (
    ActionTierReasoning       ActionTier = 0  // Reasoning only, no side effects
    ActionTierReadOnly        ActionTier = 1  // Read-only data retrieval
    ActionTierInternalModify  ActionTier = 2  // Internal data modifications
    ActionTierExternalComms   ActionTier = 3  // External communications (email, webhook, API)
    ActionTierDestructive     ActionTier = 4  // Destructive or financially binding actions
)
```

### 4.4 Delegation (New)

```go
type Delegation struct {
    ID                  uuid.UUID
    UserID              string
    AgentID             uuid.UUID
    TenantID            string
    ConversationID      string
    ApprovedTools       []string
    ApprovedActions     []ActionTier
    MaxActionTier       ActionTier
    ClassificationCaps  map[string]string  // per-hierarchy caps
    ResourceConstraints map[string]string
    Purpose             string
    ExpiresAt           time.Time
    CreatedAt           time.Time
    Revoked             bool
    RevokedAt           *time.Time

    // Delegation chain fields
    ParentDelegationID  *uuid.UUID         // nil for root delegation (user → agent)
    RootDelegationID    uuid.UUID          // always points to the root of the chain
    Depth               int                // 0 = root, 1 = first subagent, etc.
    ChainAgentIDs       []uuid.UUID        // ordered list of all agent IDs from root to this node
}
```

### 4.5 Execution Mode

```go
type ExecutionMode int

const (
    ExecutionModeDelegated ExecutionMode = 0  // Agent acts FOR user. Effective rights = intersection.
    ExecutionModeSystem    ExecutionMode = 1  // Agent acts AS system function. Separate policy.
)
```

**Delegated mode**: Agent is acting for the user. Effective rights = intersection of user + agent + delegation.

**System mode**: Agent is acting as a governed platform function (e.g., compliance scan, security quarantine). Requires separate service policy, narrow predefined workflow, and strong audit. No user impersonation semantics.

### 4.6 Recursive Delegation Chains (Subagents)

AI agent architectures frequently involve **subagent orchestration** — an orchestrator agent delegates tasks to specialist agents, which may in turn delegate to sub-specialist agents. This creates an N-level deep delegation chain where every principal (the user and every agent in the chain) must be authorized for the final action.

#### 4.6.1 The Problem

```
User (SECRET clearance)
  └─► Agent A (orchestrator, Tier 2)
        └─► Agent B (data analyst, Tier 1)
              └─► Agent C (report generator, Tier 1)
                    └─► Action: read financial report (CONFIDENTIAL)
```

The platform must evaluate:
1. Can the **user** access the financial report? (clearance check)
2. Can **Agent A** perform this class of action? (trust tier + tools)
3. Can **Agent B** perform this class of action? (trust tier + tools)
4. Can **Agent C** perform this class of action? (trust tier + tools)
5. Does the **delegation chain** permit this action at each hop? (scope narrowing)

**All must be ALLOW.** If any principal in the chain is DENY, the entire decision is DENY.

#### 4.6.2 Linked Chain Token Model

Each agent in the chain holds its own delegation token that references its parent via `parent_delegation_id`. The chain forms a linked list:

```
Token #1 (root)              Token #2                     Token #3
┌──────────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐
│ delegation_id: D1    │     │ delegation_id: D2    │     │ delegation_id: D3    │
│ sub: user@corp.com   │     │ sub: user@corp.com   │     │ sub: user@corp.com   │
│ agent_id: agent-A    │     │ agent_id: agent-B    │     │ agent_id: agent-C    │
│ parent_delegation: ∅ │◄────│ parent_delegation: D1│◄────│ parent_delegation: D2│
│ root_delegation: D1  │     │ root_delegation: D1  │     │ root_delegation: D1  │
│ depth: 0             │     │ depth: 1             │     │ depth: 2             │
│ chain_agents: [A]    │     │ chain_agents: [A,B]  │     │ chain_agents: [A,B,C]│
│ max_action_tier: 3   │     │ max_action_tier: 2   │──┐  │ max_action_tier: 1   │
│ caps:                │     │ caps:                │  │  │ caps:                │
│  nato: SECRET        │     │  nato: CONFIDENTIAL  │  │  │  nato: CONFIDENTIAL  │
│  comm: RESTRICTED    │     │  comm: INTERNAL      │  │  │  comm: INTERNAL      │
│ tools: [read, write, │     │ tools: [read, write] │  │  │ tools: [read]        │
│         analyze,     │     │                      │  │  │                      │
│         send]        │     │                      │  │  │                      │
└──────────────────────┘     └──────────────────────┘  │  └──────────────────────┘
                                                       │
                              Scope only narrows ──────┘
```

**Invariants:**
- `child.max_action_tier <= parent.max_action_tier`
- For each hierarchy `h`: `child.classification_caps[h] <= parent.classification_caps[h]`
- `child.approved_tools ⊆ parent.approved_tools`
- `child.approved_actions ⊆ parent.approved_actions`
- `child.depth == parent.depth + 1`
- `child.depth <= DELEGATION_MAX_DEPTH` (default 5)
- `child.expires_at <= parent.expires_at`

#### 4.6.3 Chain Creation Flow

When Agent B (holding Token #2) wants to delegate to subagent Agent C, it calls `CreateDelegation` with its own token as the parent. The Agent Gateway performs a **full compound policy evaluation** for the child:

```
Agent B                     Agent Gateway              Platform Service
   │                             │                          │
   ├─1. CreateDelegation ────────►                          │
   │    parent_token: Token#2    │                          │
   │    child_agent_id: agent-C  │                          │
   │    requested_scope: {...}   │                          │
   │                             │                          │
   │                    2. Validate structural constraints:  │
   │                       - depth < max_depth              │
   │                       - requested scope ⊆ parent scope │
   │                       - child agent exists and enabled  │
   │                       - parent token valid & unexpired  │
   │                             │                          │
   │                             ├─3. GetDecision ──────────►
   │                             │    Evaluate compound:     │
   │                             │    - user entitlements    │
   │                             │    - Agent C trust tier   │
   │                             │    - Agent C allowed tools│
   │                             │    - delegation scope     │
   │                             │                          │
   │                             │◄─4. Decision ────────────┤
   │                             │                          │
   │                    5. If ALLOW:                         │
   │                       - Mint child Token#3              │
   │                       - Store delegation record         │
   │                       - Log to audit                    │
   │                             │                          │
   │◄─6. Child Token #3 ────────┤                          │
   │    (or DENY + reason)       │                          │
```

#### 4.6.4 Chain Evaluation at Action Time

When the leaf agent (Agent C, holding Token #3) executes an action, the Agent Gateway walks the **full chain** and evaluates every principal:

```
Effective Permission = user_allowed
                       AND agent_A_allowed
                       AND delegation_A→B_allowed
                       AND agent_B_allowed
                       AND delegation_B→C_allowed
                       AND agent_C_allowed
                       AND delegation_C_scope_allowed
```

The evaluation is a **single call** to `GetDecision` with the full chain context. The policy engine receives:
- `subject_attributes` — the originating user
- `agent_chain` — ordered list of all agents with their attributes
- `delegation_chain` — ordered list of all delegation scopes
- `action` and `resource` — the requested operation

The policy engine iterates the chain and short-circuits on the first DENY.

```
Agent C                     Agent Gateway              Platform Service
   │                             │                          │
   ├─1. ExecuteAction ──────────►                          │
   │    token: Token#3           │                          │
   │    action: read             │                          │
   │    resource: fin-report     │                          │
   │                             │                          │
   │                    2. Resolve full chain:               │
   │                       Token#3 → Token#2 → Token#1      │
   │                       Load agent records: C, B, A       │
   │                             │                          │
   │                             ├─3. GetDecision ──────────►
   │                             │    subject: user@corp.com │
   │                             │    agent_chain: [A, B, C] │
   │                             │    delegation_chain:       │
   │                             │      [D1, D2, D3]         │
   │                             │    action: read           │
   │                             │    resource: fin-report   │
   │                             │                          │
   │                             │    Policy evaluates:      │
   │                             │    ✓ user: SECRET ≥ CONF  │
   │                             │    ✓ agent-A: tier2, read │
   │                             │    ✓ D1→D2: scope valid   │
   │                             │    ✓ agent-B: tier1, read │
   │                             │    ✓ D2→D3: scope valid   │
   │                             │    ✓ agent-C: tier1, read │
   │                             │    ✓ D3 scope: CONF ok    │
   │                             │    = ALLOW                │
   │                             │                          │
   │                             │◄─4. Compound Decision ───┤
   │                             │    decision: ALLOW        │
   │                             │    chain_decisions: [      │
   │                             │      {agent-A: ALLOW},    │
   │                             │      {agent-B: ALLOW},    │
   │                             │      {agent-C: ALLOW}     │
   │                             │    ]                      │
   │                             │                          │
   │                             ├─5. Forward to service ───►
   │◄─6. Response ──────────────┤                          │
```

#### 4.6.5 Chain Denial Scenarios

| Scenario | Chain | Result |
|----------|-------|--------|
| User lacks clearance | User DENY → (chain skipped) | **DENY** at depth 0 (user_reason) |
| Mid-chain agent untrusted | User OK → Agent A OK → Agent B DENY → (rest skipped) | **DENY** at depth 1 (agent_B_reason) |
| Scope exceeded at leaf | User OK → All agents OK → D3 cap CONFIDENTIAL < resource SECRET | **DENY** at delegation depth 2 |
| Depth limit exceeded | Agent tries to create depth 6 delegation | **DENY** at CreateDelegation (max_depth_exceeded) |
| Expired parent in chain | Token#2 expired while Token#3 still valid | **DENY** (parent_delegation_expired) |
| Revoked mid-chain | D2 revoked → D3 invalidated (cascade) | **DENY** (parent_delegation_revoked) |
| Privilege amplification | User DENY but Agent C ALLOW for action | **DENY** (blocks proxy abuse regardless of chain depth) |

#### 4.6.6 Chain Revocation

Revoking a delegation cascades to all children:

```go
// Revoking D2 automatically revokes D3 and any deeper descendants
func (s *Server) RevokeDelegation(ctx context.Context, req *RevokeDelegationRequest) {
    // 1. Revoke the target delegation
    // 2. Find all delegations where root_delegation_id matches
    //    AND depth > target.depth
    //    AND chain_agent_ids contains target.agent_id at the correct position
    // 3. Revoke all descendants
    // 4. Audit log the cascade
}
```

**Cascade rule:** Revoking any delegation in the chain invalidates all delegations below it. The `root_delegation_id` index enables efficient cascade queries.

#### 4.6.7 In-Flight Expiration: Point-in-Time Authorization

Authorization is a **point-in-time decision**. Once `GetDecision` returns `ALLOW`, the action proceeds to completion regardless of subsequent token expiration. This is consistent with standard OAuth2/JWT semantics — an HTTP request authorized at T=0 does not fail if the bearer token expires at T=1 while the server is still processing.

**Rules:**

1. The Agent Gateway resolves the full chain and calls `GetDecision` **once** per `ExecuteAction`.
2. If all tokens are valid at decision time → `ALLOW` → action is forwarded and completes.
3. If any token in the chain is expired at decision time → `DENY` → action is rejected.
4. Token expiration *after* the decision has no effect on the in-flight action.
5. The **next** `ExecuteAction` call will re-resolve the chain and discover the expiration.

**Timeline:**

```
T=898    ExecuteAction called with Token#3
T=898    Gateway resolves chain: Token#3 → Token#2 → Token#1
T=898    All tokens valid → GetDecision → ALLOW        ← authorization checkpoint
T=898    Gateway forwards request to KAS
T=900    Token#2 expires (does not affect in-flight action)
T=902    KAS returns response → Gateway returns to Agent C  ✓

T=903    Agent C calls ExecuteAction again
T=903    Gateway resolves chain → Token#2 EXPIRED → DENY  ✗
         Agent must create a new delegation
```

**Why this is safe:**

- The action was authorized by a valid policy decision at a specific point in time.
- The audit log records the decision timestamp, all token states, and the policy version used.
- Subsequent actions require a fresh chain resolution — expired tokens are immediately caught.
- The alternative (continuous authorization) would require holding open connections to the policy engine during action execution, adding latency and complexity with minimal security benefit for short-lived actions.

**Edge case — long-running actions:** For actions that take minutes (e.g., streaming large ZTDF decryptions), the point-in-time model still applies. The authorization was valid when granted. If stricter guarantees are needed for specific action types, this can be addressed in Phase 2 with periodic re-authorization for streaming RPCs.

#### 4.6.8 Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `DELEGATION_MAX_DEPTH` | 5 | Maximum chain depth (0 = user→agent only, no subagents) |
| `DELEGATION_CHAIN_CACHE_TTL` | 30s | TTL for resolved chain cache (avoids re-walking on every action) |
| `DELEGATION_CASCADE_REVOKE` | true | Whether revocation cascades to children |

---

## 5. Protobuf Contract

### 5.1 Agent Gateway Service

```protobuf
syntax = "proto3";
package stratium.services.agent_gateway;

service AgentGatewayService {
    // Authenticate user+agent pair and mint a delegation token.
    // For root delegations: user OIDC + agent credentials.
    // For child delegations: parent delegation token + child agent credentials.
    // Child creation triggers full compound policy evaluation.
    rpc CreateDelegation(CreateDelegationRequest) returns (CreateDelegationResponse);

    // Revoke an active delegation. Cascades to all child delegations in the chain.
    rpc RevokeDelegation(RevokeDelegationRequest) returns (RevokeDelegationResponse);

    // Execute an agent action with full chain authorization.
    // The gateway resolves the complete delegation chain and evaluates
    // every principal (user + all agents) before forwarding.
    rpc ExecuteAction(ExecuteActionRequest) returns (ExecuteActionResponse);

    // Validate that a declared action matches the tool call (anti-spoofing)
    rpc ValidateActionPlan(ValidateActionPlanRequest) returns (ValidateActionPlanResponse);

    // Inspect a delegation chain (for debugging/observability)
    rpc GetDelegationChain(GetDelegationChainRequest) returns (GetDelegationChainResponse);

    // Agent Registry (admin-only)
    rpc RegisterAgent(RegisterAgentRequest) returns (RegisterAgentResponse);
    rpc GetAgent(GetAgentRequest) returns (GetAgentResponse);
    rpc ListAgents(ListAgentsRequest) returns (ListAgentsResponse);
    rpc UpdateAgent(UpdateAgentRequest) returns (UpdateAgentResponse);
    rpc SuspendAgent(SuspendAgentRequest) returns (SuspendAgentResponse);
}

// --- Delegation Chain Messages ---

message CreateDelegationRequest {
    // For root delegation: user OIDC token in Authorization header
    string agent_id = 1;
    repeated string approved_tools = 2;
    repeated ActionTier approved_actions = 3;
    ActionTier max_action_tier = 4;
    map<string, string> classification_caps = 5;
    map<string, string> resource_constraints = 6;
    string purpose = 7;
    int32 ttl_seconds = 8;                    // Requested TTL (capped by max and parent)
    string conversation_id = 9;

    // For child delegation: parent agent's delegation token
    string parent_delegation_token = 10;       // Empty for root delegations
}

message CreateDelegationResponse {
    string delegation_token = 1;               // Signed JWT
    string delegation_id = 2;
    int32 depth = 3;
    google.protobuf.Timestamp expires_at = 4;
    string root_delegation_id = 5;
}

message GetDelegationChainRequest {
    string delegation_id = 1;                  // Any delegation in the chain
}

message GetDelegationChainResponse {
    string root_delegation_id = 1;
    string user_id = 2;
    repeated ChainLink chain = 3;              // Ordered root → leaf
    int32 total_depth = 4;
}

message ChainLink {
    string delegation_id = 1;
    string agent_id = 2;
    string agent_name = 3;
    AgentTrustTier trust_tier = 4;
    int32 depth = 5;
    ActionTier max_action_tier = 6;
    map<string, string> classification_caps = 7;
    repeated string approved_tools = 8;
    google.protobuf.Timestamp expires_at = 9;
    bool revoked = 10;
}
```

### 5.2 Extended GetDecision (Platform Service)

```protobuf
// Extended GetDecisionRequest — backward compatible
message GetDecisionRequest {
    map<string, google.protobuf.Value> subject_attributes = 1;
    map<string, string> resource_attributes = 2;
    string action = 3;
    map<string, string> context = 4;
    string policy_id = 5;

    // New fields for agent authorization (ignored when agent_auth disabled)
    // For single-agent requests, populate agent_attributes + delegation_context.
    // For chain requests, populate agent_chain + delegation_chain instead.
    AgentAttributes agent_attributes = 6;
    DelegationContext delegation_context = 7;

    // Delegation chain fields (for N-level subagent authorization)
    repeated AgentAttributes agent_chain = 8;        // Ordered root → leaf
    repeated DelegationContext delegation_chain = 9;  // Ordered root → leaf
}

message AgentAttributes {
    string agent_id = 1;
    string agent_name = 2;
    AgentTrustTier trust_tier = 3;
    string provider = 4;
    string model_identifier = 5;
    repeated string allowed_tools = 6;
    repeated ActionTier allowed_actions = 7;
    string tenant_id = 8;
}

message DelegationContext {
    string delegation_id = 1;
    string user_id = 2;
    string agent_id = 3;
    string conversation_id = 4;
    ExecutionMode execution_mode = 5;
    ActionTier action_tier = 6;
    string tool_name = 7;
    string purpose = 8;
    map<string, string> classification_caps = 9;
    map<string, string> resource_constraints = 10;

    // Chain fields
    string parent_delegation_id = 11;
    string root_delegation_id = 12;
    int32 depth = 13;
    repeated string chain_agent_ids = 14;
}

// Extended GetDecisionResponse
message GetDecisionResponse {
    Decision decision = 1;
    string reason = 2;
    map<string, string> details = 3;
    google.protobuf.Timestamp timestamp = 4;
    string evaluated_policy = 5;

    // New fields for compound decision breakdown
    CompoundDecision compound_decision = 6;
}

message CompoundDecision {
    Decision user_decision = 1;
    string user_reason = 2;

    // Single-agent fields (backward compatible)
    Decision agent_decision = 3;
    string agent_reason = 4;
    Decision delegation_decision = 5;
    string delegation_reason = 6;

    // Chain fields — per-agent decision breakdown (ordered root → leaf)
    repeated ChainHopDecision chain_decisions = 7;
    int32 denied_at_depth = 8;               // Depth where first DENY occurred (-1 if all ALLOW)
    string denied_principal = 9;             // "user", "agent:<id>", or "delegation:<id>"
}

// Decision for a single hop in the delegation chain
message ChainHopDecision {
    int32 depth = 1;
    string agent_id = 2;
    string delegation_id = 3;
    Decision agent_decision = 4;             // Can this agent perform this action?
    string agent_reason = 5;
    Decision delegation_decision = 6;        // Does the delegation scope permit it?
    string delegation_reason = 7;
}

enum AgentTrustTier {
    AGENT_TRUST_TIER_UNVERIFIED = 0;
    AGENT_TRUST_TIER_REGISTERED = 1;
    AGENT_TRUST_TIER_CERTIFIED = 2;
    AGENT_TRUST_TIER_PLATFORM_TRUSTED = 3;
}

enum ActionTier {
    ACTION_TIER_REASONING = 0;
    ACTION_TIER_READ_ONLY = 1;
    ACTION_TIER_INTERNAL_MODIFY = 2;
    ACTION_TIER_EXTERNAL_COMMS = 3;
    ACTION_TIER_DESTRUCTIVE = 4;
}

enum ExecutionMode {
    EXECUTION_MODE_DELEGATED = 0;
    EXECUTION_MODE_SYSTEM = 1;
}
```

### 5.3 Action Validation (Anti-Spoofing)

```protobuf
message ValidateActionPlanRequest {
    string delegation_id = 1;
    repeated PlannedAction actions = 2;
}

message PlannedAction {
    string tool_name = 1;
    string action = 2;                    // read, write, delete, send, etc.
    ActionTier declared_tier = 3;
    map<string, string> resource = 4;     // Resource attributes
    map<string, string> parameters = 5;   // Tool parameters
}

message ValidateActionPlanResponse {
    bool valid = 1;
    repeated ActionValidationResult results = 2;
}

message ActionValidationResult {
    int32 action_index = 1;
    bool valid = 2;
    string reason = 3;
    ActionTier actual_tier = 4;          // Stratium's assessment of the action tier
    bool tier_mismatch = 5;             // Agent declared wrong tier
}
```

---

## 6. Policy Model

### 6.1 Compound ABAC Evaluation

The policy engine evaluates five attribute domains in a single pass:

| Domain | Source | Example Attributes |
|--------|--------|--------------------|
| **User** | OIDC token | identity, role, clearance, department, tenant |
| **Agent** | Agent Registry | agent_id, trust_tier, provider, allowed_tools, allowed_actions |
| **Action** | Tool call | action type, sensitivity tier, reversibility, external egress |
| **Resource** | Resource metadata | classification, owner, tenant, sensitivity, legal flags |
| **Delegation** | Delegation token | execution_mode, classification_caps, purpose, ttl, resource_constraints |

### 6.2 Policy Rule Examples (OPA/Rego)

```rego
package stratium.agent_auth

import future.keywords.if
import future.keywords.in

# Rule: Effective permission is the intersection
default allow := false

allow if {
    user_allowed
    agent_allowed
    delegation_allowed
}

# User must be authorized for the requested outcome
user_allowed if {
    input.subject_attributes.clearance_level >= input.resource_attributes.classification_level
    input.action in user_permitted_actions
}

# Agent must be authorized for this class of action
agent_allowed if {
    input.agent_attributes.trust_tier >= required_trust_tier(input.delegation_context.action_tier)
    input.delegation_context.tool_name in input.agent_attributes.allowed_tools
    input.delegation_context.action_tier in input.agent_attributes.allowed_actions
}

# Delegation scope must permit this specific action
delegation_allowed if {
    input.delegation_context.execution_mode == "DELEGATED"
    classification_within_caps
    resource_within_constraints
    not delegation_expired
}

# Classification caps — per-hierarchy enforcement
classification_within_caps if {
    hierarchy := input.resource_attributes.hierarchy
    resource_level := input.resource_attributes.classification_level
    cap_level := input.delegation_context.classification_caps[hierarchy]
    resource_level <= cap_level
}

# Required trust tier for action sensitivity
required_trust_tier(action_tier) := 0 if { action_tier <= 1 }
required_trust_tier(action_tier) := 1 if { action_tier == 2 }
required_trust_tier(action_tier) := 2 if { action_tier == 3 }
required_trust_tier(action_tier) := 3 if { action_tier == 4 }
```

### 6.3 Chain Policy Evaluation (OPA/Rego)

For N-level delegation chains, the policy engine iterates every agent and delegation hop:

```rego
package stratium.agent_auth_chain

import future.keywords.if
import future.keywords.in
import future.keywords.every

default allow := false

# Chain evaluation: user AND every agent AND every delegation scope must ALLOW
allow if {
    user_allowed
    every_agent_allowed
    every_delegation_allowed
    chain_depth_ok
}

# User check (same as single-agent)
user_allowed if {
    input.subject_attributes.clearance_level >= input.resource_attributes.classification_level
    input.action in user_permitted_actions
}

# Every agent in the chain must be authorized
every_agent_allowed if {
    every i, agent in input.agent_chain {
        agent.trust_tier >= required_trust_tier(input.delegation_chain[i].action_tier)
        input.delegation_chain[i].tool_name in agent.allowed_tools
        input.delegation_chain[i].action_tier in agent.allowed_actions
    }
}

# Every delegation scope in the chain must permit the action
every_delegation_allowed if {
    every i, delegation in input.delegation_chain {
        delegation.execution_mode == "DELEGATED"
        classification_within_caps_at(delegation)
        resource_within_constraints_at(delegation)
        not delegation_expired_at(delegation)
    }
}

# Classification caps at a specific chain hop
classification_within_caps_at(delegation) if {
    hierarchy := input.resource_attributes.hierarchy
    resource_level := input.resource_attributes.classification_level
    cap_level := delegation.classification_caps[hierarchy]
    resource_level <= cap_level
}

# Scope monotonically narrows — each child ⊆ parent
scope_narrows if {
    every i in numbers.range(1, count(input.delegation_chain) - 1) {
        child := input.delegation_chain[i]
        parent := input.delegation_chain[i - 1]
        child.max_action_tier <= parent.max_action_tier
        # Per-hierarchy: child cap ≤ parent cap
        every h, cap in child.classification_caps {
            cap <= parent.classification_caps[h]
        }
    }
}

# Chain depth within configured maximum
chain_depth_ok if {
    count(input.agent_chain) <= input.max_delegation_depth
}
```

### 6.4 Denial Scenarios

**Single-agent scenarios:**

| Scenario | User | Agent | Delegation | Result |
|----------|------|-------|------------|--------|
| Normal access | ALLOW | ALLOW | ALLOW | **ALLOW** |
| User lacks clearance | DENY | ALLOW | ALLOW | **DENY** (user_reason: "insufficient clearance") |
| Agent not trusted for action | ALLOW | DENY | ALLOW | **DENY** (agent_reason: "trust tier 1 cannot perform tier 3 actions") |
| Classification cap exceeded | ALLOW | ALLOW | DENY | **DENY** (delegation_reason: "resource SECRET exceeds cap CONFIDENTIAL for nato hierarchy") |
| Agent privilege amplification | DENY | ALLOW | ALLOW | **DENY** (user_reason: blocks proxy abuse) |

**Chain-specific scenarios:**

| Scenario | Chain | Result |
|----------|-------|--------|
| All agents authorized | User OK → A OK → B OK → C OK | **ALLOW** |
| Mid-chain agent untrusted | User OK → A OK → B **DENY** → (C skipped) | **DENY** at depth 1 (agent_B: "tier 0 cannot perform tier 2") |
| Scope exceeded at leaf | User OK → A OK → B OK → D3 cap < resource | **DENY** at delegation depth 2 |
| Depth limit exceeded | Chain depth 6 > max 5 | **DENY** at CreateDelegation ("max depth exceeded") |
| Expired parent in chain | Token#2 expired, Token#3 still valid | **DENY** ("parent delegation expired at depth 1") |
| Revoked mid-chain | D2 revoked → D3 cascade-revoked | **DENY** ("delegation revoked at depth 1, cascade invalidated depth 2") |
| Scope widening attempt | Child requests NATO:SECRET but parent cap is NATO:CONFIDENTIAL | **DENY** at CreateDelegation ("child scope exceeds parent") |
| Tool not in parent scope | Child requests tool "send_email" but parent only has ["read", "write"] | **DENY** at CreateDelegation ("tool not in parent approved_tools") |

---

## 7. Agent Registry

### 7.1 Registration Flow

Admin-only registration via PAP API:

```
Admin                          PAP Server                    PostgreSQL
  │                               │                              │
  ├─POST /agents ─────────────────►                              │
  │  { name, provider, model,     │                              │
  │    trust_tier, allowed_tools,  ├─INSERT agents ──────────────►
  │    allowed_actions, tenant }   │                              │
  │                               │◄─agent_id ──────────────────┤
  │◄─{ agent_id, credentials } ───┤                              │
  │                                                              │
```

### 7.2 PAP REST Endpoints (Agent Registry)

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| POST | `/agents` | CreateAgent | Register new agent (admin) |
| GET | `/agents/{id}` | GetAgent | Retrieve agent details |
| GET | `/agents` | ListAgents | List all agents (filterable) |
| PUT | `/agents/{id}` | UpdateAgent | Update agent config |
| POST | `/agents/{id}/suspend` | SuspendAgent | Suspend agent |
| POST | `/agents/{id}/reinstate` | ReinstateAgent | Reinstate suspended agent |
| DELETE | `/agents/{id}` | DeleteAgent | Remove agent |

### 7.3 Database Schema

```sql
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    provider        VARCHAR(100) NOT NULL,
    model_id        VARCHAR(255),
    trust_tier      SMALLINT NOT NULL DEFAULT 0,
    allowed_tools   JSONB NOT NULL DEFAULT '[]',
    allowed_actions JSONB NOT NULL DEFAULT '[0, 1]',
    tenant_id       VARCHAR(255) NOT NULL,
    cert_status     VARCHAR(50) NOT NULL DEFAULT 'PENDING',
    client_id       VARCHAR(255) UNIQUE NOT NULL,
    client_secret   BYTEA NOT NULL,          -- encrypted
    metadata        JSONB DEFAULT '{}',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      VARCHAR(255) NOT NULL
);

CREATE INDEX idx_agents_tenant ON agents(tenant_id);
CREATE INDEX idx_agents_trust_tier ON agents(trust_tier);
CREATE INDEX idx_agents_client_id ON agents(client_id);

CREATE TABLE delegations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              VARCHAR(255) NOT NULL,
    agent_id             UUID NOT NULL REFERENCES agents(id),
    tenant_id            VARCHAR(255) NOT NULL,
    conversation_id      VARCHAR(255),
    approved_tools       JSONB NOT NULL DEFAULT '[]',
    approved_actions     JSONB NOT NULL DEFAULT '[]',
    max_action_tier      SMALLINT NOT NULL DEFAULT 1,
    classification_caps  JSONB NOT NULL DEFAULT '{}',
    resource_constraints JSONB NOT NULL DEFAULT '{}',
    purpose              TEXT,
    expires_at           TIMESTAMPTZ NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked              BOOLEAN NOT NULL DEFAULT false,
    revoked_at           TIMESTAMPTZ,

    -- Delegation chain fields
    parent_delegation_id UUID REFERENCES delegations(id),  -- NULL for root
    root_delegation_id   UUID NOT NULL,                    -- Always points to root (self-ref for root)
    depth                SMALLINT NOT NULL DEFAULT 0,      -- 0 = root
    chain_agent_ids      JSONB NOT NULL DEFAULT '[]'       -- Ordered agent IDs from root to this node
);

CREATE INDEX idx_delegations_user_agent ON delegations(user_id, agent_id);
CREATE INDEX idx_delegations_expires ON delegations(expires_at) WHERE revoked = false;
CREATE INDEX idx_delegations_parent ON delegations(parent_delegation_id) WHERE parent_delegation_id IS NOT NULL;
CREATE INDEX idx_delegations_root ON delegations(root_delegation_id);
CREATE INDEX idx_delegations_depth ON delegations(depth);
```

### 7.4 Audit Log Extension

Extend the existing `audit_logs` table with agent-specific columns:

```sql
ALTER TABLE audit_logs ADD COLUMN agent_id UUID;
ALTER TABLE audit_logs ADD COLUMN delegation_id UUID;
ALTER TABLE audit_logs ADD COLUMN agent_trust_tier SMALLINT;
ALTER TABLE audit_logs ADD COLUMN tool_name VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN action_tier SMALLINT;
ALTER TABLE audit_logs ADD COLUMN execution_mode VARCHAR(20);
ALTER TABLE audit_logs ADD COLUMN conversation_id VARCHAR(255);
ALTER TABLE audit_logs ADD COLUMN user_decision VARCHAR(20);
ALTER TABLE audit_logs ADD COLUMN agent_decision VARCHAR(20);
ALTER TABLE audit_logs ADD COLUMN delegation_decision VARCHAR(20);
ALTER TABLE audit_logs ADD COLUMN chain_depth SMALLINT;
ALTER TABLE audit_logs ADD COLUMN chain_agent_ids JSONB;
ALTER TABLE audit_logs ADD COLUMN root_delegation_id UUID;
ALTER TABLE audit_logs ADD COLUMN denied_at_depth SMALLINT;
ALTER TABLE audit_logs ADD COLUMN denied_principal VARCHAR(255);

CREATE INDEX idx_audit_logs_agent ON audit_logs(agent_id) WHERE agent_id IS NOT NULL;
CREATE INDEX idx_audit_logs_delegation ON audit_logs(delegation_id) WHERE delegation_id IS NOT NULL;
CREATE INDEX idx_audit_logs_root_delegation ON audit_logs(root_delegation_id) WHERE root_delegation_id IS NOT NULL;
```

---

## 8. Feature Flag Integration

### 8.1 Build-Time Flag

Consistent with the existing feature flag system in `go/features/features.go`:

```go
// New feature flag
func ShouldEnableAgentAuth() bool {
    return isFeatureEnabled("agent-auth")
}
```

**Build:**

```bash
docker build \
  --build-arg BUILD_FEATURES="agent-auth" \
  -t stratium/agent-gateway:latest .
```

**Environment variable override (runtime):**

```bash
AGENT_AUTH_ENABLED=true
```

### 8.2 Backward Compatibility

When `agent-auth` is disabled:

- `GetDecision` ignores `agent_attributes` and `delegation_context` fields (they are empty/zero-valued).
- The Agent Gateway Service does not start.
- Agent registry endpoints return `501 Not Implemented`.
- SDK delegation methods return clear errors indicating the feature is disabled.
- No schema migrations are applied for agent tables.
- Zero performance impact on existing authorization flows.

---

## 9. SDK Integration

All 4 SDKs gain agent authentication and delegation token support.

### 9.1 Go SDK

```go
// New: Agent-aware client configuration
type AgentConfig struct {
    AgentID         string
    AgentSecret     string
    GatewayAddr     string             // Agent Gateway address (:50054)
    DefaultPurpose  string
    DefaultMaxTier  ActionTier
    ClassificationCaps map[string]string
}

// Extended client with agent support
func NewAgentClient(userConfig *ZtdfClientConfig, agentConfig *AgentConfig) (*AgentClient, error)

// Create a delegation for this user+agent pair
func (c *AgentClient) CreateDelegation(ctx context.Context, opts *DelegationOptions) (*Delegation, error)

// Execute an action through the Agent Gateway with double-hop auth
func (c *AgentClient) ExecuteAction(ctx context.Context, action *AgentAction) (*ActionResult, error)

// Validate a planned set of actions before execution
func (c *AgentClient) ValidateActionPlan(ctx context.Context, actions []*PlannedAction) (*ValidationResult, error)

// Wrap with agent authorization
func (c *AgentClient) Wrap(ctx context.Context, plaintext []byte, options *WrapOptions) (*WrapResult, error)

// Unwrap with agent authorization
func (c *AgentClient) Unwrap(ctx context.Context, ztdfBlob []byte, userAttributes map[string]string) ([]byte, error)
```

### 9.2 Python SDK

```python
class AgentConfig:
    agent_id: str
    agent_secret: str
    gateway_address: str
    default_purpose: str = ""
    default_max_tier: ActionTier = ActionTier.READ_ONLY
    classification_caps: dict[str, str] = {}

class StratiumAgentClient:
    def __init__(self, user_config: StratiumConfig, agent_config: AgentConfig) -> None: ...

    def create_delegation(
        self,
        purpose: str = "",
        max_action_tier: ActionTier = ActionTier.READ_ONLY,
        classification_caps: dict[str, str] | None = None,
        ttl_seconds: int = 900,
    ) -> Delegation: ...

    def execute_action(
        self,
        action: AgentAction,
    ) -> ActionResult: ...

    def validate_action_plan(
        self,
        actions: list[PlannedAction],
    ) -> ValidationResult: ...

    def wrap(self, plaintext: bytes, options: WrapOptions) -> WrapResult: ...
    def unwrap(self, ztdf_blob: bytes, user_attributes: dict[str, str] | None = None) -> bytes: ...
```

### 9.3 Java SDK

```java
public class StratiumAgentClient {
    public static StratiumAgentClient initialize(
        StratiumClientConfig userConfig,
        AgentConfig agentConfig
    );

    public Delegation createDelegation(DelegationOptions options);
    public ActionResult executeAction(AgentAction action);
    public ValidationResult validateActionPlan(List<PlannedAction> actions);
    public WrapResult wrap(byte[] plaintext, WrapOptions options);
    public byte[] unwrap(byte[] ztdfBlob, Map<String, String> userAttrs);
}
```

### 9.4 JavaScript SDK

```javascript
class ZtdfAgentClient {
    constructor(userConfig: ZtdfClientConfig, agentConfig: AgentConfig);
    async initialize(): Promise<void>;

    async createDelegation(options: DelegationOptions): Promise<Delegation>;
    async executeAction(action: AgentAction): Promise<ActionResult>;
    async validateActionPlan(actions: PlannedAction[]): Promise<ValidationResult>;
    async wrap(plaintext: Uint8Array, options: WrapOptions): Promise<WrapResult>;
    async unwrap(ztdfBlob: Uint8Array, userAttributes?: Record<string, string>): Promise<Uint8Array>;
}
```

---

## 10. Action Validation (Anti-Spoofing)

The hybrid intent normalization model requires the agent framework to decompose prompts into structured actions, and Stratium validates that declared actions match actual tool calls.

### 10.1 Validation Rules

1. **Tier accuracy** — The declared `ActionTier` must match Stratium's assessment of the tool call. If an agent declares a `delete` operation as `ActionTierReadOnly`, validation fails.
2. **Tool allowlist** — The tool name must exist in the agent's `allowed_tools`.
3. **Resource scope** — Resource attributes must fall within the delegation's `resource_constraints`.
4. **Classification check** — Resource classification must not exceed delegation `classification_caps` for its hierarchy.

### 10.2 Flow

```
Agent Framework                 Agent Gateway
    │                               │
    ├─1. ValidateActionPlan ────────►
    │    [                           │
    │      { tool: "read_file",      │  Validates each action:
    │        action: "read",         │  - tier accuracy
    │        tier: READ_ONLY,        │  - tool in allowlist
    │        resource: {...} },      │  - resource in scope
    │      { tool: "send_email",     │  - classification check
    │        action: "send",         │
    │        tier: EXTERNAL_COMMS,   │
    │        resource: {...} }       │
    │    ]                           │
    │                               │
    │◄─2. Validation Result ────────┤
    │    { valid: true,              │
    │      results: [                │
    │        { valid: true },        │
    │        { valid: false,         │
    │          reason: "agent tier 1 │
    │          cannot perform tier 3 │
    │          actions" }            │
    │      ]                         │
    │    }                           │
    │                               │
    ├─3. Execute only valid actions ─►
    │                               │
```

---

## 11. Monitoring & Observability

### 11.1 Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `stratium_agent_auth_decisions_total` | counter | Total compound decisions by result (allow/deny) and component (user/agent/delegation) |
| `stratium_agent_auth_latency_seconds` | histogram | Latency of compound policy evaluation |
| `stratium_agent_delegations_active` | gauge | Currently active (non-expired, non-revoked) delegations |
| `stratium_agent_delegations_created_total` | counter | Total delegations created |
| `stratium_agent_actions_total` | counter | Total agent actions by tool, tier, and result |
| `stratium_agent_validation_failures_total` | counter | Action validation failures by reason (tier_mismatch, tool_not_allowed, etc.) |
| `stratium_agent_denied_by_component` | counter | Denials broken down by which component denied (user, agent, delegation) |
| `stratium_agent_privilege_amplification_attempts` | counter | Cases where agent ALLOW + user DENY detected (proxy abuse attempts) |
| `stratium_agent_chain_depth` | histogram | Delegation chain depth distribution |
| `stratium_agent_chain_denied_at_depth` | counter | Chain denials by depth (identifies problematic hops) |
| `stratium_agent_chain_revocations_total` | counter | Chain revocations (with cascade count) |
| `stratium_agent_scope_widening_attempts` | counter | Attempts to create child delegation exceeding parent scope |

### 11.2 Anomaly Detection Signals

The platform should surface alerts for:

- Agents repeatedly attempting denied actions (brute-force probing).
- Privilege amplification attempts (agent authorized, user not).
- Unusual tool chaining patterns (e.g., read → read → read → bulk_export).
- Cross-tenant access attempts.
- Delegation token reuse after revocation.
- Spike in high-tier actions from a single agent.

---

## 12. Deployment

### 12.1 New Service

The Agent Gateway follows the same deployment model as existing Stratium services:

- **Docker container**: `stratium/agent-gateway`
- **gRPC port**: `:50054`
- **mTLS**: Same cert structure (`/var/run/secrets/stratium/certs/`)
- **PostgreSQL**: Shares the existing Stratium database (new tables)
- **Config**: New environment variables:
  - `AGENT_GATEWAY_GRPC_PORT=50054`
  - `AGENT_AUTH_ENABLED=true`
  - `DELEGATION_TOKEN_TTL=900` (seconds, default 15min)
  - `DELEGATION_TOKEN_MAX_TTL=3600` (max 1 hour)
  - `DELEGATION_TOKEN_SIGNING_KEY` (JWT signing key)
  - `DELEGATION_MAX_DEPTH=5` (max chain depth, 0 disables subagents)
  - `DELEGATION_CHAIN_CACHE_TTL=30` (seconds, resolved chain cache)
  - `DELEGATION_CASCADE_REVOKE=true` (cascade revocation to children)

### 12.2 Docker Compose Addition

```yaml
agent-gateway:
    build:
        context: .
        dockerfile: deployment/docker/Dockerfile
        args:
            SERVICE_NAME: agent-gateway-server
            BUILD_FEATURES: "agent-auth"
    ports:
        - "50054:50054"
    environment:
        - DATABASE_URL=postgres://stratium:stratium@postgres:5432/stratium
        - AGENT_GATEWAY_GRPC_PORT=50054
        - AGENT_AUTH_ENABLED=true
        - PLATFORM_GRPC_ADDR=platform:50051
        - KEY_MANAGER_GRPC_ADDR=key-manager:50052
        - KEY_ACCESS_GRPC_ADDR=key-access:50053
        - KEYCLOAK_URL=http://keycloak:8080
        - DELEGATION_TOKEN_TTL=900
    depends_on:
        - postgres
        - platform
        - keycloak
    volumes:
        - ./certs:/var/run/secrets/stratium/certs:ro
```

---

## 13. Implementation Phases

### Phase 1: Foundation (Target: 4-6 weeks)

- [ ] Agent data model and database schema (agents, delegations tables)
- [ ] Agent Registry — CRUD via PAP REST API (admin-only)
- [ ] Feature flag integration (`agent-auth` in `go/features/`)
- [ ] Agent Gateway Service skeleton (gRPC server, mTLS, config)
- [ ] Delegation token minting and validation (JWT, short-lived)
- [ ] Protobuf definitions for AgentGatewayService

### Phase 2: Policy Engine (Target: 3-4 weeks)

- [ ] Extend `GetDecision` with `agent_attributes` and `delegation_context`
- [ ] Compound policy evaluation (user AND agent AND delegation)
- [ ] `CompoundDecision` response with per-component breakdown
- [ ] OPA/Rego policy templates for agent authorization
- [ ] Classification cap enforcement (per-hierarchy)
- [ ] Action tier validation

### Phase 3: Agent Gateway (Target: 3-4 weeks)

- [ ] `ExecuteAction` RPC — full double-hop authorization flow
- [ ] `ValidateActionPlan` RPC — anti-spoofing validation
- [ ] Proxy forwarding to KAS/Platform/KeyManager after authorization
- [ ] Audit log extension (agent-specific columns)
- [ ] Prometheus metrics and alerting

### Phase 4: SDK Integration (Target: 4-5 weeks)

- [ ] Go SDK — `AgentClient` with delegation + action execution
- [ ] Python SDK — `StratiumAgentClient` (highest priority for AI/ML)
- [ ] Java SDK — `StratiumAgentClient`
- [ ] JavaScript SDK — `ZtdfAgentClient` with agent support
- [ ] Cross-SDK integration tests for agent auth flows
- [ ] SDK documentation and examples

### Phase 5: Hardening (Target: 2-3 weeks)

- [ ] Load testing — compound policy evaluation latency under load
- [ ] Security review — delegation token signing, anti-replay, scope enforcement
- [ ] Anomaly detection signals and alerting rules
- [ ] Docker/K8s deployment manifests
- [ ] Documentation (runbook, API guide, migration guide)

---

## 14. Testing Strategy

### Unit Tests

- Compound policy evaluation (all denial scenarios in Section 6.3)
- Delegation token minting, validation, expiration, revocation
- Classification cap enforcement (per-hierarchy matching)
- Action tier mapping and trust tier requirements
- Anti-spoofing validation rules
- Feature flag on/off behavior

### Integration Tests

- End-to-end: agent registers → creates delegation → executes action → policy evaluates → action proxied → audit logged
- Double-hop denial: user ALLOW + agent DENY = DENY
- Privilege amplification blocked: user DENY + agent ALLOW = DENY
- Classification cap: user SECRET, cap CONFIDENTIAL, resource SECRET = DENY
- Expired delegation rejection
- Revoked delegation rejection
- Cross-SDK: agent action via Python SDK, ZTDF decryption via Go SDK

### Security Tests

- Delegation token tampering detection
- Replay attack prevention (token reuse after revocation)
- Scope escalation attempts (modifying claims in-flight)
- Cross-tenant isolation
- Agent credential rotation

---

## 15. Success Metrics

| Metric | Target |
|--------|--------|
| Compound policy evaluation latency (p99) | < 15ms |
| Delegation token minting latency (p99) | < 10ms |
| Privilege amplification attempts blocked | 100% |
| Feature flag backward compatibility | Zero regressions when disabled |
| SDK adoption | All 4 SDKs ship with agent auth within 1 release |
| Audit coverage | 100% of agent actions logged with full context |

---

## 16. Open Questions

1. **Token rotation** — Should delegation tokens support refresh, or should agents create a new delegation when the current one expires?
2. **Rate limiting per agent** — Should the Agent Gateway enforce per-agent rate limits in addition to per-user rate limits?
3. **System mode governance** — What is the approval process for granting Tier 3 (platform-trusted) status and system execution mode?
4. **Cross-tenant agents** — Can a single agent registration serve multiple tenants, or must agents be registered per-tenant?
5. **Diamond delegation chains** — If Agent A delegates to both Agent B and Agent C, and both delegate to Agent D, should D receive two separate delegations or should the system detect and merge the diamond? (Current design: two separate chains, each evaluated independently.)
6. **Chain caching strategy** — Resolved chains are cached for `DELEGATION_CHAIN_CACHE_TTL` (30s). Should mid-chain revocation invalidate the cache immediately (pub/sub) or rely on TTL expiration?
7. **Cross-chain agent reuse** — If Agent B appears in multiple active chains for the same user, should its trust tier or allowed actions be evaluated per-chain or globally?

---

## 17. References

- [Stratium Architecture Codemap](CODEMAPS/architecture.md)
- [Backend Services Codemap](CODEMAPS/backend.md)
- [Data Models Codemap](CODEMAPS/data.md)
- [Feature Flags Documentation](FEATURE_FLAGS.md)
- [ABAC API Documentation](api-attribute-based-access-control.md)
- [ZTDF Attribute Conventions](ztdf-attribute-conventions.md)
- RFC 8693 — OAuth 2.0 Token Exchange
- NIST SP 800-162 — Guide to ABAC
