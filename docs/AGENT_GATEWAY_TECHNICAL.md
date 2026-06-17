# Stratium Agent Gateway: Technical Architecture

**How Zero-Trust Authorization Works for AI Agents**

---

## Introduction

AI agents are increasingly acting on behalf of users — making API calls, accessing data, and executing workflows through tool invocations. When an agent calls an enterprise service, the platform currently treats the request as coming from a single authenticated identity. There is no mechanism to distinguish between a user acting directly and an AI agent acting on the user's behalf.

This creates a **delegated authorization gap**:

- If only the agent's service identity is authorized, the user can borrow the agent's privileges (privilege amplification).
- If only the user is authorized, the platform ignores that the agent itself may not be trusted for certain actions, tools, or data classifications.

The Stratium Agent Gateway implements a **double-hop authorization model** where every agent action is evaluated against both the user's permissions and the agent's permissions within a cryptographically verifiable delegation context.

---

## Core Principle

> An AI agent may only act within the cryptographically verifiable intersection of user authority, agent authority, delegated scope, and contextual policy.

---

## Architecture

The Agent Gateway is a gRPC service (`:50054`) that sits between AI agents and Stratium's existing services. All agent-initiated actions route through it.

```
┌─────────────────────────────────────────────────────────────┐
│                     AI Agent Frameworks                      │
│        (Claude Code / ChatGPT / Codex / LangChain)          │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────┼────────────────┐
              │ MCP Layer  │  Hooks Layer   │ REST Layer
              │ (Desktop)  │  (CLI agents)  │ (Custom)
              ▼            ▼                ▼
         stratium-mcp   Hook scripts    PAP REST API
              │            │                │
              └────────────┼────────────────┘
                           │ gRPC + mTLS
                           ▼
                  ┌────────────────────┐
                  │   Agent Gateway    │
                  │   (:50054)         │
                  │                    │
                  │ - Token minting    │
                  │ - Chain validation │
                  │ - Compound policy  │
                  │ - Audit logging    │
                  └────────┬───────────┘
                           │
               ┌───────────┼───────────┐
               ▼           ▼           ▼
          Platform    Key Manager   Key Access
          (:50051)    (:50052)     (:50053)
```

---

## The Double-Hop Authorization Model

Every agent action passes through three authorization layers, evaluated as a **compound AND**:

```
Effective Permission = user_allowed AND agent_allowed AND delegation_allowed
```

All three must return `ALLOW` for the action to proceed. If any returns `DENY`, the entire decision is `DENY`.

### Layer 1: User Policy

Standard ABAC evaluation — does the user's role, clearance, and attributes permit this action on this resource?

**Inputs:** Subject attributes (role, clearance, department), resource attributes (classification, type), action, context (IP, time).

**Examples:**
- User with INTERNAL clearance requests CONFIDENTIAL data → DENY
- User with TOP-SECRET clearance requests INTERNAL data → ALLOW

### Layer 2: Agent Policy

Independent evaluation of the agent's trust tier and capabilities.

**Agent Trust Tiers:**

| Tier | Name | Capabilities | Required for Action Tier |
|------|------|-------------|------------------------|
| 0 | Unverified | Read-only, sandboxed | Reasoning + Read-only |
| 1 | Registered | Read + limited write | + Internal modifications |
| 2 | Certified | Full read/write within scope | + External communications |
| 3 | Platform-Trusted | System-level actions | + Destructive/financial |

**Action Sensitivity Tiers:**

| Tier | Name | Examples |
|------|------|---------|
| 0 | Reasoning | Thinking, planning, analysis |
| 1 | Read-only | Reading files, querying databases, list operations |
| 2 | Internal modify | Writing files, updating configs, adding records |
| 3 | External comms | Email, webhooks, third-party API calls |
| 4 | Destructive | Delete, drop database, financial transactions |

A Registered agent (tier 1) cannot perform External communications (action tier 3), regardless of the user's permissions.

### Layer 3: Delegation Policy

Evaluation against the delegation token's scope — the specific, time-bounded authorization the user granted to the agent for this session.

**Delegation scope checks:**
- Is the tool in `approved_tools`?
- Is the action tier ≤ `max_action_tier`?
- Is the resource classification ≤ `classification_caps[hierarchy]`?
- Is the token expired?
- Is the token revoked?

---

## Delegation Token Model

Delegation tokens are HMAC-SHA256 signed JWTs minted by the Agent Gateway (or PAP). They bind a specific user-agent-session triple with a scoped set of permissions.

### Token Claims

| Claim | Type | Description |
|-------|------|-------------|
| `sub` | string | User ID (from OIDC) |
| `agent_id` | UUID | Registered agent ID |
| `agent_trust_tier` | int | Agent's trust tier (0-3) |
| `delegation_id` | UUID | Unique delegation identifier |
| `approved_tools` | []string | Tools this agent may invoke |
| `approved_actions` | []int | Action tiers allowed |
| `max_action_tier` | int | Maximum action sensitivity (0-4) |
| `classification_caps` | map[string]string | Per-hierarchy classification limits |
| `purpose` | string | Declared purpose of delegation |
| `depth` | int | Chain depth (0 = root) |
| `chain_agent_ids` | []UUID | Ordered agent IDs from root to this node |
| `parent_delegation_id` | UUID | Parent delegation (null for root) |
| `root_delegation_id` | UUID | Root delegation ID (always present) |
| `exp` | int64 | Expiration timestamp |

**Key properties:**
- Short-lived (default 15 minutes, max 24 hours)
- Bound to specific agent (can't be reused by different agent)
- Chains are linked (child references parent)
- Scope narrowing enforced at creation time

---

## Delegation Chains

A delegation chain is a linked sequence of delegations where each child's scope is equal to or a subset of its parent's scope. Sub-agents can receive the **full scope** of their parent — narrowing is allowed but not required.

```
Root: User → Agent A (CONFIDENTIAL, read+write+analyze, 30min)
  └─ Child: Agent A → Agent B (CONFIDENTIAL, read+write+analyze, 30min)  ← same scope
       └─ Grandchild: Agent B → Agent C (INTERNAL, read-only, 15min)     ← narrowed
```

### Scope Constraint Rules

When creating a child delegation, the Gateway enforces that the child does not **exceed** the parent:

- `child.max_action_tier` ≤ `parent.max_action_tier`
- `child.approved_tools` ⊆ `parent.approved_tools`
- `child.classification_caps[h]` ≤ `parent.classification_caps[h]` per hierarchy
- `child.expires_at` ≤ `parent.expires_at`
- `child.depth` < `max_depth` (default 5)

Equality is valid at every level — a child can have the same tools, same tier, and same caps as its parent. Any attempt to **widen** scope beyond the parent is rejected with a descriptive error.

### Chain Evaluation

At action time, the Gateway evaluates every hop in the chain:

```
For each delegation D[i] from root (i=0) to leaf (i=depth):
  1. Check D[i] is not revoked
  2. Check D[i] is not expired
  3. Check agent[i] trust tier ≥ required tier for action
  4. Check tool is in D[i].approved_tools
  5. Check action tier ≤ D[i].max_action_tier
  6. Check resource classification ≤ D[i].classification_caps

If any hop DENY → entire action DENY (report depth and principal)
If all hops ALLOW → action ALLOW
```

### Cascade Revocation

Revoking a delegation cascades to all descendants:

```
Revoke(D1) → Revokes D1 + D2 + D3 (all children and grandchildren)
```

The response includes the count and IDs of all revoked delegations.

---

## Integration Layers

The Agent Gateway is provider-agnostic. Three integration layers connect different agent types:

### MCP Layer (Desktop Agents)

For Claude Desktop and ChatGPT Desktop. The `stratium-mcp` binary runs as a subprocess, communicating via stdio/JSON-RPC (Model Context Protocol).

```
Desktop App → stdio → stratium-mcp → gRPC → Agent Gateway
```

The MCP server exposes Stratium tools (`register_agent`, `create_delegation`, `execute_action`, etc.) as native MCP tools that the AI agent can call directly.

### Hooks Layer (CLI Agents)

For Claude Code and OpenAI Codex. Native hook systems intercept tool calls before execution.

```
CLI Agent → PreToolUse hook → PAP REST API → Token validation + scope check
```

**SessionStart hook:** Bootstraps a delegation by calling `POST /api/v1/delegations` on the PAP. Writes the token to `/tmp/.stratium-delegation.json`.

**PreToolUse hook:** Reads the delegation token from file, classifies the command, calls `POST /api/v1/actions/check` on the PAP. Returns allow/deny to the platform.

**Fail-closed guarantee:** If hooks don't load (not in repo), the delegation file is never created, and all actions are denied.

**Command classification:** The hook normalizes Bash commands to Stratium tool names:

| Command Pattern | Normalized Tool | Action | Tier |
|----------------|----------------|--------|------|
| `cat`, `ls`, `grep` | `read_file` | read | 1 |
| `mv`, `cp`, `sed -i` | `write_file` | write | 2 |
| `curl`, `ssh`, `git push` | `bash` | send | 3 |
| `rm -rf`, `DROP TABLE` | `bash` | execute | 4 |

### REST Layer (Custom Agents)

The PAP server (`:8090`) exposes REST endpoints for delegation management and action checking:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/delegations` | Create delegation token |
| POST | `/api/v1/actions/check` | Validate action against delegation |
| GET | `/api/v1/delegations` | List active delegations |
| DELETE | `/api/v1/delegations/:id` | Revoke delegation + cascade |

Any HTTP-capable agent framework (LangChain, CrewAI, AutoGen) can use these endpoints.

---

## Cross-Provider Authorization

Delegation chains are transport-agnostic. A chain can span providers:

```
Claude Code (Anthropic, hooks layer)
  └─ Codex (OpenAI, hooks layer)
       └─ Custom Agent (REST layer)
```

Each agent calls the Gateway through its own layer. The Gateway evaluates the full chain regardless of how each hop connected.

---

## Audit Trail

Every authorization decision is logged with full chain context:

| Field | Example |
|-------|---------|
| `timestamp` | 2026-04-11T14:23:01Z |
| `agent_id` | f23bd2ac-... |
| `agent_name` | claude-analyst |
| `provider` | anthropic |
| `transport` | mcp |
| `tool_name` | read_file |
| `action_tier` | 1 |
| `authorized` | true |
| `user_decision` | ALLOW |
| `agent_decision` | ALLOW |
| `delegation_decision` | ALLOW |
| `chain_depth` | 0 |
| `delegation_id` | c7767a01-... |

For denied actions, the audit includes which hop denied and the reason:

```
agent_decision: DENY
agent_reason: "agent trust tier registered insufficient for action tier destructive"
denied_at_depth: 0
denied_principal: "agent:f23bd2ac-..."
```

---

## Comparison with Traditional Approaches

| Aspect | OAuth 2.0 | API Keys | Stratium Agent Gateway |
|--------|----------|---------|----------------------|
| Token scope | Fixed at creation | Full access | Dynamic, per-delegation, narrowable |
| Revocation | Application-dependent | App-dependent | Real-time, platform-enforced |
| Delegation chains | Not supported | Not supported | Native, recursive, scope-narrowing |
| Agent identity | Single service identity | None | Independent trust tier per agent |
| Classification caps | Not supported | Not supported | Per-hierarchy limits |
| Compound policy | Service RBAC only | None | User AND Agent AND Delegation |
| Audit granularity | "User did X via app" | "Service did X" | "User → Agent A → Agent B → Action X" |
| Enforcement | Agent voluntarily respects scopes | Inherent full access | Cryptographic binding; impossible to exceed |

---

## Security Properties

**Cryptographic non-forgeability:** Delegation tokens are HMAC-SHA256 signed. Agents cannot mint or modify tokens.

**Scope ceiling:** Child delegations cannot exceed their parent's scope. They may receive the same scope or a narrower one. No path exists to escalate beyond the root delegation.

**Fail-closed:** When the Gateway is unreachable, hooks deny all actions. No degraded-permission fallback.

**Point-in-time authorization:** Once an action is authorized and begins execution, it completes. Revocation takes effect on the *next* action, not mid-action.

**Provider independence:** Trust is based on Stratium agent registration, not on the AI provider's identity claims. An "openai" agent and an "anthropic" agent are evaluated by the same rules.

---

## Implementation Reference

| Component | Path | Purpose |
|-----------|------|---------|
| Agent Gateway | `go/services/agent-gateway/` | Core authorization service (gRPC) |
| PAP delegation REST | `go/services/pap/delegation_handlers.go` | REST endpoints for hooks |
| MCP server | `go/cmd/stratium-mcp/` | stdio/JSON-RPC for desktop agents |
| Check mode | `go/internal/mcp/check.go` | Single-shot authorization for Claude Code hooks |
| Codex hooks | `demos/codex/hooks/` | Python hook scripts for OpenAI Codex |
| Claude hooks | `demos/mcp/hooks/` | Bash hook scripts for Claude Code |
| Proto definitions | `proto/services/agent-gateway/` | gRPC service and message definitions |
| DB schema | `deployment/postgres/04-init-agent-auth.sql` | Agent, delegation, and audit tables |
