# PRD: Stratium MCP Server — Agent Authorization Demo

**Author:** Benjamin Parrish
**Date:** 2026-04-04
**Status:** Draft
**Branch:** `feature/mcp-agent-auth-demo`

---

## 1. Overview

### 1.1 Problem

AI agents (Claude, GPT-4, etc.) operating on behalf of enterprise users currently have no standardized way to enforce least-privilege access control. When an AI agent accesses sensitive financial data, there is no cryptographically enforced boundary between what the user can access and what the agent should access. Existing solutions either trust agents fully or block them entirely — neither is acceptable for regulated industries.

### 1.2 Solution

Build a **Model Context Protocol (MCP) server** (`stratium-mcp`) that exposes Stratium's agent authorization platform as native Claude tools. This enables Claude to operate under cryptographically enforced, time-bounded, scope-limited delegations — with full audit trails, delegation chains for sub-agents, and real-time revocation.

### 1.3 Demo Objective

Demonstrate to investors the full agent authorization lifecycle in a **live, interactive Claude session** backed by a **fully real** Stratium backend (Agent Gateway, Platform, Keycloak, PostgreSQL). The demo tells the story of an AI agent accessing financial records under strict authorization controls.

### 1.4 Target Audience

**Investors and VCs** — emphasis on market differentiation, the "aha moment" of real-time authorization enforcement, and the compliance story. Technical depth is present but subordinate to narrative impact.

---

## 2. Architecture

### 2.1 System Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   Claude Code (IDE)                      │
│                                                         │
│  User types: "Analyze our Q3 financial forecasts"       │
│                         │                               │
│                    MCP Protocol                          │
│                    (stdio/JSON-RPC)                      │
└─────────────┬───────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────┐
│              stratium-mcp (Go binary)                    │
│                                                         │
│  MCP Tools:                                             │
│  ├─ register_agent          ├─ execute_action           │
│  ├─ get_agent               ├─ check_permission         │
│  ├─ list_agents             ├─ validate_action_plan     │
│  ├─ suspend_agent           ├─ get_delegation_chain     │
│  ├─ create_delegation       └─ query_audit_trail*       │
│  ├─ create_sub_delegation        (* admin-only CLI)     │
│  ├─ revoke_delegation                                   │
│  └─ list_delegations                                    │
│                                                         │
│  Internal:                                              │
│  ├─ gRPC client → Agent Gateway (:50054)                │
│  ├─ OIDC auto-login → Keycloak (:8080)                  │
│  └─ Session state (delegation tokens, agent IDs)        │
└─────────┬───────────────────────────────────────────────┘
          │ gRPC + mTLS
          ▼
┌─────────────────────────────────────────────────────────┐
│              Docker Compose Stack                        │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │Agent Gateway  │  │  Platform    │  │  Keycloak    │  │
│  │  :50054       │──│  :50051      │  │  :8080       │  │
│  │  (authz)      │  │  (policy)    │  │  (OIDC)      │  │
│  └──────┬───────┘  └──────────────┘  └──────────────┘  │
│         │                                               │
│  ┌──────┴───────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Key Manager  │  │  Key Access  │  │  PostgreSQL  │  │
│  │  :50052      │  │  :50053      │  │  :5432       │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### 2.2 MCP Transport

**stdio** — Claude Code spawns `stratium-mcp` as a subprocess and communicates via stdin/stdout JSON-RPC. No network configuration, no CORS, no TLS between Claude and the MCP server.

### 2.3 MCP Implementation

**Custom minimal** — implement the MCP protocol directly (JSON-RPC 2.0 over stdin/stdout) without external MCP SDK dependencies. The protocol surface is small:

- `initialize` / `initialized` handshake
- `tools/list` → return tool definitions
- `tools/call` → dispatch to handler, return result
- `notifications/cancelled` → handle cancellation

This gives full control, zero dependency risk, and keeps the binary lean.

### 2.4 Authentication Flow

**Auto-login via OIDC (Keycloak):**

1. On first tool call, MCP server checks for cached token in `~/.stratium/token.json`
2. If missing/expired: open browser to Keycloak login page via localhost callback
3. User authenticates once → MCP server receives OAuth2 token
4. Token cached locally with refresh token support
5. Subsequent tool calls use cached token transparently

For the demo: pre-seed a demo user in Keycloak (`demo-analyst` / `demo123`) so login is instant.

---

## 3. Demo Scenario: Financial Records Authorization

### 3.1 Data Classification Hierarchy (4-tier)

| Tier | Label | Example Data | Who Can Access |
|------|-------|-------------|----------------|
| 0 | PUBLIC | Press releases, annual reports | Anyone |
| 1 | INTERNAL | Quarterly revenue forecasts, headcount plans | Employees |
| 2 | CONFIDENTIAL | Board materials, strategic plans, salary data | Directors+ |
| 3 | RESTRICTED | M&A targets, insider trading watch-lists, pre-earnings | C-suite + legal |

### 3.2 Demo Personas

| Persona | Role | Clearance | Agent Trust Tier |
|---------|------|-----------|-----------------|
| `demo-analyst` | Financial Analyst | INTERNAL (tier 1) | REGISTERED (tier 1) |
| `demo-director` | VP Finance | CONFIDENTIAL (tier 2) | CERTIFIED (tier 2) |
| `demo-admin` | CISO / Admin | RESTRICTED (tier 3) | PLATFORM_TRUSTED (tier 3) |

### 3.3 Demo Resources (seeded)

```
financial-records/
├── public/
│   ├── annual-report-2025.pdf          [PUBLIC]
│   └── press-release-q3.txt            [PUBLIC]
├── internal/
│   ├── q3-revenue-forecast.xlsx        [INTERNAL]
│   └── headcount-plan-2026.csv         [INTERNAL]
├── confidential/
│   ├── board-deck-q4.pptx              [CONFIDENTIAL]
│   └── strategic-plan-2027.pdf         [CONFIDENTIAL]
└── restricted/
    ├── ma-target-acme-corp.pdf         [RESTRICTED]
    └── insider-watchlist.csv           [RESTRICTED]
```

---

## 4. MCP Tool Definitions

### 4.1 Agent Management

#### `register_agent`
Register a new AI agent in the Stratium platform.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | yes | Agent display name |
| `description` | string | no | What this agent does |
| `provider` | string | yes | "anthropic", "openai", "custom" |
| `model_identifier` | string | no | e.g., "claude-sonnet-4-6" |
| `trust_tier` | int | yes | 0=UNVERIFIED, 1=REGISTERED, 2=CERTIFIED, 3=PLATFORM_TRUSTED |
| `allowed_tools` | string[] | no | Tool whitelist (empty = unrestricted) |
| `allowed_actions` | int[] | no | Action tier whitelist |

**Returns:** `{ agent_id, client_id, created_at }`

#### `get_agent`
Retrieve agent details by ID.

| Parameter | Type | Required |
|-----------|------|----------|
| `agent_id` | string (UUID) | yes |

**Returns:** Full agent record including trust tier, cert status, allowed tools/actions.

#### `list_agents`
List all registered agents, optionally filtered.

| Parameter | Type | Required |
|-----------|------|----------|
| `provider` | string | no |
| `trust_tier` | int | no |
| `enabled` | bool | no |

**Returns:** `{ agents: Agent[], total: int }`

#### `suspend_agent`
Suspend an agent, revoking all active delegations.

| Parameter | Type | Required |
|-----------|------|----------|
| `agent_id` | string (UUID) | yes |
| `reason` | string | yes |

**Returns:** `{ suspended: true, revoked_delegations: int }`

### 4.2 Delegation Lifecycle

#### `create_delegation`
Create a root delegation token for an agent acting on behalf of the current user.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `agent_id` | string (UUID) | yes | Target agent |
| `approved_tools` | string[] | yes | Tools this delegation permits |
| `max_action_tier` | int | yes | Highest action tier (0-4) |
| `classification_cap` | string | no | Max classification level (e.g., "INTERNAL") |
| `purpose` | string | yes | Why this delegation exists |
| `ttl_seconds` | int | no | Time-to-live (default: 900s / 15min) |

**Returns:** `{ delegation_id, delegation_token, expires_at, depth: 0 }`

#### `create_sub_delegation`
Create a child delegation with narrower scope (for sub-agent chains).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `parent_delegation_token` | string | yes | Parent's delegation token |
| `child_agent_id` | string (UUID) | yes | Sub-agent receiving delegation |
| `approved_tools` | string[] | yes | Must be ⊆ parent's tools |
| `max_action_tier` | int | yes | Must be ≤ parent's tier |
| `classification_cap` | string | no | Must be ≤ parent's cap |
| `purpose` | string | yes | Sub-agent's purpose |
| `ttl_seconds` | int | no | Must be ≤ parent's remaining TTL |

**Returns:** `{ delegation_id, delegation_token, expires_at, depth, root_delegation_id }`

#### `revoke_delegation`
Revoke a delegation and cascade to all children.

| Parameter | Type | Required |
|-----------|------|----------|
| `delegation_id` | string (UUID) | yes |
| `reason` | string | yes |

**Returns:** `{ revoked_count, revoked_delegation_ids[] }`

#### `list_delegations`
List active delegations for the current user.

| Parameter | Type | Required |
|-----------|------|----------|
| `agent_id` | string (UUID) | no |
| `active_only` | bool | no |

**Returns:** `{ delegations: Delegation[] }`

### 4.3 Authorization & Execution

#### `execute_action`
Execute an action through the authorization gateway. This is the core tool — every agent operation flows through here.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `delegation_token` | string | yes | Active delegation JWT |
| `tool_name` | string | yes | Tool being invoked |
| `action` | string | yes | "read", "write", "delete", etc. |
| `action_tier` | int | yes | 0-4 action classification |
| `resource_id` | string | no | Target resource identifier |
| `resource_classification` | string | no | Resource's classification level |

**Returns:**
```json
{
  "authorized": true|false,
  "decision": {
    "user_decision": "ALLOW|DENY",
    "user_reason": "...",
    "agent_decision": "ALLOW|DENY",
    "agent_reason": "...",
    "delegation_decision": "ALLOW|DENY",
    "delegation_reason": "...",
    "chain_decisions": [
      { "depth": 0, "agent_id": "...", "agent_decision": "ALLOW", "delegation_decision": "ALLOW" },
      { "depth": 1, "agent_id": "...", "agent_decision": "DENY", "delegation_reason": "tier exceeds max" }
    ]
  }
}
```

#### `check_permission`
Dry-run permission check without executing the action.

| Parameter | Type | Required |
|-----------|------|----------|
| `delegation_token` | string | yes |
| `tool_name` | string | yes |
| `action` | string | yes |
| `action_tier` | int | yes |
| `resource_classification` | string | no |

**Returns:** Same as `execute_action` but without proxying to target service.

#### `validate_action_plan`
Validate a batch of planned actions against a delegation's scope.

| Parameter | Type | Required |
|-----------|------|----------|
| `delegation_token` | string | yes |
| `actions` | ActionPlan[] | yes |

Each ActionPlan: `{ tool_name, action, action_tier, resource_classification }`

**Returns:** `{ valid: bool, results: [{ action, allowed: bool, reason }] }`

#### `get_delegation_chain`
Inspect the full delegation chain for audit/debugging.

| Parameter | Type | Required |
|-----------|------|----------|
| `delegation_id` | string (UUID) | yes |

**Returns:** Ordered chain from root→leaf with agent names, trust tiers, scopes, expiry at each hop.

---

## 5. Admin CLI: `stratium-audit`

A separate CLI binary for admin-only audit trail access. Agents cannot query their own audit trail.

### 5.1 Commands

```bash
# List recent authorization decisions
stratium-audit logs --limit 20 --since 5m

# Filter by agent
stratium-audit logs --agent-id <uuid> --action-tier 2

# Filter by decision
stratium-audit logs --decision DENY --since 1h

# Show delegation chain activity
stratium-audit chain <delegation-id>

# Agent activity summary
stratium-audit agent-summary <agent-id> --since 24h

# Export for compliance
stratium-audit export --format json --since 7d --output audit-report.json
```

### 5.2 Output Format

```
TIMESTAMP            AGENT               TOOL            TIER  DECISION  REASON
2026-04-04 14:23:01  claude-analyst       read_file       1     ALLOW     scope valid, tier ok
2026-04-04 14:23:05  claude-analyst       read_file       1     DENY      classification: CONFIDENTIAL > cap INTERNAL
2026-04-04 14:23:08  claude-analyst       write_file      2     DENY      tier 2 > max_action_tier 1
```

### 5.3 Implementation

- Queries PAP REST API (`GET /api/v1/audit-logs`) with auth token
- Authenticates via cached OIDC token or `--token` flag
- Formats output as table (default), JSON (`--format json`), or CSV (`--format csv`)

---

## 6. Sub-Agent Delegation via Claude Agent SDK

### 6.1 Architecture

The MCP server includes an `orchestrate_sub_agent` tool that spawns a real Claude sub-agent using the **Anthropic Agent SDK (Python)**. The sub-agent receives its own MCP server connection with a narrower delegation token.

```
Claude (parent session)
  │
  ├─ stratium-mcp (parent delegation: INTERNAL, read+write)
  │
  └─ calls orchestrate_sub_agent tool
       │
       ├─ MCP server creates sub-delegation (INTERNAL, read-only)
       ├─ Spawns Python process using claude_agent_sdk
       │   └─ Sub-agent Claude session
       │       └─ stratium-mcp (child delegation: read-only, narrower scope)
       │
       └─ Returns sub-agent result to parent Claude
```

### 6.2 `orchestrate_sub_agent` Tool

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `task` | string | yes | Natural language task for the sub-agent |
| `sub_agent_name` | string | yes | Name for the sub-agent |
| `approved_tools` | string[] | yes | Must be ⊆ parent delegation tools |
| `max_action_tier` | int | yes | Must be ≤ parent delegation tier |
| `classification_cap` | string | no | Must be ≤ parent cap |

**Flow:**
1. Register sub-agent via `RegisterAgent` RPC (trust_tier = parent - 1, min 0)
2. Create child delegation via `CreateDelegation` with `parent_delegation_token`
3. Write temporary MCP config pointing to a new `stratium-mcp` instance with the child token
4. Spawn `claude_agent_sdk.Agent` with the task and MCP config
5. Capture sub-agent output
6. Return result to parent Claude session
7. Cleanup: revoke child delegation

### 6.3 Demo Scenario: Delegation Chain

```
Parent Claude (VP Finance, CERTIFIED, CONFIDENTIAL clearance)
  └─ "Delegate to a junior analyst agent to summarize Q3 public reports"
      │
      Sub-Agent Claude (Analyst, REGISTERED, PUBLIC clearance)
        ├─ read annual-report-2025.pdf    → ALLOW (PUBLIC ≤ PUBLIC)
        ├─ read q3-revenue-forecast.xlsx  → DENY  (INTERNAL > PUBLIC)
        └─ Result returned to parent with audit trail showing chain
```

---

## 7. Demo Script (Investor Walkthrough)

### Pre-Demo Setup (one-time)

```bash
# 1. Start the full Stratium stack
docker-compose --profile agent-auth up -d

# 2. Seed demo data
./scripts/seed-demo-data.sh

# 3. Configure Claude Code MCP
# (automatically via claude_desktop_config.json)
```

### Act 1: The Setup (2 minutes)

**Talking Point:** *"Let me show you what happens when an AI agent operates under zero-trust authorization controls."*

**Claude interaction:**
```
You: "I need help analyzing our Q3 financial data. Let's set up proper
      authorization first."

Claude: [calls register_agent]
  → Registers "claude-financial-analyst" at trust tier 1 (REGISTERED)
  → Returns agent_id

Claude: [calls create_delegation]
  → Creates delegation: tools=[read_file, list_files, search],
    max_action_tier=1 (READ_ONLY), classification_cap="INTERNAL",
    ttl=120 seconds, purpose="Q3 financial analysis"
  → Returns delegation_token, expires in 2 minutes

Claude: "I'm now authorized as a financial analyst with read-only access
         to INTERNAL and below. I have 2 minutes. Let me check what I
         can access..."

Claude: [calls validate_action_plan]
  → Validates planned actions against delegation scope
  → Shows: read PUBLIC ✓, read INTERNAL ✓, read CONFIDENTIAL ✗, write ✗
```

**Talking Point:** *"The agent just self-assessed its own permissions. It knows exactly what it can and can't do — before it tries."*

### Act 2: Authorization in Action (3 minutes)

**Talking Point:** *"Now watch what happens when the agent operates within and outside its authorized scope."*

**Claude interaction:**
```
You: "Go ahead and analyze whatever financial data you can access."

Claude: [calls execute_action: read public/annual-report-2025.pdf]
  → ALLOW (PUBLIC ≤ INTERNAL cap, read ≤ READ_ONLY tier)
  → "Annual report shows revenue of $2.3B, up 15% YoY..."

Claude: [calls execute_action: read internal/q3-revenue-forecast.xlsx]
  → ALLOW (INTERNAL ≤ INTERNAL cap)
  → "Q3 forecast projects $680M revenue..."

Claude: [calls execute_action: read confidential/board-deck-q4.pptx]
  → DENY: "Classification CONFIDENTIAL exceeds delegation cap INTERNAL"
  → Claude explains: "I don't have access to board materials — they're
    classified CONFIDENTIAL and my clearance only goes to INTERNAL."

Claude: [calls execute_action: write analysis-report.md]
  → DENY: "Action tier INTERNAL_MODIFY (2) exceeds max_action_tier READ_ONLY (1)"
  → Claude explains: "I can't write files — my delegation is read-only.
    I can tell you my analysis verbally instead."
```

**Talking Point:** *"Three things just happened that don't happen with any other AI platform: (1) the agent was denied access to classified data in real-time, (2) it was denied write access because its delegation is read-only, and (3) it explained WHY it was denied — because the authorization decision includes the reason."*

### Act 3: Delegation Chains — Sub-Agent (3 minutes)

**Talking Point:** *"Now here's where it gets really interesting. What if this agent needs to delegate to a sub-agent? Watch how permissions attenuate."*

**Claude interaction:**
```
You: "Can you delegate to a junior agent to summarize just the public
      reports? I want to see how sub-delegation works."

Claude: [calls orchestrate_sub_agent]
  → Registers sub-agent "claude-junior-analyst" at trust tier 0
  → Creates child delegation: tools=[read_file], max_tier=READ_ONLY,
    classification_cap="PUBLIC" (narrower than parent's INTERNAL)
  → Spawns real sub-agent Claude session

  Sub-Agent: [execute_action: read public/annual-report-2025.pdf]
    → ALLOW (chain: parent ALLOW + child ALLOW)
    → Summarizes annual report

  Sub-Agent: [execute_action: read internal/q3-revenue-forecast.xlsx]
    → DENY at depth 1: "Classification INTERNAL exceeds child cap PUBLIC"
    → Chain shows: parent would ALLOW, but child delegation DENY

  → Sub-agent returns summary to parent

Claude: [calls get_delegation_chain]
  → Shows: depth 0 (VP Finance, CERTIFIED) → depth 1 (Junior, UNVERIFIED)
  → Each hop shows narrowed scope

Claude: "Here's the summary from my sub-agent. Note that it could only
         access PUBLIC data — even though I can access INTERNAL, I
         deliberately narrowed its scope."
```

**Talking Point:** *"The sub-agent's permissions can ONLY be equal to or narrower than the parent's. This is cryptographically enforced — a sub-agent can never escalate privileges. This is what zero-trust delegation looks like."*

### Act 4: Expiry & Revocation (2 minutes)

**Talking Point:** *"Authorization isn't just about granting access — it's about taking it away."*

#### Part A: TTL Expiry

```
[~2 minutes have passed since delegation creation]

Claude: [calls execute_action: read public/press-release-q3.txt]
  → DENY: "Delegation expired at 2026-04-04T14:25:00Z"
  → Claude: "My authorization just expired. I'd need a new delegation
    to continue working."
```

**Talking Point:** *"The delegation had a 2-minute TTL. Time-bounded access means even if a session is compromised, the window of exposure is limited."*

#### Part B: Manual Revocation

```
You: "Let me create a new delegation, then revoke it mid-session."

Claude: [calls create_delegation] → New token, 15 min TTL

Claude: [calls execute_action: read public/annual-report-2025.pdf]
  → ALLOW ✓

[In separate terminal]
$ stratium-audit logs --limit 5
  → Shows the ALLOW decision

$ stratium-audit revoke <delegation-id> --reason "demo revocation"
  → Delegation revoked, cascades to children

[Back in Claude]
Claude: [calls execute_action: read public/press-release-q3.txt]
  → DENY: "Delegation revoked: demo revocation"
  → Claude: "My delegation was just revoked by an administrator."
```

**Talking Point:** *"An admin just revoked the agent's access from a separate terminal — and the very next tool call was denied. Real-time revocation with cascade to all sub-agents. This is the kill switch every CISO asks for."*

### Act 5: Audit Trail (1 minute)

**Talking Point:** *"Everything we just did is auditable."*

```
[In admin terminal — Agent Gateway logs show every authorization decision]
$ docker logs stratium-agent-gateway --tail 15

INFO: 14:23:00 Registered agent e3bc8051-... (name=claude-financial-analyst, provider=anthropic, trust_tier=registered)
INFO: 14:23:00 Created delegation 4cdb0376-... for user=demo-analyst agent=e3bc8051-... depth=0 ttl=2m0s
INFO: 14:23:01 Action authorized: user=demo-analyst chain_depth=1 tool=read_file action=read
INFO: 14:23:05 Action authorized: user=demo-analyst chain_depth=1 tool=read_file action=read
INFO: 14:23:08 Action denied: user=demo-analyst chain_depth=1 tool=write_file action=write reason="tool not in delegation scope"
INFO: 14:24:00 Registered agent a1b2c3d4-... (name=claude-junior-analyst, provider=anthropic, trust_tier=unverified)
INFO: 14:24:00 Created delegation 7e8f9a0b-... for user=demo-analyst agent=a1b2c3d4-... depth=1 ttl=5m0s
INFO: 14:24:01 Action authorized: user=demo-analyst chain_depth=2 tool=read_file action=read
INFO: 14:24:05 Action denied: user=demo-analyst chain_depth=2 tool=read_file action=read reason="denied at depth 1"
INFO: 14:25:00 Action denied: user=demo-analyst tool=read_file reason="delegation expired"
INFO: 14:26:45 Delegation 4cdb0376-... revoked (reason: demo revocation, cascade: 2 delegations)
INFO: 14:26:50 Action denied: user=demo-analyst tool=read_file reason="delegation revoked"
INFO: 14:26:50 Suspended agent e3bc8051-... (reason: demo complete, revoked delegations: 1)
```

**Talking Point:** *"Full audit trail — every registration, every delegation, every authorization decision with the agent, tool, and reason. Timestamped, centralized in the gateway service logs, ready for your SIEM. This is what regulated industries need for AI governance compliance."*

---

## 8. Implementation Plan

### 8.1 Component Breakdown

#### Component 1: MCP Protocol Layer (`mcp/`)

Custom minimal JSON-RPC 2.0 implementation over stdio.

**Files:**
- `go/cmd/stratium-mcp/main.go` — Entry point, stdio loop
- `go/internal/mcp/protocol.go` — JSON-RPC message types, read/write
- `go/internal/mcp/server.go` — MCP server (initialize, tools/list, tools/call dispatch)
- `go/internal/mcp/types.go` — MCP-specific types (Tool, ToolResult, etc.)

**Protocol Messages:**
```
→ {"jsonrpc":"2.0","method":"initialize","params":{...},"id":1}
← {"jsonrpc":"2.0","result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"stratium-mcp","version":"1.0.0"}},"id":1}
→ {"jsonrpc":"2.0","method":"notifications/initialized"}
→ {"jsonrpc":"2.0","method":"tools/list","id":2}
← {"jsonrpc":"2.0","result":{"tools":[...]},"id":2}
→ {"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{...}},"id":3}
← {"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"..."}]},"id":3}
```

#### Component 2: gRPC Client (`internal/gateway/`)

Client wrapper for the Agent Gateway gRPC service.

**Files:**
- `go/internal/gateway/client.go` — gRPC dial, connection management, TLS config
- `go/internal/gateway/agents.go` — RegisterAgent, GetAgent, ListAgents, SuspendAgent
- `go/internal/gateway/delegations.go` — CreateDelegation, RevokeDelegation, GetDelegationChain
- `go/internal/gateway/actions.go` — ExecuteAction, ValidateActionPlan

**Reuses:** `proto/services/agent-gateway/` generated Go code.

#### Component 3: OIDC Auth (`internal/auth/`)

Auto-login flow for Keycloak authentication.

**Files:**
- `go/internal/auth/oidc.go` — OAuth2 authorization code flow with localhost callback
- `go/internal/auth/token_cache.go` — Cache tokens in `~/.stratium/token.json`, refresh on expiry

**Flow:**
1. Check `~/.stratium/token.json` for valid token
2. If expired: attempt refresh token grant
3. If no token: start localhost HTTP server on random port, open browser to Keycloak authorize URL
4. Keycloak redirects to localhost callback with auth code
5. Exchange code for token, cache, return

#### Component 4: Tool Handlers (`internal/tools/`)

One handler per MCP tool, mapping tool arguments to gRPC calls.

**Files:**
- `go/internal/tools/registry.go` — Tool registration, argument parsing, dispatch
- `go/internal/tools/agents.go` — register_agent, get_agent, list_agents, suspend_agent
- `go/internal/tools/delegations.go` — create_delegation, create_sub_delegation, revoke_delegation, list_delegations
- `go/internal/tools/actions.go` — execute_action, check_permission, validate_action_plan, get_delegation_chain
- `go/internal/tools/sub_agent.go` — orchestrate_sub_agent (spawns Python Agent SDK process)

#### Component 5: Sub-Agent Orchestrator (`scripts/sub_agent_runner.py`)

Python script that uses `claude_agent_sdk` to run a sub-agent with its own MCP config.

**Files:**
- `demos/mcp/sub_agent_runner.py` — Agent SDK orchestrator
- `demos/mcp/sub_agent_mcp_config.json.tmpl` — Template MCP config for sub-agent

**Flow:**
1. Receives args: task, delegation_token, MCP server binary path
2. Writes temporary MCP config with child delegation token as env var
3. Creates `claude_agent_sdk.Agent` with MCP config
4. Runs agent with the task prompt
5. Captures and returns output
6. Cleans up temp config

#### Component 6: Admin CLI (`cmd/stratium-audit/`)

**Files:**
- `go/cmd/stratium-audit/main.go` — CLI entry point (cobra)
- `go/internal/audit/client.go` — PAP REST API client for audit logs
- `go/internal/audit/formatter.go` — Table, JSON, CSV output formatters

#### Component 7: Demo Seed Data (`demos/mcp/`)

**Files:**
- `demos/mcp/seed-demo-data.sh` — Creates demo users in Keycloak, seeds financial records, creates base policies
- `demos/mcp/financial-records/` — Sample files at each classification tier
- `demos/mcp/README.md` — Setup and walkthrough instructions

### 8.2 Configuration

**Claude Code MCP config** (`~/.claude/claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "stratium": {
      "command": "/path/to/stratium-mcp",
      "args": ["--config", "/path/to/mcp-config.yaml"],
      "env": {
        "STRATIUM_GATEWAY_ADDRESS": "localhost:50054",
        "STRATIUM_KEYCLOAK_URL": "http://localhost:8080/realms/stratium",
        "STRATIUM_TLS_CA": "/path/to/certs/ca.crt"
      }
    }
  }
}
```

**MCP server config** (`mcp-config.yaml`):
```yaml
gateway:
  address: localhost:50054
  tls:
    enabled: true
    ca_file: ./config/examples/certs/ca.crt

auth:
  keycloak_url: http://localhost:8080/realms/stratium
  client_id: stratium-mcp
  token_cache: ~/.stratium/token.json

sub_agent:
  python_binary: python3
  runner_script: ./demos/mcp/sub_agent_runner.py
  stratium_mcp_binary: ./stratium-mcp

logging:
  level: info
  format: json
```

### 8.3 Build & Run

```bash
# Build MCP server
go build -o bin/stratium-mcp ./go/cmd/stratium-mcp

# Build audit CLI
go build -o bin/stratium-audit ./go/cmd/stratium-audit

# Start backend
docker-compose --profile agent-auth up -d

# Seed demo data
./demos/mcp/seed-demo-data.sh

# Configure Claude Code
cp demos/mcp/claude_desktop_config.json ~/.claude/

# Run demo
claude  # Start Claude Code — stratium-mcp starts automatically
```

---

## 9. Investor Talking Points

### Why This Matters

| Point | Message |
|-------|---------|
| **Market timing** | Every enterprise adopting AI agents needs authorization controls. This is the seatbelt for AI agents — you don't ship the car without it. |
| **Zero-trust for AI** | Extends the zero-trust model that enterprises already use for humans to AI agents. Not a new paradigm — an extension of what CISOs already understand. |
| **Cryptographic enforcement** | Not policy documents or best practices — real-time, cryptographically enforced authorization with HMAC-signed delegation tokens. |
| **Delegation chains** | The only platform that supports hierarchical agent delegation with automatic scope attenuation. Sub-agents can never escalate beyond their parent. |
| **Kill switch** | Real-time revocation with cascade. Admin revokes one delegation, entire chain goes dark instantly. |
| **Audit everything** | Every decision, every agent, every tool call — timestamped, queryable, exportable. SOC 2, HIPAA, SOX-ready. |
| **Model agnostic** | Works with Claude, GPT-4, Gemini, open-source models — any agent that supports MCP or tool use. |
| **Developer experience** | One MCP config line and agents are authorized. No SDK changes, no application code changes. |

### Competitive Differentiation

| Feature | Stratium | AWS Verified Permissions | OPA/Rego | Custom RBAC |
|---------|----------|--------------------------|----------|-------------|
| Agent-specific authorization | ✓ | ✗ | ✗ | ✗ |
| Delegation chains | ✓ (depth 5) | ✗ | ✗ | ✗ |
| Real-time revocation | ✓ (cascade) | ✓ | ✗ | Partial |
| MCP integration | ✓ (native) | ✗ | ✗ | ✗ |
| Classification hierarchies | ✓ (NATO + Commercial) | ✗ | Manual | ✗ |
| Cedar policy engine | ✓ | ✓ | ✗ | ✗ |
| Time-bounded tokens | ✓ (TTL) | Session-based | ✗ | Session-based |
| Compound decisions (user+agent+delegation) | ✓ | ✗ | ✗ | ✗ |

---

## 10. Testing Plan

### 10.1 Unit Tests

| Component | Test File | Coverage Target |
|-----------|-----------|----------------|
| MCP protocol | `mcp/protocol_test.go` | JSON-RPC parse/serialize, error codes |
| Tool handlers | `tools/*_test.go` | Argument validation, gRPC mock calls |
| OIDC auth | `auth/oidc_test.go` | Token cache, refresh flow |
| Audit formatter | `audit/formatter_test.go` | Table, JSON, CSV output |

### 10.2 Integration Tests

| Scenario | What it tests |
|----------|--------------|
| Full tool lifecycle | register → delegate → execute → revoke via MCP |
| Sub-delegation chain | Parent creates child, child scope is narrower |
| TTL expiry | Delegation expires, subsequent calls denied |
| Revocation cascade | Revoke root, all children denied |
| Classification enforcement | Access at each tier, verify allow/deny boundaries |

### 10.3 Demo Dry Run

Run the full investor walkthrough script against the local Docker stack. Verify:
- [ ] All 5 acts complete without errors
- [ ] Timing works (2-min TTL for Act 4a)
- [ ] Sub-agent spawns and returns results (Act 3)
- [ ] Audit CLI shows correct log entries (Act 5)
- [ ] No stale state between demo runs (cleanup script)

---

## 11. Security Considerations

| Risk | Mitigation |
|------|-----------|
| Delegation token theft | HMAC-SHA256 signed, short TTL (default 15min), conversation-scoped |
| Privilege escalation via sub-agent | `ScopeNarrows()` enforced server-side — child scope must be ⊆ parent |
| OIDC token exposure | Stored in `~/.stratium/token.json` with 0600 permissions, refresh tokens rotated |
| MCP server compromise | Server is a local process (stdio), no network surface. gRPC to gateway uses mTLS |
| Audit log tampering | Logs stored in PostgreSQL, admin-only access via authenticated API |
| Demo credential leakage | Demo users have minimal permissions, isolated tenant, documented in seed script |

---

## 12. Future Extensions (Post-Demo)

- **PAP UI integration** — Visual dashboard for delegation chains and audit trail
- **SSE transport** — Enable remote/shared MCP server for team demos
- **Policy authoring via MCP** — Expose Cedar policy tools for interactive policy creation
- **Multi-model orchestration** — Demo with Claude + GPT-4 agents in the same delegation chain
- **Webhook notifications** — Real-time alerts when agents hit authorization boundaries
- **SDK packages** — Publish `stratium-mcp` as a brew/apt installable binary
