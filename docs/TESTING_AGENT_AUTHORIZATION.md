# Manual Testing Guide: AI Agent Authorization

**Feature:** Agent Authorization (double-hop model)
**Feature Flag:** `agent-auth`
**Date:** 2026-03-28

---

## Prerequisites

- Docker and Docker Compose installed
- `grpcurl` installed (`brew install grpcurl`)
- `jq` installed (`brew install jq`)
- Access to OpenAI Codex or Claude Code (for end-to-end agent testing)
- Stratium repo cloned and built (`make build`)

### Connectivity Notes

All Stratium services run with TLS using self-signed certificates:

| Protocol | Tool | Flags Needed |
|----------|------|-------------|
| **HTTPS** (PAP :8090) | `curl` | `-sk` (skip cert verification for self-signed) |
| **gRPC+TLS** (Platform :50051, Gateway :50054) | `grpcurl` | `-cacert config/examples/certs/ca.crt` |
| **HTTP** (Keycloak :8080) | `curl` | `-s` (no TLS, plain HTTP) |

The Agent Gateway gRPC service requires the `x-user-id` metadata header for `CreateDelegation` and `RegisterAgent` only. `RevokeDelegation`, `ExecuteAction`, `ValidateActionPlan`, and `GetDelegationChain` do not require it.

---

## 1. Environment Setup

### 1.1 Start All Services (Including Agent Gateway)

```bash
cd deployment/docker

# Start base services + agent gateway (requires agent-auth profile)
docker-compose --profile agent-auth up -d

# Verify all services are running
docker-compose --profile agent-auth ps
```

Expected services:
| Service | Port | Status |
|---------|------|--------|
| postgres | 5432 | healthy |
| keycloak | 8080 | healthy |
| redis | 6379 | healthy |
| platform | 50051 | running |
| key-manager | 50052 | running |
| key-access | 50053 | running |
| pap | 8090 | running |
| agent-gateway | 50054 | running |

### 1.2 Verify Services

```bash
# Keycloak is up
curl -s http://localhost:8080/realms/stratium | jq .realm

# PAP health check
curl -sk https://localhost:8090/health | jq .

# Agent Gateway gRPC reflection (should list services)
grpcurl -cacert config/examples/certs/ca.crt localhost:50054 list
```

### 1.3 Get an Admin Token

```bash
# Using the helper script
./scripts/get_token.sh admin456 admin123

# Or manually
export TOKEN=$(curl -s -X POST \
  'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=stratium-pap' \
  -d 'client_secret=stratium-pap-secret' \
  -d 'grant_type=password' \
  -d 'username=admin456' \
  -d 'password=admin123' | jq -r .access_token)

echo $TOKEN
```

### 1.4 Verify Database Tables Exist

```bash
docker exec -it stratium-postgres psql -U stratium -d stratium_pap -c "\dt"
```

Expected new tables: `agents`, `delegations` (in addition to existing `policies`, `entitlements`, `audit_logs`)

---

## 2. Test: Agent Registry (PAP REST API)

### 2.1 Register an Agent

```bash
# Register a Claude-based agent
curl -sk -X POST https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "claude-research-agent",
    "description": "Research assistant for document analysis",
    "provider": "anthropic",
    "model_identifier": "claude-sonnet-4-20250514",
    "trust_tier": 1,
    "allowed_tools": ["read_file", "search", "list_documents"],
    "allowed_actions": [0, 1],
    "tenant_id": "test-tenant",
    "metadata": {"purpose": "research", "version": "1.0"}
  }' | jq .

# Save the returned values — AGENT_ID is the UUID id field (e.g. "e0c21604-c830-477c-a0c4-784f737cba05")
# NOT the client_id field (e.g. "agent_e0c21604") — these are different fields
export AGENT_ID="<id UUID from response>"
export CLIENT_ID="<client_id from response>"
export CLIENT_SECRET="<client_secret from response>"
```

**Expected:** HTTP 201 with `agent_id`, `client_id`, and `client_secret` (shown only once).

**PASS criteria:**
- [ ] Returns 201 with valid UUID agent_id
- [ ] client_id starts with `agent_`
- [ ] client_secret is a 64-character hex string

### 2.2 Register a Second Agent (Higher Trust Tier)

```bash
curl -sk -X POST https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "codex-code-agent",
    "description": "Code generation and execution agent",
    "provider": "openai",
    "model_identifier": "codex",
    "trust_tier": 2,
    "allowed_tools": ["read_file", "write_file", "execute_code", "search"],
    "allowed_actions": [0, 1, 2],
    "tenant_id": "test-tenant"
  }' | jq .

export AGENT2_ID="<id UUID from response>"  # UUID, not client_id
```

### 2.3 List Agents

```bash
curl -sk "https://localhost:8090/api/v1/agents?tenant_id=test-tenant" \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**PASS criteria:**
- [ ] Returns both registered agents
- [ ] `total_count` is 2
- [ ] Trust tiers match what was registered

### 2.4 Get Agent by ID

```bash
curl -sk https://localhost:8090/api/v1/agents/$AGENT_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**PASS criteria:**
- [ ] Returns the correct agent
- [ ] `client_secret` is NOT included in the response (security)

### 2.5 Update Agent

```bash
curl -sk -X PUT https://localhost:8090/api/v1/agents/$AGENT_ID \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "trust_tier": 2,
    "allowed_tools": ["read_file", "search", "list_documents", "summarize"]
  }' | jq .
```

**PASS criteria:**
- [ ] Returns 200 with updated trust_tier = 2
- [ ] allowed_tools includes new tool "summarize"

### 2.6 Suspend Agent

```bash
curl -sk -X POST https://localhost:8090/api/v1/agents/$AGENT2_ID/suspend \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "testing suspension flow"}' | jq .
```

**PASS criteria:**
- [ ] Returns `success: true`
- [ ] Agent's cert_status becomes "SUSPENDED"
- [ ] Agent's enabled becomes false

### 2.7 Reinstate Agent

```bash
curl -sk -X POST https://localhost:8090/api/v1/agents/$AGENT2_ID/reinstate \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**PASS criteria:**
- [ ] Returns `success: true`
- [ ] Verify agent is re-enabled: `curl ... /agents/$AGENT2_ID | jq .enabled`

### 2.8 Feature Flag Guard — Disabled

Stop the services, remove the `agent-auth` feature flag, and verify endpoints return 501:

```bash
# Without agent-auth enabled, the endpoints should return 501
curl -sk -X GET https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**PASS criteria:**
- [ ] Returns HTTP 501 with `"error": "agent authorization is not enabled"`

### 2.9 Delete Agent

```bash
curl -sk -X DELETE https://localhost:8090/api/v1/agents/$AGENT2_ID \
  -H "Authorization: Bearer $TOKEN" | jq .
```

**PASS criteria:**
- [ ] Returns `deleted: true`
- [ ] Subsequent GET returns 404

---

## 3. Test: Audit Logging

```bash
curl -sk "https://localhost:8090/api/v1/audit-logs?entity_type=agent" \
  -H "Authorization: Bearer $TOKEN" | jq '.audit_logs[] | {action, entity_type, actor}'
```

> **Note:** If this returns an empty array, the `audit_logs` table's CHECK constraint
> may not include `agent`. Fix with:
> ```bash
> docker exec -i stratium-postgres psql -U keycloak -d stratium_pap -c \
>   "ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_entity_type_check;
>    ALTER TABLE audit_logs ADD CONSTRAINT audit_logs_entity_type_check
>    CHECK (entity_type IN ('policy', 'entitlement', 'agent', 'delegation'));"
> ```

**PASS criteria:**
- [ ] Audit entries exist for create, update, suspend, reinstate, delete actions
- [ ] Each entry has correct actor (admin456)
- [ ] Each entry has entity_type "agent"

---

## 4. Test: Database Schema Verification

```bash
# Connect to postgres
docker exec -it stratium-postgres psql -U stratium -d stratium_pap

# Verify agents table schema
\d agents

# Verify delegations table schema
\d delegations

# Verify audit_logs has new agent columns
\d audit_logs

# Check indexes
\di

# Check for the seeded agent-auth OPA policy
SELECT name, description FROM policies WHERE name = 'agent-compound-authorization';

# Exit
\q
```

**PASS criteria:**
- [ ] `agents` table has all expected columns (id, name, trust_tier, allowed_tools, client_id, etc.)
- [ ] `delegations` table has chain fields (parent_delegation_id, root_delegation_id, depth, chain_agent_ids)
- [ ] `audit_logs` has new columns (agent_id, delegation_id, chain_depth, etc.)
- [ ] OPA policy `agent-compound-authorization` is seeded
- [ ] All indexes exist (idx_agents_tenant, idx_delegations_root, etc.)

---

## 5. Test: Delegation Token Flow (gRPC)

These tests exercise the Agent Gateway gRPC service directly.

### 5.1 Create a Root Delegation

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -H "x-user-id: admin456" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "approved_tools": ["read_file", "search"],
    "approved_actions": [0, 1],
    "max_action_tier": 1,
    "classification_caps": {"nato": "CONFIDENTIAL", "commercial": "INTERNAL"},
    "purpose": "Document research session",
    "ttl_seconds": 900,
    "conversation_id": "test-session-001"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/CreateDelegation
```

**PASS criteria:**
- [ ] Returns a delegation_token (JWT string)
- [ ] delegation_id is a valid UUID
- [ ] depth = 0 (root)
- [ ] root_delegation_id == delegation_id
- [ ] expires_at is ~15 minutes from now

```bash
export DELEGATION_TOKEN="<delegation_token from response>"
export DELEGATION_ID="<delegation_id from response>"
```

### 5.2 Decode the Delegation Token

```bash
# Decode JWT payload (second segment)
# JWT uses base64url (no padding, - and _ instead of + and /); fix before decoding
echo $DELEGATION_TOKEN | cut -d. -f2 | tr '_-' '/+' | \
  awk '{l=length($0)%4; if(l==2)$0=$0"=="; else if(l==3)$0=$0"="; print}' | \
  base64 -d | jq .
```

**PASS criteria:**
- [ ] `sub` matches the authenticated user (admin456's user ID)
- [ ] `agent_id` matches the registered agent
- [ ] `approved_tools` contains ["read_file", "search"]
- [ ] `max_action_tier` is 1
- [ ] `classification_caps` has nato: CONFIDENTIAL, commercial: INTERNAL
- [ ] `depth` is 0
- [ ] `chain_agent_ids` contains just the one agent

### 5.3 Inspect the Delegation Chain

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{"delegation_id": "'$DELEGATION_ID'"}' \
  localhost:50054 agent_gateway.AgentGatewayService/GetDelegationChain
```

**PASS criteria:**
- [ ] Returns a chain with 1 link
- [ ] Chain[0] matches the delegation we created
- [ ] total_depth = 1

### 5.4 Execute an Action (Authorized)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_token": "'$DELEGATION_TOKEN'",
    "target_service": "platform",
    "method": "GetDecision",
    "action": "read",
    "action_tier": 1,
    "tool_name": "read_file",
    "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ExecuteAction
```

**PASS criteria:**
- [ ] `authorized: true`
- [ ] Decision chain_decisions show ALLOW for agent and delegation

### 5.5 Execute an Action (Denied — Tool Not Allowed)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_token": "'$DELEGATION_TOKEN'",
    "target_service": "platform",
    "method": "GetDecision",
    "action": "write",
    "action_tier": 2,
    "tool_name": "write_file",
    "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ExecuteAction
```

**PASS criteria:**
- [ ] `authorized: false`
- [ ] Error mentions "tool not in" agent or delegation scope
- [ ] Decision shows DENY at the correct hop

### 5.6 Execute an Action (Denied — Action Tier Too High)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_token": "'$DELEGATION_TOKEN'",
    "target_service": "platform",
    "method": "Execute",
    "action": "delete",
    "action_tier": 4,
    "tool_name": "read_file",
    "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ExecuteAction
```

**PASS criteria:**
- [ ] `authorized: false`
- [ ] Error mentions "action tier exceeds"

---

## 6. Test: Delegation Chain (Subagent Delegation)

### 6.1 Register a Subagent

```bash
curl -sk -X POST https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "summarizer-subagent",
    "description": "Summarizes documents found by the research agent",
    "provider": "anthropic",
    "model_identifier": "claude-haiku-4-5-20251001",
    "trust_tier": 0,
    "allowed_tools": ["read_file"],
    "allowed_actions": [0, 1],
    "tenant_id": "test-tenant"
  }' | jq .

export SUBAGENT_ID="<id UUID from response>"  # UUID, not client_id
```

### 6.2 Create a Child Delegation (Agent A Delegates to Agent B)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -H "x-user-id: admin456" \
  -d '{
    "agent_id": "'$SUBAGENT_ID'",
    "approved_tools": ["read_file"],
    "approved_actions": [0, 1],
    "max_action_tier": 1,
    "classification_caps": {"nato": "RESTRICTED", "commercial": "INTERNAL"},
    "purpose": "Summarize NATO restricted documents",
    "ttl_seconds": 300,
    "conversation_id": "test-session-001",
    "parent_delegation_token": "'$DELEGATION_TOKEN'"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/CreateDelegation
```

**PASS criteria:**
- [ ] Returns a new delegation_token
- [ ] depth = 1
- [ ] root_delegation_id matches the original root
- [ ] expires_at <= parent's expires_at
- [ ] Classification cap narrowed (RESTRICTED <= CONFIDENTIAL)

```bash
export CHILD_TOKEN="<child delegation_token>"
export CHILD_DELEGATION_ID="<child delegation_id>"
```

### 6.3 Inspect the Full Chain

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{"delegation_id": "'$CHILD_DELEGATION_ID'"}' \
  localhost:50054 agent_gateway.AgentGatewayService/GetDelegationChain
```

**PASS criteria:**
- [ ] Chain has 2 links
- [ ] Chain[0] is the root agent (claude-research-agent)
- [ ] Chain[1] is the child agent (summarizer-subagent)
- [ ] Classification caps narrow from root to child
- [ ] total_depth = 2

### 6.4 Child Delegation — Scope Widening Rejected

```bash
# Try to create a child with MORE tools than parent
grpcurl -cacert config/examples/certs/ca.crt \
  -H "x-user-id: admin456" \
  -d '{
    "agent_id": "'$SUBAGENT_ID'",
    "approved_tools": ["read_file", "write_file", "send_email"],
    "approved_actions": [0, 1, 2, 3],
    "max_action_tier": 4,
    "classification_caps": {"nato": "SECRET"},
    "purpose": "Attempt to escalate privileges",
    "ttl_seconds": 300,
    "parent_delegation_token": "'$DELEGATION_TOKEN'"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/CreateDelegation
```

**PASS criteria (CRITICAL SECURITY TEST):**
- [ ] Request FAILS with "child delegation scope exceeds parent"
- [ ] Error names the first violated scope (e.g., "child max_action_tier exceeds parent")
- [ ] No delegation token is returned
- [ ] gRPC code is `Internal` (server's current behavior for scope violations)

### 6.5 Max Depth Exceeded

Create delegations to depth 5 (the default max), then try to create one more:

**PASS criteria:**
- [ ] Depth 5 delegation fails with "delegation chain exceeds maximum depth"

---

## 7. Test: Revocation and Cascade

### 7.1 Revoke Root Delegation

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_id": "'$DELEGATION_ID'",
    "reason": "testing cascade revocation"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/RevokeDelegation
```

**PASS criteria:**
- [ ] `success: true`
- [ ] `revoked_count` includes the root AND the child (cascade)
- [ ] Both delegation IDs appear in `revoked_delegation_ids`

### 7.2 Verify Revoked Tokens Are Rejected

```bash
# Try to use the revoked root token
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_token": "'$DELEGATION_TOKEN'",
    "action": "read",
    "action_tier": 1,
    "tool_name": "read_file"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ExecuteAction
```

**PASS criteria:**
- [ ] `authorized: false`
- [ ] Error mentions "revoked" or "inactive"

### 7.3 Verify Cascade — Child Token Also Rejected

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_token": "'$CHILD_TOKEN'",
    "action": "read",
    "action_tier": 1,
    "tool_name": "read_file"
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ExecuteAction
```

**PASS criteria:**
- [ ] `authorized: false`
- [ ] Error mentions "revoked"

---

## 8. Test: Action Plan Validation (Anti-Spoofing)

### 8.1 Validate a Correct Action Plan

```bash
# First create a fresh delegation
# ... (repeat step 5.1) ...

grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_id": "'$DELEGATION_ID'",
    "actions": [
      {
        "tool_name": "read_file",
        "action": "read",
        "declared_tier": 1,
        "resource": {"type": "document"}
      },
      {
        "tool_name": "search",
        "action": "query",
        "declared_tier": 1,
        "resource": {"type": "index"}
      }
    ]
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ValidateActionPlan
```

**PASS criteria:**
- [ ] `valid: true`
- [ ] All results show valid: true

### 8.2 Validate a Spoofed Action Plan (Tier Mismatch)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "delegation_id": "'$DELEGATION_ID'",
    "actions": [
      {
        "tool_name": "read_file",
        "action": "delete",
        "declared_tier": 1,
        "resource": {"type": "document"}
      }
    ]
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/ValidateActionPlan
```

**PASS criteria:**
- [ ] `valid: false`
- [ ] Result shows `tier_mismatch: true`
- [ ] `actual_tier` is 4 (destructive), not 1 (read-only)
- [ ] Reason explains the agent declared the wrong tier

---

## 9. Test: Compound Policy Evaluation (Platform Service)

### 9.1 GetDecision with Agent Attributes (Single Agent)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "subject_attributes": {
      "role": {"string_value": "admin"},
      "clearance": {"string_value": "SECRET"}
    },
    "resource_attributes": {
      "classification": "CONFIDENTIAL",
      "hierarchy": "nato"
    },
    "action": "read",
    "agent_attributes": {
      "agent_id": "'$AGENT_ID'",
      "agent_name": "claude-research-agent",
      "trust_tier": 1,
      "allowed_tools": ["read_file", "search"]
    },
    "delegation_context": {
      "delegation_id": "'$DELEGATION_ID'",
      "user_id": "admin456",
      "agent_id": "'$AGENT_ID'",
      "action_tier": 1,
      "tool_name": "read_file",
      "classification_caps": {"nato": "CONFIDENTIAL"}
    }
  }' \
  localhost:50051 platform.PlatformService/GetDecision
```

**PASS criteria:**
- [ ] Top-level decision is ALLOW
- [ ] compound_decision is populated
- [ ] compound_decision.user_decision = ALLOW
- [ ] compound_decision.agent_decision = ALLOW
- [ ] compound_decision.delegation_decision = ALLOW
- [ ] denied_at_depth = -1

### 9.2 GetDecision — Agent DENY (Trust Tier Too Low)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "subject_attributes": {
      "role": {"string_value": "admin"},
      "clearance": {"string_value": "SECRET"}
    },
    "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"},
    "action": "delete",
    "agent_attributes": {
      "agent_id": "'$AGENT_ID'",
      "trust_tier": 0,
      "allowed_tools": ["delete_resource"]
    },
    "delegation_context": {
      "delegation_id": "'$DELEGATION_ID'",
      "user_id": "admin456",
      "agent_id": "'$AGENT_ID'",
      "action_tier": 4,
      "tool_name": "delete_resource"
    }
  }' \
  localhost:50051 platform.PlatformService/GetDecision
```

**PASS criteria:**
- [ ] Top-level decision is DENY
- [ ] compound_decision.agent_decision = DENY
- [ ] Reason mentions "trust tier insufficient"
- [ ] denied_principal starts with "agent:"

### 9.3 GetDecision Without Agent Attributes (Backward Compatibility)

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -d '{
    "subject_attributes": {
      "role": {"string_value": "admin"}
    },
    "resource_attributes": {"type": "document"},
    "action": "read"
  }' \
  localhost:50051 platform.PlatformService/GetDecision
```

**PASS criteria:**
- [ ] Returns a normal decision (ALLOW or DENY based on existing policies)
- [ ] compound_decision is empty/null (no agent attributes provided)
- [ ] Zero behavioral change from pre-agent-auth behavior

---

## 10. End-to-End Test with AI Agents

### 10.1 Claude Code Integration Test

Using Claude Code locally, simulate an agent-initiated workflow:

1. **Register Claude Code as an agent** (step 2.1)
2. **Create a delegation** scoped to read-only, CONFIDENTIAL classification
3. **Have Claude Code attempt to read a document** — should succeed
4. **Have Claude Code attempt to write** — should be denied by delegation scope
5. **Revoke the delegation mid-session** — subsequent calls should fail

### 10.2 OpenAI Codex Integration Test

1. **Register Codex as a Tier 2 agent** with write permissions
2. **Create a delegation** with internal-modify action tier
3. **Have Codex execute a code generation task** (write action)
4. **Verify the action is authorized** through the gateway
5. **Create a subagent delegation** from Codex to a summarizer
6. **Verify scope narrowing** — the summarizer can only read

### 10.3 Multi-Agent Chain Test

```
User (SECRET clearance)
  └─► Claude Code (orchestrator, Tier 2, depth 0)
        └─► Codex (code generator, Tier 1, depth 1)
              └─► Summarizer (Tier 0, depth 2)
```

1. Register all 3 agents at different trust tiers
2. Create root delegation from user → Claude Code
3. Claude Code creates child delegation → Codex (narrower scope)
4. Codex creates child delegation → Summarizer (even narrower)
5. Summarizer executes a read action — should succeed
6. Summarizer attempts a write action — should be denied
7. Revoke the Codex delegation — Summarizer's delegation should cascade-revoke
8. Verify Claude Code's delegation is still active

---

## 11. Negative / Security Tests

| # | Test | Expected Result |
|---|------|-----------------|
| S1 | Tampered JWT (modify claims, keep signature) | DENY — signature validation fails |
| S2 | Expired delegation token | DENY — "delegation expired" |
| S3 | Use delegation token after agent is suspended | DENY — agent disabled |
| S4 | Cross-tenant agent access | DENY — tenant mismatch |
| S5 | Forge a delegation_id that doesn't exist in DB | DENY — delegation not found |
| S6 | Replay a revoked token | DENY — delegation revoked |
| S7 | Create child with tool not in parent scope | DENY — "tool not in parent approved_tools" |
| S8 | Create child with higher action tier than parent | DENY — "child max_action_tier exceeds parent" |
| S9 | Create child with classification cap exceeding parent | DENY — "child scope exceeds parent" |
| S10 | Create delegation at depth 6 (default max 5) | DENY — "exceeds maximum depth" |
| S11 | Privilege amplification: user DENY + agent ALLOW | Overall DENY — blocks proxy abuse |

---

## 12. Cleanup

```bash
# Stop all services
cd deployment/docker
docker-compose --profile agent-auth down

# Remove volumes (fresh start)
docker-compose --profile agent-auth down -v
```

---

## Test Accounts

| Username | Password | Role | Classification | Use For |
|----------|----------|------|----------------|---------|
| admin456 | admin123 | admin | top-secret | Agent registration, full access |
| user123 | password123 | user | confidential | Standard delegation testing |
| test-user | test123 | tester | secret | Classification cap testing |
| service-account-1 | service123 | service | unclassified | Minimal access testing |

---

## Troubleshooting

**Agent Gateway not starting:**
```bash
docker-compose --profile agent-auth logs agent-gateway
# Common: missing agent-auth feature flag in build
```

**gRPC connection refused on 50054:**
- Verify the agent-gateway container is running
- Check if the `agent-auth` profile was included in the up command

**PAP returns 404 on `/api/v1/agents`:**
- The PAP needs both the build flag AND the runtime config:
  1. `BUILD_FEATURES: "agent-auth"` in docker-compose PAP build args (or uncomment if commented out)
  2. `STRATIUM_AGENT_GATEWAY_ENABLED=true` as PAP environment variable
- After changing build args, rebuild: `docker-compose build pap && docker-compose up -d pap`

**PAP returns 501 "agent authorization is not enabled":**
- The build flag is present but `STRATIUM_AGENT_GATEWAY_ENABLED=true` env var is missing

**Database tables missing:**
- On a fresh volume, the init scripts run automatically. On an existing volume, run the migration manually:
  ```bash
  docker exec -i stratium-postgres psql -U keycloak -d stratium_pap < deployment/postgres/04-init-agent-auth.sql
  ```
- Verify tables exist: `docker exec stratium-postgres psql -U stratium -d stratium_pap -c "\dt"`
- Note: DDL requires the `keycloak` superuser; the `stratium` user has DML-only access

**Token validation fails:**
- Verify the signing key is consistent (ephemeral keys change on restart)
- For production testing, set `STRATIUM_AGENT_GATEWAY_DELEGATION_SIGNING_KEY`
