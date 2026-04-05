# Manual Testing Guide: Stratium MCP Server

**Feature:** Claude MCP Integration for Agent Authorization
**Binaries:** `stratium-mcp`, `stratium-audit`
**Date:** 2026-04-05

---

## Prerequisites

- Docker and Docker Compose installed
- `jq` installed (`brew install jq`)
- `grpcurl` installed (`brew install grpcurl`)
- Go 1.25+ (to build the binaries)
- Claude Code CLI installed (for interactive MCP testing)
- Claude Desktop app (optional, for GUI-based testing)
- Python 3.10+ with `anthropic` package (optional, for sub-agent testing)

### Connectivity Notes

| Protocol | Service | Port | Tool | Flags Needed |
|----------|---------|------|------|-------------|
| **gRPC+TLS** | Agent Gateway | 50054 | `grpcurl` | `-cacert config/examples/certs/ca.crt` |
| **HTTPS** | PAP | 8090 | `curl` | `-sk` (self-signed cert) |
| **HTTP** | Keycloak | 8080 | `curl` | `-s` (plain HTTP) |

The MCP server communicates with Claude over **stdio** (stdin/stdout JSON-RPC). It connects to the Agent Gateway over gRPC and Keycloak over HTTP.

---

## 1. Environment Setup

### 1.1 Start All Services

```bash
cd deployment/docker
docker-compose --profile agent-auth up -d
docker-compose --profile agent-auth ps
```

Expected services:

| Service | Port | Status |
|---------|------|--------|
| postgres | 5432 | healthy |
| keycloak | 8080 | healthy |
| platform | 50051 | running |
| key-manager | 50052 | running |
| key-access | 50053 | running |
| pap | 8090 | healthy |
| agent-gateway | 50054 | running |

### 1.2 Verify Services Are Reachable

```bash
# Keycloak
curl -s http://localhost:8080/realms/stratium | jq .realm
# Expected: "stratium"

# PAP
curl -sk https://localhost:8090/health | jq .status
# Expected: "healthy"

# Agent Gateway (gRPC reflection)
grpcurl -cacert config/examples/certs/ca.crt localhost:50054 list
# Expected: agent_gateway.AgentGatewayService
```

### 1.3 Build the MCP Server and Audit CLI

```bash
make build-mcp build-audit
```

**PASS criteria:**
- [ ] `bin/stratium-mcp` exists and is executable
- [ ] `bin/stratium-audit` exists and is executable

### 1.4 Seed Demo Data

```bash
./demos/mcp/seed-demo-data.sh
```

**PASS criteria:**
- [ ] Script completes without errors
- [ ] Demo users created (or "already exists")
- [ ] OIDC client `stratium-mcp` created (or "already exists")
- [ ] Classification policies created (or HTTP 500 if already seeded)

### 1.5 Test Accounts

| User | Password | Client ID | Client Secret | Purpose |
|------|----------|-----------|---------------|---------|
| `admin456` | `admin123` | `stratium-pap` | `stratium-pap-secret` | Admin operations |
| `demo-analyst` | `demo123` | `stratium-mcp` | (public client) | INTERNAL clearance demo |
| `demo-director` | `demo123` | `stratium-mcp` | (public client) | CONFIDENTIAL clearance demo |
| `demo-admin` | `demo123` | `stratium-mcp` | (public client) | RESTRICTED clearance demo |

---

## 2. Test: MCP Protocol (stdio)

These tests verify the MCP JSON-RPC protocol works correctly without any backend dependencies.

### 2.1 Initialize Handshake

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] Returns valid JSON-RPC response with `id: 1`
- [ ] `result.protocolVersion` is `"2024-11-05"`
- [ ] `result.serverInfo.name` is `"stratium-mcp"`
- [ ] `result.capabilities.tools` is present

### 2.2 List Tools

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}\n{"jsonrpc":"2.0","method":"tools/list","id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq '.result.tools | length'
```

**PASS criteria:**
- [ ] Returns `13` (total tool count)

### 2.3 Verify All Tool Names

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}\n{"jsonrpc":"2.0","method":"tools/list","id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.tools[].name' | sort
```

Expected tool names:
```
check_permission
create_delegation
create_sub_delegation
execute_action
get_agent
get_delegation_chain
list_agents
list_delegations
orchestrate_sub_agent
register_agent
revoke_delegation
suspend_agent
validate_action_plan
```

**PASS criteria:**
- [ ] All 13 tools listed
- [ ] Each tool has `name`, `description`, and `inputSchema`

### 2.4 Unknown Method Returns Error

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"nonexistent/method","id":99}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq .
```

**PASS criteria:**
- [ ] Response has `error.code` of `-32601` (method not found)

### 2.5 Unknown Tool Returns Error

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"nonexistent_tool","arguments":{}},"id":99}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq .
```

**PASS criteria:**
- [ ] Response has `error.code` of `-32601`
- [ ] Error message mentions "unknown tool"

---

## 3. Test: OIDC Authentication

### 3.1 Token Cache (Manual Pre-seed)

The MCP server normally opens a browser for OIDC login. For testing, pre-seed a token:

```bash
# Get a token via password grant
export TOKEN=$(curl -s -X POST \
  'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -d 'client_id=stratium-mcp' \
  -d 'grant_type=password' \
  -d 'username=admin456' \
  -d 'password=admin123' | jq -r .access_token)

export EXPIRES_AT=$(date -v+1H +%s 2>/dev/null || date -d '+1 hour' +%s)

# Pre-seed the token cache
mkdir -p ~/.stratium
cat > ~/.stratium/token.json << EOF
{
  "access_token": "$TOKEN",
  "refresh_token": "",
  "token_type": "Bearer",
  "expires_in": 3600,
  "expires_at": $EXPIRES_AT,
  "user_id": "admin456"
}
EOF

echo "Token cached at ~/.stratium/token.json"
```

> **Note:** This bypasses the browser-based OIDC flow. The MCP server will use this cached token for all gRPC calls to the Agent Gateway.

**PASS criteria:**
- [ ] `~/.stratium/token.json` exists with a valid access_token
- [ ] Token is not expired (check `expires_at` > current unix timestamp)

### 3.2 Verify Token Works Against Agent Gateway

```bash
grpcurl -cacert config/examples/certs/ca.crt \
  -H "authorization: Bearer $TOKEN" \
  -H "x-user-id: admin456" \
  -d '{}' \
  localhost:50054 agent_gateway.AgentGatewayService/ListAgents
```

**PASS criteria:**
- [ ] Returns a valid response (may be empty `agents` list)
- [ ] No `UNAUTHENTICATED` or `PERMISSION_DENIED` error

---

## 4. Test: Agent Registration (via MCP)

### 4.1 Register Agent

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"test-mcp-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files"]}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] Response contains `agent_id` (UUID format)
- [ ] Response contains `client_id`
- [ ] Response contains `created_at` timestamp
- [ ] `message` confirms successful registration

```bash
# Save the agent_id for later tests
export AGENT_ID="<agent_id from response>"
```

### 4.2 Get Agent Details

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_agent","arguments":{"agent_id":"'"$AGENT_ID"'"}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] Returns agent with matching `agent_id`
- [ ] `trust_tier` is `1`
- [ ] `allowed_tools` includes `read_file` and `list_files`
- [ ] `enabled` is `true`

### 4.3 List Agents

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"list_agents","arguments":{}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `total` >= 1
- [ ] At least one agent in `agents` array
- [ ] Previously registered agent appears in the list

---

## 5. Test: Delegation Lifecycle (via MCP)

### 5.1 Create Root Delegation

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"delegation-test-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files","search"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"testing delegation lifecycle","ttl_seconds":300}},"id":3}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] Returns `delegation_id` (UUID)
- [ ] `expires_at` is ~5 minutes from now
- [ ] `depth` is `0` (root delegation)
- [ ] `scope.approved_tools` matches `["read_file","list_files"]`
- [ ] `scope.max_action_tier` is `1`
- [ ] `scope.classification_cap` is `"INTERNAL"`
- [ ] `instructions` field is present (enforcement instructions for Claude)
- [ ] `delegation_token` is NOT in the response (cached internally by MCP server)
- [ ] File `~/.stratium/delegation.json` is created with `delegation_id` and `delegation_token`

```bash
export DELEGATION_ID="<delegation_id from response>"

# Verify delegation was persisted for the PreToolUse hook
cat ~/.stratium/delegation.json | jq .delegation_id
```

### 5.2 Revoke Delegation

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"revoke_delegation","arguments":{"delegation_id":"'"$DELEGATION_ID"'","reason":"testing revocation"}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `revoked` is `true`
- [ ] `revoked_count` >= 1
- [ ] `reason` matches "testing revocation"

---

## 6. Test: Authorization Decisions (via MCP)

This is the core demo flow. We create a delegation and test allow/deny decisions.

### 6.1 Setup: Register Agent and Create Delegation

```bash
# This sends 3 sequential MCP calls: init, register, delegate
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"authz-test-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files","write_file"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"authorization testing","ttl_seconds":120}},"id":3}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null
```

> **Note:** The MCP server maintains session state — the agent_id and delegation_token from calls 2 and 3 are cached for subsequent calls in the same session. Since each `printf` pipe creates a new process, you'll need to combine all calls in a single pipe for stateful tests.

### 6.2 Positive Path: Allowed Action (READ_ONLY tool in scope)

Add `execute_action` to the pipe from 6.1:

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"authz-pos-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files","write_file"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"positive path test","ttl_seconds":120}},"id":3}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_action","arguments":{"tool_name":"read_file","action":"read","action_tier":1,"resource_classification":"PUBLIC"}},"id":4}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `authorized` is `true`
- [ ] `message` starts with `"ALLOWED"`
- [ ] Response contains `tool`, `action`, `tier` fields
- [ ] No `reason` field (only present on denials)

### 6.3 Negative Path: Denied — Tool Not in Scope

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"authz-neg-tool-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files","write_file"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"negative tool test","ttl_seconds":120}},"id":3}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_action","arguments":{"tool_name":"write_file","action":"write","action_tier":2}},"id":4}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `authorized` is `false`
- [ ] `message` starts with `"DENIED"`
- [ ] `reason` field present with denial explanation

### 6.4 Negative Path: Denied — Action Tier Exceeds Max

```bash
# Same setup but try action_tier 2 (INTERNAL_MODIFY) with max_action_tier 1 (READ_ONLY)
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"authz-neg-tier-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"tier violation test","ttl_seconds":120}},"id":3}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_action","arguments":{"tool_name":"read_file","action":"read","action_tier":2}},"id":4}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `authorized` is `false`
- [ ] `message` starts with `"DENIED"`
- [ ] `reason` field present with denial explanation

### 6.5 Classification Enforcement (Architectural Note)

> **Important:** Classification-based access control (e.g., CONFIDENTIAL resource vs. INTERNAL clearance) is enforced by the **Platform policy engine** (OPA/Cedar), not the Agent Gateway. The Gateway enforces delegation scope (tools, action tiers, chain validity). Classification checks fire when `ExecuteAction` proxies a real request to a target service (Platform, Key Manager, KAS), which triggers a full ABAC policy evaluation.
>
> In the demo, `execute_action` calls that don't target a real service will pass the Gateway's delegation scope check but won't hit the Platform policy engine. This is by design — the Gateway is a delegation enforcer, not a replacement for the policy engine.
>
> During the interactive Claude demo (Section 11), classification enforcement is demonstrated through the narrative and the policy engine's evaluation path.

To verify classification attributes are flowing into tokens correctly:

```bash
# Get a token as demo-analyst and inspect claims
ANALYST_TOKEN=$(curl -sf http://localhost:8080/realms/stratium/protocol/openid-connect/token \
  -d grant_type=password -d client_id=stratium-mcp \
  -d username=demo-analyst -d password=demo123 | jq -r .access_token)

echo "$ANALYST_TOKEN" | python3 -c "
import sys, json, base64
t = sys.stdin.read().strip().split('.')[1]
t += '=' * (4 - len(t) % 4)
c = json.loads(base64.urlsafe_b64decode(t))
print(json.dumps({k: c.get(k) for k in ['preferred_username','classification','department','role']}, indent=2))
"
```

**PASS criteria:**
- [ ] `classification` is `"internal"` for demo-analyst
- [ ] `classification` is `"confidential"` for demo-director
- [ ] `classification` is `"restricted"` for demo-admin

---

## 7. Test: Validate Action Plan (via MCP)

### 7.1 Batch Validation — Mixed Allow/Deny

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"plan-test-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"classification_cap":"INTERNAL","purpose":"plan validation test","ttl_seconds":120}},"id":3}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"validate_action_plan","arguments":{"actions":[{"tool_name":"read_file","action":"read","action_tier":1,"resource_classification":"PUBLIC"},{"tool_name":"read_file","action":"read","action_tier":1,"resource_classification":"CONFIDENTIAL"},{"tool_name":"write_file","action":"write","action_tier":2}]}},"id":4}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `valid` is `false` (because at least one action is invalid)
- [ ] `results` array has 3 entries
- [ ] First action (`read_file` PUBLIC) — `valid: true`
- [ ] Second action (`read_file` CONFIDENTIAL) — `valid: true` (classification is not checked at the Gateway level; see section 6.5 architectural note)
- [ ] Third action (`write_file`) — `valid: false`, reason mentions `"tool \"write_file\" not in agent allowed_tools"`
- [ ] `message` reads `"Validated 3 actions: 2 valid, 1 invalid"`

---

## 8. Test: Delegation Chain Inspection

### 8.1 Get Delegation Chain

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"chain-test-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file"],"max_action_tier":1,"purpose":"chain inspection test","ttl_seconds":120}},"id":3}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_delegation_chain","arguments":{}},"id":4}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `chain_depth` is `1`
- [ ] `chain[0].depth` is `0`
- [ ] `chain[0].agent_name` is `"chain-test-agent"`
- [ ] `chain[0].trust_tier` is `1`
- [ ] `chain[0].approved_tools` includes `"read_file"`

---

## 9. Test: Agent Suspension

### 9.1 Suspend Agent

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"suspend-test-agent","provider":"anthropic","trust_tier":1}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file"],"max_action_tier":1,"purpose":"suspension test","ttl_seconds":120}},"id":3}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

Save the `agent_id`, then suspend:

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"suspend_agent","arguments":{"agent_id":"'"$AGENT_ID"'","reason":"testing suspension flow"}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text' | jq .
```

**PASS criteria:**
- [ ] `suspended` is `true`
- [ ] `revoked_delegations` >= 1
- [ ] `message` confirms agent was suspended

---

## 10. Test: Audit Trail

### Audit Architecture

There are two audit sources in the current implementation:

| Source | What it logs | How to query |
|--------|-------------|-------------|
| **Agent Gateway (stdout)** | Agent registrations, delegation create/revoke, authorization decisions (allow/deny) | `docker logs stratium-agent-gateway` |
| **PAP (database)** | Policy and entitlement CRUD events | `stratium-audit` CLI or PAP REST API |

For the demo, the **Agent Gateway logs** are the primary audit trail for authorization decisions. Database-backed agent authorization audit is a future enhancement.

### 10.1 Agent Gateway Logs — Authorization Decisions

Run the MCP tests in sections 4–9 first to generate events, then:

```bash
docker logs stratium-agent-gateway --tail 20
```

**PASS criteria:**
- [ ] Shows `Registered agent <uuid>` entries for each `register_agent` call
- [ ] Shows `Created delegation <uuid>` entries with user, agent, depth, TTL
- [ ] Shows `Action authorized` or `Action denied` entries with user, tool, action
- [ ] Shows `Suspended agent <uuid>` entries with reason and revoked delegation count

Example expected output:
```
INFO: 2026/04/05 17:28:15 Registered agent e3bc8051-... (name=authz-pos-agent, provider=anthropic, trust_tier=registered)
INFO: 2026/04/05 17:28:15 Created delegation 4cdb0376-... for user=admin456 agent=e3bc8051-... depth=0 ttl=2m0s
INFO: 2026/04/05 17:28:15 Action authorized: user=admin456 chain_depth=1 tool=read_file action=read
INFO: 2026/04/05 17:28:15 Action denied: user=admin456 chain_depth=1 tool=write_file action=write reason="denied at depth 0"
INFO: 2026/04/05 17:30:00 Suspended agent e3bc8051-... (reason: testing suspension flow, revoked delegations: 1)
```

### 10.2 Agent Gateway Logs — Follow Mode (for live demo)

During the interactive demo, open a second terminal:

```bash
docker logs -f stratium-agent-gateway
```

This shows authorization decisions in real time as Claude uses tools.

### 10.3 PAP Audit CLI — Help Output

```bash
./bin/stratium-audit --help
```

**PASS criteria:**
- [ ] Shows `logs`, `chain`, `agent-summary`, `export` subcommands
- [ ] `--pap-url`, `--token`, `--format`, `--insecure` flags documented

### 10.4 PAP Audit CLI — Query Policy Events

```bash
export TOKEN=$(curl -s -X POST \
  'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -d 'client_id=stratium-pap' \
  -d 'client_secret=stratium-pap-secret' \
  -d 'grant_type=password' \
  -d 'username=admin456' \
  -d 'password=admin123' | jq -r .access_token)

./bin/stratium-audit logs --token "$TOKEN" --limit 5 --format json
```

> **Note:** The `stratium-audit` CLI queries the PAP's `audit_logs` table, which contains policy/entitlement CRUD events — not agent authorization decisions. Agent authorization events are in the Agent Gateway stdout logs (section 10.1).

**PASS criteria:**
- [ ] Command executes without TLS errors
- [ ] Returns JSON array of PAP audit entries
- [ ] Entries contain `actor`, `action`, `entity_type`, `timestamp` fields

### 10.5 PAP Audit CLI — Table Format

```bash
./bin/stratium-audit logs --token "$TOKEN" --limit 5
```

**PASS criteria:**
- [ ] Prints formatted table with column headers
- [ ] Columns are aligned

---

## 11. Test: PreToolUse Hook (Claude Code Hard Enforcement)

The PreToolUse hook provides system-level enforcement in Claude Code. It reads the delegation state persisted by the MCP server and checks with the Agent Gateway before every tool call.

> **Note:** This hook only works in Claude Code (CLI), not Claude Desktop. Claude Desktop relies on CLAUDE.md instructions and tool descriptions for enforcement.

### 11.1 Prerequisites

```bash
# Verify hook is registered
cat ~/.claude/settings.json | jq '.hooks.PreToolUse'

# Verify hook script exists and is executable
ls -la demos/mcp/hooks/pre-tool-use.sh

# Verify grpcurl is installed (used by the hook)
which grpcurl
```

### 11.2 Create a Delegation (generates ~/.stratium/delegation.json)

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"register_agent","arguments":{"name":"hook-test-agent","provider":"anthropic","trust_tier":1,"allowed_tools":["read_file","list_files"]}},"id":2}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"create_delegation","arguments":{"approved_tools":["read_file","list_files"],"max_action_tier":1,"purpose":"hook test","ttl_seconds":300}},"id":3}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null > /dev/null

cat ~/.stratium/delegation.json | jq .delegation_id
```

**PASS criteria:**
- [ ] `~/.stratium/delegation.json` exists
- [ ] Contains `delegation_token` (JWT string)
- [ ] Contains `delegation_id` (UUID)

### 11.3 Hook: ALLOW — Read Tool (in scope)

```bash
echo '{"tool_name":"Read","tool_input":{"path":"/tmp/test.txt"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"
```

**PASS criteria:**
- [ ] No output (hook is silent on ALLOW)
- [ ] Exit code is `0`

### 11.4 Hook: ALLOW — Glob Tool (in scope as list_files)

```bash
echo '{"tool_name":"Glob","tool_input":{"pattern":"*.go"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"
```

**PASS criteria:**
- [ ] Exit code is `0`

### 11.5 Hook: DENY — Write Tool (not in scope)

```bash
echo '{"tool_name":"Write","tool_input":{"path":"/tmp/out.txt","content":"hello"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"
```

**PASS criteria:**
- [ ] Exit code is `2` (DENY)
- [ ] Output JSON contains `permissionDecision: "deny"`
- [ ] `permissionDecisionReason` mentions `write_file` and tier or scope

### 11.6 Hook: DENY — Bash Tool (tier 2 > max 1)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"npm install"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"
```

**PASS criteria:**
- [ ] Exit code is `2` (DENY)
- [ ] Reason mentions `bash` and tier

### 11.7 Hook: Skips MCP Tools (no recursion)

```bash
echo '{"tool_name":"register_agent","tool_input":{"name":"test"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"
```

**PASS criteria:**
- [ ] Exit code is `0` (stratium MCP tools are always allowed — avoids recursion)

### 11.8 Hook: No Delegation — Fails Open

```bash
# Temporarily remove delegation
mv ~/.stratium/delegation.json ~/.stratium/delegation.json.bak

echo '{"tool_name":"Read","tool_input":{"path":"/tmp/test.txt"}}' \
  | STRATIUM_GATEWAY_ADDRESS=localhost:50054 \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    demos/mcp/hooks/pre-tool-use.sh
echo "Exit: $?"

# Restore
mv ~/.stratium/delegation.json.bak ~/.stratium/delegation.json
```

**PASS criteria:**
- [ ] Exit code is `0` (fails open when no delegation exists)

### 11.9 Cleanup: Revoke Delegation

```bash
# Remove persisted delegation state
rm -f ~/.stratium/delegation.json
```

---

## 12. Test: Claude Code Integration (Interactive)

This section tests the full end-to-end flow inside Claude Code with both enforcement layers: the PreToolUse hook (hard block) and CLAUDE.md instructions (soft enforcement via MCP tools).

### 12.1 Prerequisites

```bash
# Verify MCP server is configured
cat ~/.claude/settings.json | jq .mcpServers.stratium.command
# Expected: "/Users/<you>/Development/stratium/bin/stratium-mcp"

# Verify PreToolUse hook is registered
cat ~/.claude/settings.json | jq '.hooks.PreToolUse'
# Expected: array with stratium hook entry

# Verify binary is built
ls -la bin/stratium-mcp

# Verify CLAUDE.md has agent authorization section
grep "Agent Authorization (MANDATORY)" CLAUDE.md
# Expected: match found

# Verify token is cached (from section 3.1)
cat ~/.stratium/token.json | jq .user_id
# Expected: "admin456"
```

### 12.2 Start Claude Code

```bash
cd /path/to/stratium
claude
```

Claude should start `stratium-mcp` automatically from `~/.claude/settings.json`.

### 12.3 Verify Tools Are Available

In the Claude Code session, type:

```
List all available stratium tools
```

**PASS criteria:**
- [ ] Claude lists the 13 stratium tools
- [ ] No error about MCP server failing to start

### 12.4 Demo Flow: Register + Delegate

In the Claude Code session:

```
Register a new agent called "demo-financial-analyst" with trust tier 1,
provider "anthropic", and allowed tools ["read_file", "list_files"].
Then create a delegation with those tools, max action tier 1 (READ_ONLY),
classification cap "INTERNAL", and a 2-minute TTL.
```

**PASS criteria:**
- [ ] Claude calls `register_agent` and reports the agent_id
- [ ] Claude calls `create_delegation` and reports delegation_id, expiry, scope
- [ ] Claude receives `instructions` field telling it to call `execute_action` before every action
- [ ] `~/.stratium/delegation.json` is created (for the PreToolUse hook)

### 12.5 Demo Flow: Soft Enforcement (MCP Tools)

```
Now try to execute_action for read_file with action "read", tier 1.
Then try execute_action for write_file with action "write", tier 2.
```

**PASS criteria:**
- [ ] First action (read_file, tier 1): `authorized: true`
- [ ] Second action (write_file, tier 2): `authorized: false` with denial reason

### 12.6 Demo Flow: Hard Enforcement (PreToolUse Hook)

```
Try to read the file demos/mcp/financial-records/public/annual-report-2025.txt
```

**PASS criteria:**
- [ ] PreToolUse hook fires (check gateway logs: `docker logs -f stratium-agent-gateway`)
- [ ] If `Read` maps to `read_file` (in scope): file is read successfully
- [ ] If Claude tries to write a file: hook returns exit 2 and Claude sees "Stratium authorization denied"

### 12.7 Demo Flow: Revocation

```
Revoke the current delegation with reason "demo complete".
```

**PASS criteria:**
- [ ] Claude calls `revoke_delegation`
- [ ] Reports `revoked: true` with count of revoked delegations
- [ ] `~/.stratium/delegation.json` is removed
- [ ] Subsequent tool calls fail open (no delegation to check against)

---

## 13. Test: Claude Desktop Integration (Optional)

> **Enforcement model:** Claude Desktop does not support PreToolUse hooks. Enforcement relies on three soft layers: (1) CLAUDE.md instructions loaded into the system prompt, (2) `execute_action` tool description marked MANDATORY, (3) `create_delegation` response includes behavioral instructions. Claude follows these reliably in practice.

### 13.1 Configure Claude Desktop

```bash
# macOS — merge into existing config or copy directly:
cp demos/mcp/claude_desktop_config.json \
   ~/Library/Application\ Support/Claude/claude_desktop_config.json

# Verify the path is correct for your machine:
cat demos/mcp/claude_desktop_config.json | jq .mcpServers.stratium.command
```

> **Important:** The `command` field must be an absolute path to `bin/stratium-mcp`. Edit the path if your repo is not at `/Users/benjaminparrish/Development/stratium`.

### 13.2 Restart Claude Desktop

Quit and reopen the Claude Desktop app. The MCP server should start automatically.

### 13.3 Verify Tools

In the Claude Desktop chat, ask:

```
What stratium tools do you have available?
```

**PASS criteria:**
- [ ] Claude lists the 13 stratium tools
- [ ] No errors about MCP server connection

### 13.4 Demo Flow: Register + Delegate + Authorize

In Claude Desktop, prompt:

```
Register a new agent called "desktop-analyst" with trust tier 1,
provider "anthropic", and allowed tools ["read_file", "list_files"].
Then create a delegation with those tools, max action tier 1 (READ_ONLY),
and purpose "desktop demo". After that, try to execute_action for
read_file (action "read", tier 1), then try write_file (action "write", tier 2).
```

**PASS criteria:**
- [ ] Claude calls `register_agent` — agent created
- [ ] Claude calls `create_delegation` — receives `instructions` telling it to check authorization
- [ ] Claude calls `execute_action` for read_file — `authorized: true`
- [ ] Claude calls `execute_action` for write_file — `authorized: false`, Claude explains the denial
- [ ] Claude does NOT attempt to write the file after receiving the denial

### 13.5 Verify CLAUDE.md Enforcement

Without explicitly asking Claude to call `execute_action`, ask it to perform an action:

```
Read the file demos/mcp/financial-records/public/annual-report-2025.txt
```

**PASS criteria:**
- [ ] Claude calls `execute_action` first (due to CLAUDE.md instructions) before attempting to read
- [ ] If authorized, Claude proceeds to read the file
- [ ] If no delegation is active, Claude explains it needs to create one first

---

## 14. Security Tests

### 14.1 No Delegation Token — Should Fail

```bash
printf '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}\n{"jsonrpc":"2.0","method":"tools/call","params":{"name":"execute_action","arguments":{"tool_name":"read_file","action":"read","action_tier":1}},"id":2}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | tail -1 | jq -r '.result.content[0].text'
```

**PASS criteria:**
- [ ] Returns error: "delegation_token required (no active delegation in this session)"
- [ ] `isError` is `true`

### 14.2 Expired Token Cache — Should Re-authenticate

```bash
# Write an expired token
cat > ~/.stratium/token.json << 'EOF'
{
  "access_token": "expired.jwt.token",
  "expires_in": 0,
  "expires_at": 1000000000,
  "user_id": "admin456"
}
EOF
```

The next MCP tool call should trigger the OIDC browser flow (or fail if Keycloak is unreachable).

**PASS criteria:**
- [ ] MCP server detects expired token
- [ ] Attempts to refresh or re-authenticate

> **Cleanup:** Re-seed a valid token per section 3.1 after this test.

### 14.3 Token File Permissions

```bash
ls -la ~/.stratium/token.json
```

**PASS criteria:**
- [ ] File permissions are `0600` (owner read/write only)
- [ ] File is not world-readable

---

## 15. Cleanup

### 15.1 Remove Test Agents

Test agents accumulate in the database. To clean up:

```bash
# List agents and identify test ones
grpcurl -cacert config/examples/certs/ca.crt \
  -H "authorization: Bearer $TOKEN" \
  -H "x-user-id: admin456" \
  -d '{}' \
  localhost:50054 agent_gateway.AgentGatewayService/ListAgents \
  | jq '.agents[] | {id, name}'
```

### 15.2 Remove Token and Delegation Cache

```bash
rm -f ~/.stratium/token.json
rm -f ~/.stratium/delegation.json
```

### 15.3 Stop Docker Services

```bash
cd deployment/docker
docker-compose --profile agent-auth down
```

### 15.4 Remove Demo Policies (Optional)

If you want to re-run the seed script cleanly, delete the demo policies via the PAP API or truncate the `policies` table:

```bash
docker exec -it stratium-postgres psql -U stratium -d stratium_pap \
  -c "DELETE FROM policies WHERE tenant_id = 'demo';"
```

---

## Troubleshooting

### MCP server exits immediately

**Problem:** `./bin/stratium-mcp` exits with no output.
**Cause:** The binary reads from stdin. When run without piped input, it waits for input and EOF.
**Fix:** Always pipe JSON-RPC messages into it, or let Claude Code manage the lifecycle.

### "failed to connect to agent gateway"

**Problem:** MCP server logs connection errors to stderr.
**Cause:** Agent Gateway is not running or not on port 50054.
**Fix:**
```bash
docker ps | grep agent-gateway
# If missing, start with: docker-compose --profile agent-auth up -d agent-gateway
```

### "authentication required" on tool calls

**Problem:** Every tool call returns an auth error.
**Cause:** No cached token and browser OIDC flow can't complete (headless env).
**Fix:** Pre-seed a token per section 3.1.

### PAP returns "Client sent an HTTP request to an HTTPS server"

**Problem:** `stratium-audit` or seed script gets a 400 from PAP.
**Cause:** PAP runs HTTPS with self-signed certs. Using `http://` instead of `https://`.
**Fix:** Use `https://localhost:8090` and `-k` flag for curl (or `--pap-url https://localhost:8090` for the audit CLI).

### Claude Code doesn't see stratium tools

**Problem:** Claude Code doesn't list any stratium tools.
**Cause:** MCP server not configured in `~/.claude/settings.json`, or binary not built.
**Fix:**
```bash
# Verify config exists
cat ~/.claude/settings.json | jq .mcpServers.stratium

# Verify binary exists
ls -la $(cat ~/.claude/settings.json | jq -r .mcpServers.stratium.command)

# Restart Claude Code
claude
```

### Claude Desktop doesn't see stratium tools

**Problem:** Claude Desktop doesn't list any stratium tools.
**Cause:** Config not in the right location, or absolute path is wrong.
**Fix:**
```bash
# Verify config location (macOS)
cat ~/Library/Application\ Support/Claude/claude_desktop_config.json | jq .

# Verify the binary path exists
ls -la $(cat ~/Library/Application\ Support/Claude/claude_desktop_config.json \
  | jq -r .mcpServers.stratium.command)

# Restart Claude Desktop after any config change
```

### "language must be one of xacml, opa, json, cedar"

**Problem:** Seed script fails creating policies.
**Cause:** Policy language should be `opa`, not `rego`.
**Fix:** Already fixed in the current seed script. If using an old version, update `"language": "rego"` to `"language": "opa"`.
