# Testing Guide: OpenAI Agent Authorization

**Feature:** Multi-Provider Agent Authorization (OpenAI Codex & Desktop)
**PRD:** `docs/PRD_OPENAI_AGENT_AUTHORIZATION.md`
**Date:** 2026-04-11

---

## Prerequisites

- Docker and Docker Compose installed
- `jq` installed (`brew install jq`)
- `grpcurl` installed (`brew install grpcurl`)
- Go 1.25+
- Python 3.10+
- Claude Code CLI (for Claude-side testing)

---

## 1. Environment Setup

### 1.1 Start All Services

```bash
cd deployment/docker
docker-compose --profile agent-auth up -d
docker-compose --profile agent-auth ps
```

### 1.2 Build Binaries

```bash
make build-mcp build-audit
```

### 1.3 Seed Demo Data

```bash
# Seed base data (users, policies, Claude agents)
./demos/mcp/seed-demo-data.sh

# Seed OpenAI agents
./demos/codex/seed-openai-agents.sh
```

---

## 2. Test: `--mode=check` (Single-Shot Authorization)

### 2.1 No Delegation Token (Fail-Closed)

```bash
echo '{"tool_name":"Bash","action":"read","action_tier":1}' \
  | STRATIUM_DELEGATION_TOKEN="" ./bin/stratium-mcp --mode=check 2>/dev/null
```

**PASS criteria:**
- [ ] Returns `{"authorized":false,"error":"STRATIUM_DELEGATION_TOKEN not set"}`
- [ ] Exit code is 1

### 2.2 Valid Token, Gateway Unreachable (Fail-Closed)

```bash
echo '{"tool_name":"Bash","action":"read","action_tier":1}' \
  | STRATIUM_DELEGATION_TOKEN="test-jwt" \
    STRATIUM_GATEWAY_ADDRESS="localhost:99999" \
    ./bin/stratium-mcp --mode=check 2>/dev/null
```

**PASS criteria:**
- [ ] Returns `{"authorized":false,"error":"gateway call failed: ..."}`
- [ ] `authorized` is `false`

### 2.3 Valid Token + Running Gateway

First, obtain a delegation token (requires running stack):

```bash
# Get OIDC credentials
TOKEN=$(cat ~/.stratium/token.json | jq -r '.access_token')
USER_ID=$(cat ~/.stratium/token.json | jq -r '.user_id')

# Get first registered agent ID (note: field is "id", not "agentId")
AGENT_ID=$(grpcurl -cacert config/examples/certs/ca.crt \
  -H "authorization: Bearer $TOKEN" \
  -H "x-user-id: $USER_ID" \
  localhost:50054 agent_gateway.AgentGatewayService/ListAgents \
  | jq -r '.agents[0].id')

# Create a delegation token (HMAC-SHA256 signed by Agent Gateway)
DELEGATION_TOKEN=$(grpcurl -cacert config/examples/certs/ca.crt \
  -H "authorization: Bearer $TOKEN" \
  -H "x-user-id: $USER_ID" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "approved_tools": ["read_file", "write_file", "bash"],
    "approved_actions": [0, 1, 2],
    "max_action_tier": 2,
    "classification_caps": {"commercial": "INTERNAL"},
    "purpose": "Test check mode",
    "ttl_seconds": 900
  }' \
  localhost:50054 agent_gateway.AgentGatewayService/CreateDelegation \
  | jq -r '.delegationToken')
```

> **Important:** `STRATIUM_DELEGATION_TOKEN` must be the Stratium-minted delegation JWT (HMAC-SHA256), **not** the Keycloak OIDC access token (RS256). If you see `"unexpected signing method: RS256"`, you're using the wrong token.

Now test the check:

```bash
echo '{"tool_name":"read_file","action":"read","action_tier":1}' \
  | STRATIUM_DELEGATION_TOKEN="$DELEGATION_TOKEN" \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    ./bin/stratium-mcp --mode=check 2>/dev/null
```

**PASS criteria:**
- [ ] Returns `{"authorized":true,"decision":{"agent_decision":"ALLOW","delegation_decision":"ALLOW"}}`
- [ ] `agent_decision` and `delegation_decision` are both `"ALLOW"`

### 2.4 Denial — Action Tier Exceeds Delegation

Using the same delegation token (max_action_tier: 2), request a tier 4 action:

```bash
echo '{"tool_name":"bash","action":"execute","action_tier":4}' \
  | STRATIUM_DELEGATION_TOKEN="$DELEGATION_TOKEN" \
    STRATIUM_TLS_CA=config/examples/certs/ca.crt \
    ./bin/stratium-mcp --mode=check 2>/dev/null
```

**PASS criteria:**
- [ ] Returns `{"authorized":false,...}`
- [ ] Error mentions "denied at depth 0"

---

## 3. Test: Codex Hook Scripts

### 3.1 Run Unit Tests

```bash
python3 demos/codex/hooks/test_hooks.py
```

**PASS criteria:**
- [ ] All 5 test suites pass
- [ ] classify_command: 24/24 assertions pass
- [ ] All hook scripts return valid JSON

### 3.2 PreToolUse Hook — No Token (Deny)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | STRATIUM_DELEGATION_TOKEN="" \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] `permissionDecision` is `"deny"`
- [ ] Reason mentions "No Stratium delegation token"

### 3.3 PreToolUse Hook — Unreachable Binary (Fail-Closed)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"}}' \
  | STRATIUM_DELEGATION_TOKEN="test-jwt" \
    STRATIUM_MCP_BIN="/nonexistent/binary" \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] `permissionDecision` is `"deny"`
- [ ] Reason mentions "failed" or "No such file"

### 3.4 PreToolUse Hook — End-to-End (with binary, no gateway)

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | STRATIUM_DELEGATION_TOKEN="test-jwt" \
    STRATIUM_MCP_BIN="./bin/stratium-mcp" \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] `permissionDecision` is `"deny"` (gateway unreachable = fail-closed)
- [ ] Reason contains `"gateway call failed"` (connection error, not a token or classification issue)

### 3.5 SessionStart Hook — No Token

```bash
echo '{"source":"startup"}' \
  | STRATIUM_DELEGATION_TOKEN="" \
    python3 demos/codex/hooks/stratium_session_start.py 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] `additionalContext` contains "WARNING"
- [ ] Mentions "No Stratium delegation token"

---

## 4. Test: Cross-Provider Delegation Chain

### 4.1 Run Go Tests

```bash
cd go && go test ./services/agent-gateway/ -run TestCross -v
```

**PASS criteria:**
- [ ] `child_max_tier_leq_parent` passes
- [ ] `child_tools_subset_of_parent` passes
- [ ] `child_depth_is_parent_plus_one` passes
- [ ] `child_chain_extends_parent_chain` passes
- [ ] `child_root_delegation_matches_parent` passes
- [ ] `no_provider_field_in_token` passes

### 4.2 Classification Cap Narrowing

```bash
cd go && go test ./services/agent-gateway/ -run TestClassification -v
```

**PASS criteria:**
- [ ] Equal caps: valid
- [ ] Child narrower: valid
- [ ] Child wider: invalid
- [ ] Child most narrow: valid

---

## 5. Test: `stratium-audit` Provider/Layer Filtering

### 5.1 Verify New Flags

```bash
./bin/stratium-audit logs --help
```

**PASS criteria:**
- [ ] `--provider` flag is listed
- [ ] `--transport` flag is listed

### 5.2 Filter by Provider

```bash
./bin/stratium-audit logs --provider openai --since 1h
```

**PASS criteria:**
- [ ] Only shows logs from OpenAI agents
- [ ] PROVIDER column shows "openai"
- [ ] LAYER column is present

---

## 6. Test: ChatGPT Desktop MCP Config

### 6.1 Verify Config File

```bash
cat demos/codex/chatgpt_desktop_config.json | jq .
```

**PASS criteria:**
- [ ] Valid JSON
- [ ] `mcpServers.stratium.command` points to `stratium-mcp`
- [ ] Environment variables are set

### 6.2 Verify MCP Server Starts (Desktop Mode)

```bash
# MCP server should start and respond to initialize
printf '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"chatgpt-desktop","version":"1.0"}},"id":1}\n' \
  | STRATIUM_TLS_CA=config/examples/certs/ca.crt ./bin/stratium-mcp 2>/dev/null | jq .
```

**PASS criteria:**
- [ ] Returns valid JSON-RPC response
- [ ] `serverInfo.name` is `"stratium-mcp"`
- [ ] Same response as Claude Desktop would get (provider-agnostic)

---

## 7. Full Multi-Provider Demo (E2E)

Requires the full stack running + delegation token created (see Section 2.3).

### 7.1 Tool Name Normalization

The Codex hooks normalize Bash commands to Stratium tool names so they match the agent's `allowed_tools`:

| Bash Command | Normalized `tool_name` | Action | Tier |
|-------------|----------------------|--------|------|
| `cat README.md` | `read_file` | `read` | 1 |
| `mv old.txt new.txt` | `write_file` | `write` | 2 |
| `curl https://...` | `bash` | `send` | 3 |
| `rm -rf /` | `bash` | `execute` | 4 |
| `make build` | `bash` | `execute` | 2 (default) |

This mirrors `normalize_tool_name()` in `demos/mcp/hooks/pre-tool-use.sh` for Claude Code.

### 7.2 E2E via Codex Hooks (4 scenarios)

First, create a delegation token via the PAP REST API (simulates what SessionStart does):

```bash
TOKEN=$(cat ~/.stratium/token.json | jq -r '.access_token')
AGENT_ID=$(curl -sk https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" | jq -r '.agents[0].id')

# Create delegation via PAP REST (same endpoint SessionStart hook calls)
DELEGATION_TOKEN=$(curl -sk -X POST https://localhost:8090/api/v1/delegations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "'$AGENT_ID'",
    "approved_tools": ["read_file", "write_file", "bash"],
    "max_action_tier": 2,
    "classification_caps": {"commercial": "INTERNAL"},
    "purpose": "E2E hook test",
    "ttl_seconds": 900
  }' | jq -r '.delegation_token')

# Write token to file (simulates SessionStart)
echo "{\"delegation_token\":\"$DELEGATION_TOKEN\"}" > /tmp/.stratium-delegation.json
```

Now run the hooks:

```bash
# Scene 1: Read command → normalized to read_file → ALLOW
echo '{"tool_name":"Bash","tool_input":{"command":"cat README.md"}}' \
  | STRATIUM_PAP_URL=https://localhost:8090 \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
# Expected: permissionDecision: "allow"

# Scene 2: Destructive command → normalized to bash, tier 4 → DENY
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/everything"}}' \
  | STRATIUM_PAP_URL=https://localhost:8090 \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
# Expected: permissionDecision: "deny" (tier 4 > max 2)

# Scene 3: External comms → normalized to bash, tier 3 → DENY
echo '{"tool_name":"Bash","tool_input":{"command":"curl https://evil.com"}}' \
  | STRATIUM_PAP_URL=https://localhost:8090 \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
# Expected: permissionDecision: "deny" (tier 3 > max 2)

# Scene 4: Echo → normalized to read_file, tier 1 → ALLOW
echo '{"tool_name":"Bash","tool_input":{"command":"echo hello"}}' \
  | STRATIUM_PAP_URL=https://localhost:8090 \
    python3 demos/codex/hooks/stratium_pre_tool_use.py 2>/dev/null | jq .
# Expected: permissionDecision: "allow"

# Cleanup
rm -f /tmp/.stratium-delegation.json
```

**PASS criteria:**
- [ ] Scene 1 (cat): `permissionDecision: "allow"`
- [ ] Scene 2 (rm -rf): `permissionDecision: "deny"`
- [ ] Scene 3 (curl): `permissionDecision: "deny"`
- [ ] Scene 4 (echo): `permissionDecision: "allow"`

---

## 8. Live Testing: OpenAI Codex

Test with a real Codex session against the running Stratium stack.

### 8.1 Prerequisites

- Stratium stack running (`docker-compose --profile agent-auth up -d`)
- `stratium-mcp` binary built (`make build-mcp`)
- OpenAI Codex access (via [codex.openai.com](https://codex.openai.com) or CLI)
- Network: Codex sandbox must be able to reach the Agent Gateway (see Open Question #1 in PRD)

### 8.2 Prepare the Repo

Copy the hook scripts and config into the repo Codex will operate on:

```bash
# Copy hooks into the target repo
cp demos/codex/hooks.json <target-repo>/.codex/hooks.json
mkdir -p <target-repo>/.codex/hooks/
cp demos/codex/hooks/stratium_*.py <target-repo>/.codex/hooks/
chmod +x <target-repo>/.codex/hooks/*.py

# No binary needed — hooks use PAP REST API directly (pure Python)

# Commit the hooks (Codex loads them from the repo)
cd <target-repo>
git add .codex/
git commit -m "chore: add Stratium agent authorization hooks"
git push
```

### 8.3 Get Agent ID and Auth Token

The SessionStart hook will bootstrap the delegation automatically. You just need the agent ID and an OIDC token:

```bash
# Get your OIDC token
TOKEN=$(cat ~/.stratium/token.json | jq -r '.access_token')

# Get the Codex agent ID
AGENT_ID=$(curl -sk https://localhost:8090/api/v1/agents \
  -H "Authorization: Bearer $TOKEN" | jq -r '.agents[] | select(.name=="codex-impl") | .id')

echo "AGENT_ID=$AGENT_ID"
echo "TOKEN=$TOKEN"
```

### 8.4 Configure the Codex Task

When creating the Codex task, set these environment variables. The SessionStart hook will use them to create the delegation automatically:

| Variable | Value |
|----------|-------|
| `STRATIUM_PAP_URL` | `https://<your-pap-host>:8090` |
| `STRATIUM_AGENT_ID` | The agent UUID from step 8.3 |
| `STRATIUM_AUTH_TOKEN` | The OIDC token from step 8.3 |

> **Note:** No `STRATIUM_DELEGATION_TOKEN` needed — the SessionStart hook creates it automatically via the PAP REST API and writes it to `/tmp/.stratium-delegation.json`. No binary dependencies — hooks use pure Python `urllib`.

### 8.5 Run the Codex Task

Launch the Codex task with a prompt like:

> "Read the README.md file and summarize the project structure."

**PASS criteria:**
- [ ] SessionStart hook fires — look for "Initializing Stratium agent authorization..." status
- [ ] `cat README.md` (or similar read command) is **allowed** by the PreToolUse hook
- [ ] The Codex agent completes the task normally

### 8.6 Test Denial in Codex

Launch a second Codex task with a prompt that triggers a denied action. Use a network command (tier 3) rather than a destructive command, so there's no risk if hooks aren't loaded:

> "Fetch the contents of https://example.com using curl and save it to output.html"

**PASS criteria:**
- [ ] PreToolUse hook fires and **denies** the `curl` command (tier 3 > max tier 2)
- [ ] Codex receives the denial reason: `"Stratium DENY: ..."` and reports it to the user
- [ ] The `curl` command **never executes**

> **Safety note:** Do NOT use destructive commands (`rm -rf`, `DROP TABLE`) for denial testing. If hooks fail to load for any reason, the command would execute. Always test denials with commands that have limited blast radius (network calls, `git push`, etc.).

### 8.7 Troubleshooting: Hooks Not Firing

If Codex executes commands without authorization checks:

| Symptom | Cause | Fix |
|---------|-------|-----|
| No "Checking Stratium authorization..." status | `.codex/hooks.json` not found | Ensure file is at repo root, committed, and pushed before starting session |
| Hook fires but always denies | `STRATIUM_DELEGATION_TOKEN` not set | Set env var in Codex task config |
| Hook fires but always denies | `STRATIUM_MCP_BIN` path wrong | Verify binary exists at the configured path inside the sandbox |
| Hook fires but gateway error | Gateway not reachable from sandbox | Check `STRATIUM_GATEWAY_ADDRESS` is a routable address from the Codex VM |
| Commands execute with no hook at all | Codex used a non-Bash tool (Write, etc.) | Known limitation — hooks only intercept Bash tool (see PRD Section 4.6) |

### 8.7 Verify Audit Trail

After both tasks complete, check the audit trail:

```bash
./bin/stratium-audit logs --provider openai --since 30m
```

**PASS criteria:**
- [ ] Both ALLOW and DENY decisions appear
- [ ] Agent name shows `codex-impl`
- [ ] Provider shows `openai`

---

## 9. Live Testing: ChatGPT Desktop

Test with ChatGPT Desktop using `stratium-mcp` as an MCP server.

### 9.1 Prerequisites

- Stratium stack running
- `stratium-mcp` binary built
- ChatGPT Desktop app with MCP server support enabled

### 9.2 Configure ChatGPT Desktop

Copy the MCP config to the ChatGPT Desktop configuration directory:

```bash
# macOS (expected path — may vary based on ChatGPT Desktop version)
mkdir -p ~/Library/Application\ Support/ChatGPT/
cp demos/codex/chatgpt_desktop_config.json \
   ~/Library/Application\ Support/ChatGPT/config.json
```

Or manually configure in ChatGPT Desktop settings:

| Setting | Value |
|---------|-------|
| MCP Server Name | `stratium` |
| Command | `/path/to/bin/stratium-mcp` |
| Environment: `STRATIUM_GATEWAY_ADDRESS` | `localhost:50054` |
| Environment: `STRATIUM_KEYCLOAK_URL` | `http://localhost:8080/realms/stratium` |
| Environment: `STRATIUM_CLIENT_ID` | `stratium-mcp` |
| Environment: `STRATIUM_TLS_CA` | `/path/to/config/examples/certs/ca.crt` |

### 9.3 Start a Session

1. Open ChatGPT Desktop
2. Start a new conversation
3. The MCP server should connect — verify the Stratium tools appear in the tool list

**PASS criteria:**
- [ ] `stratium-mcp` process starts (check `ps aux | grep stratium-mcp`)
- [ ] Stratium tools are available (register_agent, create_delegation, execute_action, etc.)

### 9.4 Register and Authorize

In the ChatGPT Desktop conversation:

1. Ask: *"Register yourself as an OpenAI agent with provider 'openai' and trust tier 1"*
2. Ask: *"Create a delegation with approved tools [read_file, write_file] and max action tier 2"*
3. Ask: *"Check if you can read a file by calling execute_action with tool_name 'read_file', action 'read', action_tier 1"*

**PASS criteria:**
- [ ] `register_agent` returns an agent_id
- [ ] `create_delegation` returns a delegation_token and expires_at
- [ ] `execute_action` returns `authorized: true` with `agent_decision: "ALLOW"`, `delegation_decision: "ALLOW"`

### 9.5 Test Denial in Desktop

Ask: *"Check if you can delete files by calling execute_action with tool_name 'bash', action 'execute', action_tier 4"*

**PASS criteria:**
- [ ] `execute_action` returns `authorized: false`
- [ ] Reason explains the tier exceeds the delegation scope

### 9.6 Verify Provider-Agnostic Behavior

The same MCP tools and responses should be identical to a Claude Desktop session. The only difference is the agent registers with `provider: "openai"`.

**PASS criteria:**
- [ ] Tool list is identical to Claude Desktop (`tools/list` returns same 13-14 tools)
- [ ] `register_agent` with `provider: "openai"` works
- [ ] Delegation and authorization flow is identical to Claude Desktop

### 9.7 Verify Audit Trail

```bash
./bin/stratium-audit logs --provider openai --transport mcp --since 30m
```

**PASS criteria:**
- [ ] Actions from ChatGPT Desktop appear in the audit trail
- [ ] PROVIDER shows `openai`
- [ ] LAYER shows `mcp`

---

## Test Account Reference

| User | Password | Agent | Provider | Trust Tier |
|------|----------|-------|----------|------------|
| admin456 | admin123 | (admin) | — | — |
| demo-analyst | demo123 | codex-impl | openai | 1 |
| demo-analyst | demo123 | desktop-reviewer | openai | 1 |
| demo-director | demo123 | codex-sub-agent | openai | 1 |
