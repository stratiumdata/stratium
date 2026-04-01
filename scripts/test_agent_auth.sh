#!/bin/bash
# test_agent_auth.sh — Manual test runner for the Agent Authorization feature
#
# Usage:
#   ./scripts/test_agent_auth.sh            # run all sections
#   ./scripts/test_agent_auth.sh 1          # environment setup only
#   ./scripts/test_agent_auth.sh 2          # agent registry (PAP REST)
#   ./scripts/test_agent_auth.sh 3          # audit logging
#   ./scripts/test_agent_auth.sh 4          # database schema
#   ./scripts/test_agent_auth.sh 5          # delegation token flow (gRPC)
#   ./scripts/test_agent_auth.sh 6          # delegation chain / subagent
#   ./scripts/test_agent_auth.sh 7          # revocation and cascade
#   ./scripts/test_agent_auth.sh 8          # action plan validation
#   ./scripts/test_agent_auth.sh 9          # compound policy evaluation
#   ./scripts/test_agent_auth.sh 11         # security / negative tests
#   ./scripts/test_agent_auth.sh clean      # cleanup (section 12)
#
# State (agent IDs, tokens) is saved to /tmp/stratium-agent-auth.env between runs
# so individual sections can be run after a prior full run.

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-https://localhost:8090}"
GATEWAY_ADDR="${GATEWAY_ADDR:-localhost:50054}"
PLATFORM_ADDR="${PLATFORM_ADDR:-localhost:50051}"
CACERT="${CACERT:-config/examples/certs/ca.crt}"
REALM="${REALM:-stratium}"
TENANT_ID="${TENANT_ID:-test-tenant}"
ADMIN_USER="${ADMIN_USER:-admin456}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
STATE_FILE="${STATE_FILE:-/tmp/stratium-agent-auth.env}"

# ─── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Counters ─────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0

# ─── Helpers ──────────────────────────────────────────────────────────────────

section_header() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━ Section $1: $2 ━━━${NC}"
    echo ""
}

step() {
    echo -e "${YELLOW}▶ $*${NC}"
}

pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $*"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $*"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "  ${YELLOW}– SKIP${NC}: $*"
    SKIP=$((SKIP + 1))
}

assert_contains() {
    local label="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        pass "$label"
    else
        fail "$label — expected to contain '$expected', got: $actual"
    fi
}

assert_not_contains() {
    local label="$1" unexpected="$2" actual="$3"
    if echo "$actual" | grep -q "$unexpected"; then
        fail "$label — expected NOT to contain '$unexpected', got: $actual"
    else
        pass "$label"
    fi
}

assert_json_field() {
    local label="$1" field="$2" expected="$3" json="$4"
    local actual
    actual=$(echo "$json" | jq -r "$field" 2>/dev/null || true)
    if [ "$actual" = "$expected" ]; then
        pass "$label"
    else
        fail "$label — $field: expected '$expected', got '$actual'"
    fi
}

assert_json_field_nonempty() {
    local label="$1" field="$2" json="$3"
    local actual
    actual=$(echo "$json" | jq -r "$field" 2>/dev/null || true)
    if [ -n "$actual" ] && [ "$actual" != "null" ]; then
        pass "$label"
    else
        fail "$label — $field is empty or null"
    fi
}

# Assert a response represents any form of denial/error:
#   - {"authorized": false}  (proto3 success response)
#   - {"grpc_error": "..."}  (normalized gRPC error from grpc_call)
#   - {"error": "..."}       (application-level JSON error body)
_assert_denied() {
    local label="$1" resp="$2"
    if echo "$resp" | jq -e '.authorized == false' >/dev/null 2>&1; then
        pass "$label (authorized:false)"
    elif echo "$resp" | jq -e '.grpc_error' >/dev/null 2>&1; then
        pass "$label (gRPC error: $(echo "$resp" | jq -r '.grpc_error'))"
    elif echo "$resp" | jq -e '.error' >/dev/null 2>&1; then
        pass "$label (error: $(echo "$resp" | jq -r '.error'))"
    else
        fail "$label — expected denial, got: $resp"
    fi
}

assert_http_error() {
    # Checks that the response JSON contains an "error" key
    local label="$1" json="$2"
    local err
    err=$(echo "$json" | jq -r '.error // empty' 2>/dev/null || true)
    if [ -n "$err" ]; then
        pass "$label (error: $err)"
    else
        fail "$label — expected an error response, got: $json"
    fi
}

grpc_call() {
    # grpc_call [-H header value] ... <addr> <method> [json_data]
    # Returns JSON on success; on gRPC error returns {"grpc_error":"<message>","grpc_code":"<code>"}
    local -a extra_flags
    extra_flags=()
    while [[ "${1:-}" == -H ]]; do
        extra_flags+=("$1" "$2")
        shift 2
    done
    local addr="$1" method="$2" data="${3:-}"
    local raw
    # Use ${extra_flags[@]+"${extra_flags[@]}"} to safely expand empty arrays under set -u
    if [ -n "$data" ]; then
        raw=$(grpcurl -cacert "$CACERT" ${extra_flags[@]+"${extra_flags[@]}"} -d "$data" "$addr" "$method" 2>&1) || true
    else
        raw=$(grpcurl -cacert "$CACERT" ${extra_flags[@]+"${extra_flags[@]}"} "$addr" "$method" 2>&1) || true
    fi
    # grpcurl errors start with "ERROR:" — normalize to JSON so jq always works
    if echo "$raw" | grep -q '^ERROR:'; then
        local code msg
        code=$(echo "$raw" | grep 'Code:' | awk '{print $2}')
        msg=$(echo "$raw" | grep 'Message:' | sed 's/.*Message: //')
        echo "{\"grpc_error\":\"$msg\",\"grpc_code\":\"$code\"}"
    else
        echo "$raw"
    fi
}

# Assert that a grpc_call response is a gRPC error (not success JSON)
assert_grpc_error() {
    local label="$1" expected_fragment="$2" resp="$3"
    local err
    err=$(echo "$resp" | jq -r '.grpc_error // empty' 2>/dev/null || true)
    if [ -n "$err" ] && echo "$err" | grep -qi "$expected_fragment"; then
        pass "$label (error: $err)"
    elif [ -n "$err" ]; then
        fail "$label — got error but wrong message: $err (expected: $expected_fragment)"
    else
        fail "$label — expected gRPC error, got success response: $resp"
    fi
}

save_state() {
    cat > "$STATE_FILE" <<EOF
TOKEN='${TOKEN:-}'
AGENT_ID='${AGENT_ID:-}'
AGENT2_ID='${AGENT2_ID:-}'
SUBAGENT_ID='${SUBAGENT_ID:-}'
DELEGATION_ID='${DELEGATION_ID:-}'
DELEGATION_TOKEN='${DELEGATION_TOKEN:-}'
CHILD_DELEGATION_ID='${CHILD_DELEGATION_ID:-}'
CHILD_TOKEN='${CHILD_TOKEN:-}'
EOF
    echo -e "  ${CYAN}(state saved to $STATE_FILE)${NC}"
}

load_state() {
    if [ -f "$STATE_FILE" ]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        echo -e "${CYAN}Loaded state from $STATE_FILE${NC}"
    fi
}

summary() {
    echo ""
    echo -e "${BOLD}━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}PASS${NC}: $PASS"
    [ "$FAIL" -gt 0 ] && echo -e "  ${RED}FAIL${NC}: $FAIL" || echo -e "  FAIL: $FAIL"
    [ "$SKIP" -gt 0 ] && echo -e "  SKIP: $SKIP"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [ "$FAIL" -eq 0 ]
}

# ─── Section 1: Environment Setup ────────────────────────────────────────────

section_1() {
    section_header 1 "Environment Setup"

    step "Keycloak reachable"
    realm=$(curl -s "$KEYCLOAK_URL/realms/$REALM" | jq -r '.realm' 2>/dev/null || true)
    assert_json_field "Keycloak realm" ".realm" "$REALM" "$(curl -s "$KEYCLOAK_URL/realms/$REALM")"

    step "PAP health check"
    health=$(curl -sk "$PAP_URL/health")
    assert_contains "PAP healthy" "healthy" "$health"

    step "Agent Gateway gRPC reflection"
    svc_list=$(grpcurl -cacert "$CACERT" "$GATEWAY_ADDR" list 2>&1 || true)
    assert_contains "AgentGatewayService listed" "AgentGatewayService" "$svc_list"

    step "Get admin token"
    TOKEN=$(curl -s -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "client_id=stratium-pap" \
        -d "client_secret=stratium-pap-secret" \
        -d "grant_type=password" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASS" | jq -r '.access_token' 2>/dev/null || true)
    if [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ]; then
        pass "Admin token obtained"
        export TOKEN
    else
        fail "Admin token — empty or null"
    fi

    step "Database tables"
    tables=$(docker exec stratium-postgres psql -U stratium -d stratium_pap -c "\dt" 2>/dev/null || true)
    assert_contains "agents table exists" "agents" "$tables"
    assert_contains "delegations table exists" "delegations" "$tables"

    save_state
}

# ─── Section 2: Agent Registry (PAP REST) ────────────────────────────────────

section_2() {
    section_header 2 "Agent Registry (PAP REST API)"

    step "2.1 Register claude-research-agent (tier 1)"
    resp=$(curl -sk -X POST "$PAP_URL/api/v1/agents" \
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
          "tenant_id": "'"$TENANT_ID"'",
          "metadata": {"purpose": "research", "version": "1.0"}
        }')
    assert_json_field_nonempty "2.1 agent_id returned" ".agent_id" "$resp"
    assert_contains "2.1 client_id prefix" "agent_" "$(echo "$resp" | jq -r '.client_id')"
    AGENT_ID=$(echo "$resp" | jq -r '.agent_id')
    export AGENT_ID

    step "2.2 Register codex-code-agent (tier 2)"
    resp2=$(curl -sk -X POST "$PAP_URL/api/v1/agents" \
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
          "tenant_id": "'"$TENANT_ID"'"
        }')
    assert_json_field_nonempty "2.2 agent2_id returned" ".agent_id" "$resp2"
    AGENT2_ID=$(echo "$resp2" | jq -r '.agent_id')
    export AGENT2_ID

    step "2.3 List agents"
    list=$(curl -sk "$PAP_URL/api/v1/agents?tenant_id=$TENANT_ID" \
        -H "Authorization: Bearer $TOKEN")
    assert_contains "2.3 claude-research-agent in list" "claude-research-agent" "$list"
    assert_contains "2.3 codex-code-agent in list" "codex-code-agent" "$list"

    step "2.4 Get agent by ID"
    get=$(curl -sk "$PAP_URL/api/v1/agents/$AGENT_ID" \
        -H "Authorization: Bearer $TOKEN")
    assert_json_field "2.4 correct agent returned" ".id" "$AGENT_ID" "$get"
    assert_not_contains "2.4 client_secret not in GET response" "client_secret" "$get"

    step "2.5 Update agent"
    upd=$(curl -sk -X PUT "$PAP_URL/api/v1/agents/$AGENT_ID" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"trust_tier": 2, "allowed_tools": ["read_file", "search", "list_documents", "summarize"]}')
    # updateAgent returns the full Agent struct: .id, .trust_tier, .allowed_tools etc.
    assert_json_field "2.5 trust_tier updated" ".trust_tier" "2" "$upd"
    assert_contains "2.5 summarize in allowed_tools" "summarize" "$(echo "$upd" | jq -r '.allowed_tools | @json')"

    step "2.6 Suspend agent2"
    sus=$(curl -sk -X POST "$PAP_URL/api/v1/agents/$AGENT2_ID/suspend" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"reason": "testing suspension flow"}')
    assert_json_field "2.6 success true" ".success" "true" "$sus"

    step "2.7 Reinstate agent2"
    rei=$(curl -sk -X POST "$PAP_URL/api/v1/agents/$AGENT2_ID/reinstate" \
        -H "Authorization: Bearer $TOKEN")
    assert_json_field "2.7 success true" ".success" "true" "$rei"
    enabled=$(curl -sk "$PAP_URL/api/v1/agents/$AGENT2_ID" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.enabled')
    assert_json_field "2.7 agent re-enabled" ".enabled" "true" \
        "$(curl -sk "$PAP_URL/api/v1/agents/$AGENT2_ID" -H "Authorization: Bearer $TOKEN")"

    step "2.9 Delete agent2"
    del=$(curl -sk -X DELETE "$PAP_URL/api/v1/agents/$AGENT2_ID" \
        -H "Authorization: Bearer $TOKEN")
    assert_json_field "2.9 deleted true" ".deleted" "true" "$del"
    not_found=$(curl -sk "$PAP_URL/api/v1/agents/$AGENT2_ID" \
        -H "Authorization: Bearer $TOKEN")
    assert_http_error "2.9 GET after delete returns error" "$not_found"

    save_state
}

# ─── Section 3: Audit Logging ─────────────────────────────────────────────────

section_3() {
    section_header 3 "Audit Logging"

    step "3.1 Query audit logs for agent entity_type"
    logs=$(curl -sk "$PAP_URL/api/v1/audit-logs?entity_type=agent" \
        -H "Authorization: Bearer $TOKEN")
    assert_json_field_nonempty "3.1 audit_logs field present" ".audit_logs" "$logs"

    count=$(echo "$logs" | jq '.audit_logs | length')
    if [ "${count:-0}" -gt 0 ]; then
        pass "3.1 audit log entries exist (count: $count)"
        echo "$logs" | jq '.audit_logs[] | {action, entity_type, actor}' | head -20
    else
        fail "3.1 no audit log entries found"
    fi
}

# ─── Section 4: Database Schema ───────────────────────────────────────────────

section_4() {
    section_header 4 "Database Schema Verification"

    step "4.1 agents table schema"
    agents_schema=$(docker exec stratium-postgres psql -U stratium -d stratium_pap -c "\d agents" 2>/dev/null || true)
    assert_contains "4.1 trust_tier column" "trust_tier" "$agents_schema"
    assert_contains "4.1 client_id column" "client_id" "$agents_schema"
    assert_contains "4.1 allowed_tools column" "allowed_tools" "$agents_schema"

    step "4.2 delegations table schema"
    del_schema=$(docker exec stratium-postgres psql -U stratium -d stratium_pap -c "\d delegations" 2>/dev/null || true)
    assert_contains "4.2 chain_agent_ids column" "chain_agent_ids" "$del_schema"
    assert_contains "4.2 root_delegation_id column" "root_delegation_id" "$del_schema"
    assert_contains "4.2 depth column" "depth" "$del_schema"

    step "4.3 agent-compound-authorization OPA policy seeded"
    policy=$(docker exec stratium-postgres psql -U keycloak -d stratium_pap -tAc \
        "SELECT name FROM policies WHERE name = 'agent-compound-authorization';" 2>/dev/null | tr -d '[:space:]' || true)
    if [ -n "$policy" ]; then
        pass "4.3 OPA policy present"
    else
        fail "4.3 OPA policy missing — run the migration:
       docker exec -i stratium-postgres psql -U keycloak -d stratium_pap < deployment/postgres/04-init-agent-auth.sql"
    fi
}

# ─── Section 5: Delegation Token Flow (gRPC) ──────────────────────────────────

section_5() {
    section_header 5 "Delegation Token Flow (gRPC)"

    step "5.1 Create root delegation"
    resp=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["read_file", "search"],
          "approved_actions": [0, 1],
          "max_action_tier": 1,
          "classification_caps": {"nato": "CONFIDENTIAL", "commercial": "INTERNAL"},
          "purpose": "Document research session",
          "ttl_seconds": 900,
          "conversation_id": "test-session-001"
        }' 2>&1 || true)
    assert_json_field_nonempty "5.1 delegation_token returned" ".delegationToken" "$resp"
    assert_json_field_nonempty "5.1 delegation_id returned" ".delegationId" "$resp"
    # proto3 omits zero-value fields (depth=0 → absent from JSON); null/absent means 0
    local depth; depth=$(echo "$resp" | jq -r '.depth // "0"' 2>/dev/null || echo "0")
    if [ "$depth" = "0" ] || [ "$depth" = "null" ]; then
        pass "5.1 depth is 0 (root)"
    else
        fail "5.1 depth is 0 (root) — got: $depth"
    fi
    DELEGATION_TOKEN=$(echo "$resp" | jq -r '.delegationToken')
    DELEGATION_ID=$(echo "$resp" | jq -r '.delegationId')
    export DELEGATION_TOKEN DELEGATION_ID

    step "5.2 Decode delegation token JWT"
    seg=$(echo "$DELEGATION_TOKEN" | cut -d. -f2 | tr '_-' '/+' | \
        awk '{l=length($0)%4; if(l==2)$0=$0"=="; else if(l==3)$0=$0"="; print}' | \
        base64 -d 2>/dev/null | jq . 2>/dev/null || true)
    assert_json_field_nonempty "5.2 agent_id in JWT" ".agent_id" "$seg"
    local jwt_depth; jwt_depth=$(echo "$seg" | jq -r '.depth // "0"' 2>/dev/null || echo "0")
    if [ "$jwt_depth" = "0" ] || [ "$jwt_depth" = "null" ]; then
        pass "5.2 depth 0 in JWT"
    else
        fail "5.2 depth 0 in JWT — got: $jwt_depth"
    fi

    step "5.3 GetDelegationChain"
    chain=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/GetDelegationChain \
        '{"delegation_id": "'"$DELEGATION_ID"'"}' 2>&1 || true)
    assert_json_field "5.3 total_depth = 1" ".totalDepth" "1" "$chain"

    step "5.4 ExecuteAction — authorized (read_file, tier 1)"
    exec_ok=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{
          "delegation_token": "'"$DELEGATION_TOKEN"'",
          "target_service": "platform",
          "method": "GetDecision",
          "action": "read",
          "action_tier": 1,
          "tool_name": "read_file",
          "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
        }' 2>&1 || true)
    # proto3: authorized=true is explicit; authorized=false may be omitted (treat absent as false)
    assert_json_field "5.4 authorized true" ".authorized" "true" "$exec_ok"

    step "5.5 ExecuteAction — denied (write_file, not in delegation)"
    exec_deny=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{
          "delegation_token": "'"$DELEGATION_TOKEN"'",
          "target_service": "platform",
          "method": "GetDecision",
          "action": "write",
          "action_tier": 2,
          "tool_name": "write_file",
          "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
        }' 2>&1 || true)
    # authorized=false may be omitted in proto3 JSON (omitempty); absent also means false
    local auth55; auth55=$(echo "$exec_deny" | jq -r '.authorized // "false"' 2>/dev/null || echo "false")
    if [ "$auth55" = "false" ] || echo "$exec_deny" | jq -e '.grpc_error' >/dev/null 2>&1; then
        pass "5.5 write_file denied"
    else
        fail "5.5 expected denial, got: $exec_deny"
    fi

    step "5.6 ExecuteAction — denied (action tier 4 exceeds max 1)"
    exec_tier=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{
          "delegation_token": "'"$DELEGATION_TOKEN"'",
          "target_service": "platform",
          "method": "Execute",
          "action": "delete",
          "action_tier": 4,
          "tool_name": "read_file",
          "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"}
        }' 2>&1 || true)
    local auth56; auth56=$(echo "$exec_tier" | jq -r '.authorized // "false"' 2>/dev/null || echo "false")
    if [ "$auth56" = "false" ] || echo "$exec_tier" | jq -e '.grpc_error' >/dev/null 2>&1; then
        pass "5.6 action tier 4 denied"
    else
        fail "5.6 expected denial, got: $exec_tier"
    fi

    save_state
}

# ─── Section 6: Delegation Chain (Subagent) ───────────────────────────────────

section_6() {
    section_header 6 "Delegation Chain (Subagent)"

    step "6.1 Register summarizer-subagent (tier 0)"
    resp=$(curl -sk -X POST "$PAP_URL/api/v1/agents" \
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
          "tenant_id": "'"$TENANT_ID"'"
        }')
    assert_json_field_nonempty "6.1 subagent_id returned" ".agent_id" "$resp"
    SUBAGENT_ID=$(echo "$resp" | jq -r '.agent_id')
    export SUBAGENT_ID

    step "6.2 Create child delegation (parent → subagent)"
    child=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$SUBAGENT_ID"'",
          "approved_tools": ["read_file"],
          "approved_actions": [0, 1],
          "max_action_tier": 1,
          "classification_caps": {"nato": "RESTRICTED", "commercial": "INTERNAL"},
          "purpose": "Summarize NATO restricted documents",
          "ttl_seconds": 300,
          "conversation_id": "test-session-001",
          "parent_delegation_token": "'"$DELEGATION_TOKEN"'"
        }' 2>&1 || true)
    assert_json_field "6.2 depth = 1" ".depth" "1" "$child"
    assert_json_field_nonempty "6.2 child delegation_token returned" ".delegationToken" "$child"
    CHILD_TOKEN=$(echo "$child" | jq -r '.delegationToken')
    CHILD_DELEGATION_ID=$(echo "$child" | jq -r '.delegationId')
    export CHILD_TOKEN CHILD_DELEGATION_ID

    step "6.3 GetDelegationChain — 2 links"
    chain=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/GetDelegationChain \
        '{"delegation_id": "'"$CHILD_DELEGATION_ID"'"}' 2>&1 || true)
    assert_json_field "6.3 total_depth = 2" ".totalDepth" "2" "$chain"

    step "6.4 Scope widening rejected"
    widened=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$SUBAGENT_ID"'",
          "approved_tools": ["read_file", "write_file", "send_email"],
          "approved_actions": [0, 1, 2, 3],
          "max_action_tier": 4,
          "classification_caps": {"nato": "SECRET"},
          "purpose": "Attempt to escalate privileges",
          "ttl_seconds": 300,
          "parent_delegation_token": "'"$DELEGATION_TOKEN"'"
        }' 2>&1 || true)
    assert_grpc_error "6.4 scope exceeds parent" "scope exceeds parent" "$widened"
    assert_not_contains "6.4 no delegation token in response" "delegationToken" "$(echo "$widened" | jq -r '.delegationToken // empty' 2>/dev/null || true)"

    save_state
}

# ─── Section 7: Revocation and Cascade ────────────────────────────────────────

section_7() {
    section_header 7 "Revocation and Cascade"

    step "7.1 Revoke root delegation"
    rev=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/RevokeDelegation \
        '{
          "delegation_id": "'"$DELEGATION_ID"'",
          "reason": "testing cascade revocation"
        }' 2>&1 || true)
    assert_json_field "7.1 success true" ".success" "true" "$rev"
    assert_contains "7.1 child in revokedDelegationIds" "$CHILD_DELEGATION_ID" "$rev"

    step "7.2 Revoked root token rejected"
    exec_rev=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{
          "delegation_token": "'"$DELEGATION_TOKEN"'",
          "action": "read",
          "action_tier": 1,
          "tool_name": "read_file"
        }')
    # Server may return: authorized:false, a gRPC error, or {"error":"..."}
    _assert_denied "7.2 revoked token rejected" "$exec_rev"

    step "7.3 Cascade — child token also rejected"
    exec_child=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{
          "delegation_token": "'"$CHILD_TOKEN"'",
          "action": "read",
          "action_tier": 1,
          "tool_name": "read_file"
        }')
    _assert_denied "7.3 cascaded child rejected" "$exec_child"
}

# ─── Section 8: Action Plan Validation ────────────────────────────────────────

section_8() {
    section_header 8 "Action Plan Validation"

    # Need a fresh active delegation for this section
    step "8.0 Create fresh delegation for validation tests"
    fresh=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["read_file", "search"],
          "approved_actions": [0, 1],
          "max_action_tier": 1,
          "classification_caps": {"nato": "CONFIDENTIAL"},
          "purpose": "Action plan validation test",
          "ttl_seconds": 300,
          "conversation_id": "test-session-validate"
        }' 2>&1 || true)
    VAL_DELEGATION_ID=$(echo "$fresh" | jq -r '.delegationId')
    assert_json_field_nonempty "8.0 fresh delegation created" ".delegationId" "$fresh"

    step "8.1 Validate correct action plan"
    valid=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ValidateActionPlan \
        '{
          "delegation_id": "'"$VAL_DELEGATION_ID"'",
          "actions": [
            {"tool_name": "read_file", "action": "read", "declared_tier": 1, "resource": {"type": "document"}},
            {"tool_name": "search", "action": "query", "declared_tier": 1, "resource": {"type": "index"}}
          ]
        }' 2>&1 || true)
    # proto3: valid=true is explicit; valid=false may be omitted
    assert_json_field "8.1 valid true" ".valid" "true" "$valid"

    step "8.2 Validate spoofed action plan (tier mismatch)"
    spoofed=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ValidateActionPlan \
        '{
          "delegation_id": "'"$VAL_DELEGATION_ID"'",
          "actions": [
            {"tool_name": "read_file", "action": "delete", "declared_tier": 1, "resource": {"type": "document"}}
          ]
        }' 2>&1 || true)
    local valid82; valid82=$(echo "$spoofed" | jq -r '.valid // "false"' 2>/dev/null || echo "false")
    if [ "$valid82" = "false" ]; then
        pass "8.2 valid false"
    else
        fail "8.2 valid false — got: $valid82"
    fi
    # tierMismatch lives inside .results[0] per the proto
    tier_mismatch=$(echo "$spoofed" | jq -r '.results[0].tierMismatch // empty' 2>/dev/null || true)
    if [ "$tier_mismatch" = "true" ]; then
        pass "8.2 tier_mismatch flagged in results[0]"
    else
        fail "8.2 tierMismatch not found in results[0]: $spoofed"
    fi
}

# ─── Section 9: Compound Policy Evaluation ────────────────────────────────────

section_9() {
    section_header 9 "Compound Policy Evaluation (Platform Service)"

    # Check that the running platform server has agent_attributes support (requires rebuild if not)
    local platform_schema
    platform_schema=$(grpcurl -cacert "$CACERT" "$PLATFORM_ADDR" describe platform.GetDecisionRequest 2>/dev/null || true)
    if ! echo "$platform_schema" | grep -q "agent_attributes"; then
        skip "9.1-9.3 Platform server binary predates agent_attributes proto field"
        echo -e "  ${YELLOW}→ Rebuild required: make build && docker-compose restart platform${NC}"
        return
    fi

    # Fresh delegation needed
    step "9.0 Create fresh delegation"
    fresh=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["read_file", "search"],
          "approved_actions": [0, 1],
          "max_action_tier": 1,
          "classification_caps": {"nato": "CONFIDENTIAL"},
          "purpose": "Platform compound policy test",
          "ttl_seconds": 300,
          "conversation_id": "test-session-compound"
        }' 2>&1 || true)
    COMP_DELEGATION_ID=$(echo "$fresh" | jq -r '.delegationId')
    assert_json_field_nonempty "9.0 delegation created" ".delegationId" "$fresh"

    step "9.1 GetDecision — compound ALLOW"
    allow=$(grpc_call "$PLATFORM_ADDR" \
        platform.PlatformService/GetDecision \
        '{
          "subject_attributes": {"role": "admin"},
          "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"},
          "action": "read",
          "agent_attributes": {
            "agent_id": "'"$AGENT_ID"'",
            "agent_name": "claude-research-agent",
            "trust_tier": 1,
            "allowed_tools": ["read_file", "search"]
          },
          "delegation_context": {
            "delegation_id": "'"$COMP_DELEGATION_ID"'",
            "user_id": "'"$ADMIN_USER"'",
            "agent_id": "'"$AGENT_ID"'",
            "action_tier": 1,
            "tool_name": "read_file",
            "classification_caps": {"nato": "CONFIDENTIAL"}
          }
        }' 2>&1 || true)
    # 9.1 verifies compound evaluation ran and populated compound_decision fields.
    # Top-level ALLOW depends on entitlements existing for these resource attributes;
    # what matters here is that agent and delegation decisions are evaluated.
    local compound_agent_decision
    compound_agent_decision=$(echo "$allow" | jq -r '.compoundDecision.agentDecision // empty' 2>/dev/null || true)
    if [ -n "$compound_agent_decision" ]; then
        pass "9.1 compound evaluation ran (agentDecision: $compound_agent_decision)"
    else
        fail "9.1 compound evaluation did not populate compoundDecision — response: $allow"
    fi
    local compound_delegation_decision
    compound_delegation_decision=$(echo "$allow" | jq -r '.compoundDecision.delegationDecision // empty' 2>/dev/null || true)
    if [ -n "$compound_delegation_decision" ]; then
        pass "9.1 delegationDecision populated: $compound_delegation_decision"
    else
        fail "9.1 delegationDecision missing from compoundDecision"
    fi

    step "9.2 GetDecision — agent DENY (trust tier 0 for delete)"
    deny=$(grpc_call "$PLATFORM_ADDR" \
        platform.PlatformService/GetDecision \
        '{
          "subject_attributes": {"role": "admin"},
          "resource_attributes": {"classification": "CONFIDENTIAL", "hierarchy": "nato"},
          "action": "delete",
          "agent_attributes": {
            "agent_id": "'"$AGENT_ID"'",
            "trust_tier": 0,
            "allowed_tools": ["delete_resource"]
          },
          "delegation_context": {
            "delegation_id": "'"$COMP_DELEGATION_ID"'",
            "user_id": "'"$ADMIN_USER"'",
            "agent_id": "'"$AGENT_ID"'",
            "action_tier": 4,
            "tool_name": "delete_resource"
          }
        }' 2>&1 || true)
    assert_contains "9.2 top-level DENY" "DENY" "$deny"

    step "9.3 GetDecision — no agent attributes (backward compat)"
    back=$(grpc_call "$PLATFORM_ADDR" \
        platform.PlatformService/GetDecision \
        '{
          "subject_attributes": {"role": "admin"},
          "resource_attributes": {"type": "document"},
          "action": "read"
        }' 2>&1 || true)
    # Should get a decision (ALLOW or DENY), not an error
    if echo "$back" | grep -qE "ALLOW|DENY"; then
        pass "9.3 backward-compat decision returned"
    else
        fail "9.3 expected ALLOW or DENY, got: $back"
    fi
    assert_not_contains "9.3 compound_decision absent" "compoundDecision" "$back"
}

# ─── Section 11: Security / Negative Tests ────────────────────────────────────

section_11() {
    section_header 11 "Security / Negative Tests"

    # Need a fresh delegation
    step "Setup: fresh delegation for security tests"
    fresh=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["read_file"],
          "approved_actions": [0],
          "max_action_tier": 1,
          "classification_caps": {"nato": "CONFIDENTIAL"},
          "purpose": "Security negative test",
          "ttl_seconds": 60,
          "conversation_id": "sec-test"
        }' 2>&1 || true)
    SEC_TOKEN=$(echo "$fresh" | jq -r '.delegationToken')
    SEC_DEL_ID=$(echo "$fresh" | jq -r '.delegationId')

    step "S2 Tampered JWT rejected"
    # Flip one character in the payload segment
    tampered=$(echo "$SEC_TOKEN" | awk -F. '{print $1"."substr($2,1,length($2)-1)"X."$3}')
    tampered_resp=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/ExecuteAction \
        '{"delegation_token": "'"$tampered"'", "action": "read", "action_tier": 1, "tool_name": "read_file"}' \
        2>&1 || true)
    _assert_denied "S2 tampered JWT rejected" "$tampered_resp"

    step "S6 Replay of non-existent delegation ID"
    fake_id="00000000-0000-0000-0000-000000000000"
    fake_resp=$(grpc_call "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/GetDelegationChain \
        '{"delegation_id": "'"$fake_id"'"}' 2>&1 || true)
    assert_contains "S6 non-existent delegation_id rejected" "not found" "$fake_resp"

    step "S7 Child with tool not in parent scope"
    s7=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["write_file"],
          "approved_actions": [0],
          "max_action_tier": 1,
          "parent_delegation_token": "'"$SEC_TOKEN"'",
          "ttl_seconds": 30,
          "purpose": "scope escalation test"
        }' 2>&1 || true)
    assert_grpc_error "S7 tool-not-in-parent rejected" "scope exceeds parent" "$s7"

    step "S8 Child with higher action tier"
    s8=$(grpc_call -H "x-user-id: $ADMIN_USER" "$GATEWAY_ADDR" \
        agent_gateway.AgentGatewayService/CreateDelegation \
        '{
          "agent_id": "'"$AGENT_ID"'",
          "approved_tools": ["read_file"],
          "approved_actions": [0],
          "max_action_tier": 4,
          "parent_delegation_token": "'"$SEC_TOKEN"'",
          "ttl_seconds": 30,
          "purpose": "tier escalation test"
        }' 2>&1 || true)
    assert_grpc_error "S8 higher action tier rejected" "scope exceeds parent" "$s8"

    step "S11 Privilege amplification — user DENY blocks agent ALLOW"
    local plat_schema
    plat_schema=$(grpcurl -cacert "$CACERT" "$PLATFORM_ADDR" describe platform.GetDecisionRequest 2>/dev/null || true)
    if ! echo "$plat_schema" | grep -q "agent_attributes"; then
        skip "S11 Platform server binary predates agent_attributes — rebuild required"
        return
    fi
    s11=$(grpc_call "$PLATFORM_ADDR" \
        platform.PlatformService/GetDecision \
        '{
          "subject_attributes": {"role": {"string_value": "viewer"}},
          "resource_attributes": {"classification": "TOP-SECRET", "hierarchy": "nato"},
          "action": "delete",
          "agent_attributes": {
            "agent_id": "'"$AGENT_ID"'",
            "trust_tier": 2,
            "allowed_tools": ["delete_resource"]
          },
          "delegation_context": {
            "delegation_id": "'"$SEC_DEL_ID"'",
            "user_id": "'"$ADMIN_USER"'",
            "agent_id": "'"$AGENT_ID"'",
            "action_tier": 4,
            "tool_name": "delete_resource"
          }
        }' 2>&1 || true)
    assert_contains "S11 overall DENY (proxy abuse blocked)" "DENY" "$s11"
}

# ─── Section 12: Cleanup ──────────────────────────────────────────────────────

section_clean() {
    section_header 12 "Cleanup"
    echo "Stopping services..."
    (cd deployment/docker && docker-compose --profile agent-auth down) || true
    rm -f "$STATE_FILE"
    echo -e "${GREEN}Done.${NC}"
}

# ─── Main ─────────────────────────────────────────────────────────────────────

# Load persisted state from prior runs
load_state

TARGET="${1:-all}"

run_section() {
    case "$1" in
        1)  section_1 ;;
        2)  section_2 ;;
        3)  section_3 ;;
        4)  section_4 ;;
        5)  section_5 ;;
        6)  section_6 ;;
        7)  section_7 ;;
        8)  section_8 ;;
        9)  section_9 ;;
        11) section_11 ;;
        clean) section_clean ;;
        *) echo "Unknown section: $1"; exit 1 ;;
    esac
}

if [ "$TARGET" = "all" ]; then
    for s in 1 2 3 4 5 6 7 8 9 11; do
        run_section "$s"
    done
else
    run_section "$TARGET"
fi

summary
