#!/usr/bin/env python3
"""
Stratium Agent Authorization Demo
-----------------------------------
Demonstrates Zero-Trust authorization for AI agents using Claude's tool-use
API. Every tool call Claude makes is intercepted and checked against Stratium's
Agent Gateway before execution. Approved actions are ALLOWED; out-of-scope
actions are DENIED with a clear explanation returned to Claude.

Authorization flow per tool call:
  Claude decides to use tool
    → ExecuteAction on Agent Gateway (gRPC)
      → Agent Gateway validates delegation token + scope
        → Platform Service evaluates compound decision
          → ALLOW: tool executes, result returned to Claude
          → DENY:  error returned to Claude, tool blocked

Demo scenario:
  Agent scope: READ_ONLY (tier 1), tools: [list_files, read_file]
  Claude is asked to: read files AND write a report AND run tests
  Result: read actions ALLOWED, write/execute actions DENIED

Usage:
  export ANTHROPIC_API_KEY=sk-ant-...
  python demos/agent_auth_demo.py

Requirements:
  pip install anthropic
  # Stratium stack must be running: make docker-up
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

# ── Dependency check ──────────────────────────────────────────────────────────

try:
    import anthropic
except ImportError:
    print("\n  Missing dependency: pip install anthropic\n")
    sys.exit(1)

# ── Configuration ─────────────────────────────────────────────────────────────

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
PAP_URL      = os.environ.get("PAP_URL",      "https://localhost:8090")
GATEWAY_ADDR = os.environ.get("GATEWAY_ADDR", "localhost:50054")
CACERT       = os.environ.get("CACERT",       "config/examples/certs/ca.crt")
REALM        = "stratium"
ADMIN_USER   = "admin456"
ADMIN_PASS   = "admin123"
PAP_CLIENT   = "stratium-pap"
PAP_SECRET   = "stratium-pap-secret"

# Approved tools and their authorization parameters
TOOL_AUTH: dict[str, dict] = {
    "list_files":        {"action": "read",    "action_tier": 1, "in_scope": True},
    "read_file":         {"action": "read",    "action_tier": 1, "in_scope": True},
    "write_file":        {"action": "write",   "action_tier": 2, "in_scope": False},
    "run_shell_command": {"action": "execute", "action_tier": 4, "in_scope": False},
}

APPROVED_TOOLS = [name for name, meta in TOOL_AUTH.items() if meta["in_scope"]]
MAX_DELEGATION_TIER = 1  # READ_ONLY

ACTION_TIER_NAMES = {
    0: "REASONING",
    1: "READ_ONLY",
    2: "INTERNAL_MODIFY",
    3: "EXTERNAL_COMMS",
    4: "DESTRUCTIVE",
}

# ── ANSI colors ───────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"

# ── Terminal helpers ──────────────────────────────────────────────────────────

def banner() -> None:
    print(f"\n{BOLD}{CYAN}{'═' * 60}{NC}")
    print(f"{BOLD}{CYAN}   STRATIUM AGENT AUTHORIZATION DEMO{NC}")
    print(f"{BOLD}{CYAN}   Zero-Trust Access Control for AI Agents{NC}")
    print(f"{BOLD}{CYAN}{'═' * 60}{NC}\n")

def section(title: str) -> None:
    print(f"\n{BOLD}{YELLOW}▶  {title}{NC}")

def ok(msg: str) -> None:
    print(f"   {GREEN}✓{NC}  {msg}")

def fail(msg: str) -> None:
    print(f"   {RED}✗{NC}  {msg}")

def info(msg: str) -> None:
    print(f"   {DIM}→{NC}  {msg}")

def print_auth_box(
    tool_name: str,
    action_tier: int,
    authorized: bool,
    reason: str,
    in_scope: bool,
) -> None:
    tier_name = ACTION_TIER_NAMES.get(action_tier, f"TIER_{action_tier}")
    max_tier_name = ACTION_TIER_NAMES.get(MAX_DELEGATION_TIER, "READ_ONLY")
    width = 54

    def row(label: str, value: str, color: str = "") -> None:
        print(f"   │  {label:<18}{color}{value}{NC}")

    print(f"\n   {'─' * width}")
    print(f"   │  {BOLD}STRATIUM AUTHORIZATION CHECK{NC}")
    print(f"   │")
    row("Tool:",       f"{BOLD}{tool_name}{NC}")
    row("Action Tier:", f"{BOLD}{tier_name} ({action_tier}){NC}")
    row("Max Allowed:", f"{BOLD}{max_tier_name} ({MAX_DELEGATION_TIER}){NC}")
    if not in_scope:
        row("Scope:", "not in approved_tools", RED)
    elif action_tier > MAX_DELEGATION_TIER:
        row("Scope:", "tier exceeds delegation cap", RED)
    else:
        row("Scope:", "within delegation scope", GREEN)
    print(f"   │")
    if authorized:
        print(f"   │  Decision:         {GREEN}{BOLD}✅  ALLOW{NC}")
    else:
        if reason:
            row("Reason:", reason[:36], DIM)
        print(f"   │  Decision:         {RED}{BOLD}❌  DENY{NC}")
    print(f"   {'─' * width}")

# ── Stratium API calls ────────────────────────────────────────────────────────

def get_keycloak_token() -> str:
    """Obtain a user token from Keycloak via password grant."""
    payload = urllib.parse.urlencode({
        "grant_type":    "password",
        "client_id":     PAP_CLIENT,
        "client_secret": PAP_SECRET,
        "username":      ADMIN_USER,
        "password":      ADMIN_PASS,
    }).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())["access_token"]


def register_agent(token: str, name: str) -> tuple[str, str]:
    """Register a new agent with the PAP REST API. Returns (agent_id, client_id)."""
    payload = json.dumps({
        "name":             name,
        "trust_tier":       1,
        "provider":         "demo",
        "model_identifier": "claude-sonnet-4-6",
        "allowed_tools":    APPROVED_TOOLS,
    }).encode()

    result = subprocess.run(
        [
            "curl", "-sk", "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", f"Authorization: Bearer {token}",
            "-H", f"x-user-id: {ADMIN_USER}",
            "-d", payload.decode(),
            f"{PAP_URL}/api/v1/agents",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    resp = json.loads(result.stdout)
    if "error" in resp:
        raise RuntimeError(resp["error"])
    return resp["agent_id"], resp.get("client_id", "")


def create_delegation(token: str, agent_id: str, conversation_id: str) -> tuple[str, str]:
    """Create a delegation via the Agent Gateway gRPC. Returns (token, delegation_id)."""
    req_data = json.dumps({
        "agent_id":       agent_id,
        "approved_tools": APPROVED_TOOLS,
        "max_action_tier": MAX_DELEGATION_TIER,
        "purpose":        "AI code review — read-only scope",
        "ttl_seconds":    900,
        "conversation_id": conversation_id,
    })
    result = subprocess.run(
        [
            "grpcurl", "-cacert", CACERT,
            "-H", f"authorization: Bearer {token}",
            "-H", f"x-user-id: {ADMIN_USER}",
            "-d", req_data,
            GATEWAY_ADDR,
            "agent_gateway.AgentGatewayService/CreateDelegation",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(result.stderr.strip() or "grpcurl failed")
    resp = json.loads(result.stdout)
    return resp["delegationToken"], resp["delegationId"]


def execute_action(
    delegation_token: str,
    tool_name: str,
    action: str,
    action_tier: int,
    resource_attrs: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """
    Call Agent Gateway ExecuteAction. Returns (authorized, reason).
    grpcurl errors (token invalid, revoked, etc.) are treated as DENY.
    """
    req_data = json.dumps({
        "delegation_token":  delegation_token,
        "action":            action,
        "tool_name":         tool_name,
        "action_tier":       action_tier,
        "resource_attributes": resource_attrs or {},
    })
    result = subprocess.run(
        [
            "grpcurl", "-cacert", CACERT,
            "-d", req_data,
            GATEWAY_ADDR,
            "agent_gateway.AgentGatewayService/ExecuteAction",
        ],
        capture_output=True,
        text=True,
    )

    raw = result.stdout.strip()
    err = result.stderr.strip()

    # grpcurl errors start with "ERROR:"
    if "ERROR:" in (raw + err):
        combined = raw + "\n" + err
        msg = ""
        for line in combined.splitlines():
            if "Message:" in line:
                msg = line.split("Message:", 1)[1].strip()
                break
        return False, msg or "gRPC error"

    resp = json.loads(raw) if raw else {}
    return resp.get("authorized", False), resp.get("error", "")


def delete_agent(token: str, agent_id: str) -> None:
    """Clean up the demo agent from the PAP."""
    subprocess.run(
        [
            "curl", "-sk", "-X", "DELETE",
            "-H", f"Authorization: Bearer {token}",
            f"{PAP_URL}/api/v1/agents/{agent_id}",
        ],
        capture_output=True,
    )

# ── Simulated tool execution ──────────────────────────────────────────────────

def _simulate_list_files(inp: dict) -> str:
    path = inp.get("path", ".")
    return (
        f"Files in {path}:\n"
        "  auth_module.py       (3.2 KB)\n"
        "  policy_engine.go     (8.1 KB)\n"
        "  access_control.py    (5.4 KB)\n"
        "  jwt_validator.go     (2.8 KB)\n"
        "  README.md            (1.1 KB)"
    )

def _simulate_read_file(inp: dict) -> str:
    path = inp.get("path", "unknown")
    classification = inp.get("classification", "UNCLASSIFIED")
    return (
        f"# {path}  [{classification}]\n\n"
        "def authenticate(token: str) -> User:\n"
        "    \"\"\"Validates JWT and returns the authenticated user.\"\"\"\n"
        "    payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])\n"
        "    # WARNING: SECRET_KEY is hardcoded — should use env var\n"
        "    return User.from_payload(payload)\n\n"
        "def authorize(user: User, resource: str, action: str) -> bool:\n"
        "    \"\"\"ABAC check against policy engine.\"\"\"\n"
        "    # TODO: validate against classification caps before allowing read\n"
        "    return policy_engine.evaluate(user.attributes, resource, action)\n"
    )

TOOL_SIMULATORS = {
    "list_files":        _simulate_list_files,
    "read_file":         _simulate_read_file,
    "write_file":        lambda inp: "BLOCKED — authorization denied",
    "run_shell_command": lambda inp: "BLOCKED — authorization denied",
}

# ── Core demo logic ───────────────────────────────────────────────────────────

def handle_tool_call(
    tool_name: str,
    tool_input: dict,
    delegation_token: str,
) -> dict:
    """Intercept a Claude tool call, check authorization, execute if allowed."""
    auth = TOOL_AUTH.get(tool_name, {"action": "execute", "action_tier": 4, "in_scope": False})

    print(f"\n   {BOLD}Claude wants to use: {CYAN}{tool_name}{NC}")
    info("Calling Stratium ExecuteAction...")

    # Build resource attributes from tool input when classification is present
    resource_attrs: dict[str, str] = {}
    if "classification" in tool_input:
        resource_attrs["classification"] = tool_input["classification"]
        resource_attrs["hierarchy"] = "nato"

    authorized, reason = execute_action(
        delegation_token,
        tool_name,
        auth["action"],
        auth["action_tier"],
        resource_attrs,
    )

    print_auth_box(tool_name, auth["action_tier"], authorized, reason, auth["in_scope"])

    if authorized:
        ok("Tool executed")
        result = TOOL_SIMULATORS.get(tool_name, lambda _: "OK")(tool_input)
        return {"result": result}
    else:
        fail("Tool blocked by Stratium")
        denied_msg = reason or "action not permitted by delegation scope"
        return {"error": f"Authorization DENIED by Stratium: {denied_msg}"}


def run_claude_session(delegation_token: str) -> None:
    """Run an agentic Claude conversation with Stratium-enforced tool authorization."""
    section("Starting Claude Conversation (claude-sonnet-4-6)")

    if not os.environ.get("ANTHROPIC_API_KEY"):
        fail("ANTHROPIC_API_KEY is not set")
        info("export ANTHROPIC_API_KEY=sk-ant-...")
        return

    # Tool schemas for Claude's tool-use API
    claude_tools = [
        {
            "name": "list_files",
            "description": "List files in a directory on the codebase.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "read_file",
            "description": "Read the source code of a file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "classification": {
                        "type": "string",
                        "description": "Data classification level (e.g. CONFIDENTIAL)",
                        "default": "UNCLASSIFIED",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "write_file",
            "description": "Write or overwrite a file with new content.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string", "description": "Destination file path"},
                    "content": {"type": "string", "description": "File content to write"},
                },
                "required": ["path", "content"],
            },
        },
        {
            "name": "run_shell_command",
            "description": "Execute a shell command and return output.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run"},
                },
                "required": ["command"],
            },
        },
    ]

    user_prompt = (
        "You are a security code reviewer with read-only access to this codebase.\n\n"
        "Please do the following:\n"
        "1. List the files in /security/auth\n"
        "2. Read auth_module.py (classification: CONFIDENTIAL) and identify any security issues\n"
        "3. Write a security report to /reports/security_review.md with your findings\n"
        "4. Run the test suite with: python -m pytest tests/auth/ -v\n\n"
        "Complete all four steps."
    )

    print(f"\n   {BOLD}User prompt:{NC}")
    for line in user_prompt.splitlines():
        print(f"   {DIM}{line}{NC}")
    print()

    client = anthropic.Anthropic()
    messages: list[dict] = [{"role": "user", "content": user_prompt}]

    # Agentic loop — continue until Claude stops using tools
    while True:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1024,
            tools=claude_tools,
            messages=messages,
        )

        # Append assistant turn to conversation history
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn":
            print(f"\n   {BOLD}Claude's final response:{NC}")
            for block in response.content:
                if hasattr(block, "text") and block.text:
                    for line in block.text.splitlines():
                        print(f"   {line}")
            break

        if response.stop_reason != "tool_use":
            break

        # Process each tool call through Stratium authorization
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result = handle_tool_call(block.name, block.input, delegation_token)
                tool_results.append(
                    {
                        "type":        "tool_result",
                        "tool_use_id": block.id,
                        "content":     json.dumps(result),
                    }
                )

        messages.append({"role": "user", "content": tool_results})


def print_summary() -> None:
    """Print the final authorization summary."""
    print(f"\n{BOLD}{CYAN}{'═' * 60}{NC}")
    print(f"{BOLD}{CYAN}   AUTHORIZATION SUMMARY{NC}")
    print(f"{BOLD}{CYAN}{'═' * 60}{NC}")
    print(f"   Delegation scope: READ_ONLY (tier ≤ 1)")
    print(f"   Approved tools:   {', '.join(APPROVED_TOOLS)}\n")
    print(f"   {GREEN}✅  list_files        → ALLOW  (READ_ONLY, in scope){NC}")
    print(f"   {GREEN}✅  read_file          → ALLOW  (READ_ONLY, in scope){NC}")
    print(f"   {RED}❌  write_file         → DENY   (INTERNAL_MODIFY, tier > max){NC}")
    print(f"   {RED}❌  run_shell_command  → DENY   (DESTRUCTIVE, tier > max){NC}")
    print(f"\n   {DIM}Powered by Stratium Zero-Trust Agent Authorization{NC}")
    print(f"{BOLD}{CYAN}{'═' * 60}{NC}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    banner()

    # ── 1. Keycloak auth ──────────────────────────────────────────────────────
    section("Authenticating with Keycloak")
    try:
        token = get_keycloak_token()
        ok(f"Token obtained for user: {BOLD}{ADMIN_USER}{NC}")
    except Exception as exc:
        fail(f"Keycloak auth failed: {exc}")
        info("Is the Stratium stack running?  →  make docker-up")
        sys.exit(1)

    # ── 2. Register agent ─────────────────────────────────────────────────────
    section("Registering AI Agent with Stratium PAP")
    agent_name = f"claude-code-reviewer-{uuid.uuid4().hex[:6]}"
    try:
        agent_id, client_id = register_agent(token, agent_name)
        ok(f"Agent registered:  {BOLD}{client_id}{NC}")
        ok(f"Agent UUID:        {DIM}{agent_id}{NC}")
        ok(f"Approved tools:    {GREEN}{', '.join(APPROVED_TOOLS)}{NC}")
        ok(f"Max action tier:   {GREEN}READ_ONLY (1){NC}")
    except Exception as exc:
        fail(f"Agent registration failed: {exc}")
        sys.exit(1)

    # ── 3. Create delegation ──────────────────────────────────────────────────
    section("Creating Delegation Token (user → agent)")
    conv_id = f"demo-{uuid.uuid4().hex[:8]}"
    try:
        delegation_token, delegation_id = create_delegation(token, agent_id, conv_id)
        ok(f"Delegation ID:     {DIM}{delegation_id}{NC}")
        ok(f"Scope:             READ_ONLY, tools: {', '.join(APPROVED_TOOLS)}")
        ok(f"Conversation:      {DIM}{conv_id}{NC}")
        info(f"Token (preview):   {DIM}{delegation_token[:48]}…{NC}")
    except Exception as exc:
        fail(f"Delegation creation failed: {exc}")
        delete_agent(token, agent_id)
        sys.exit(1)

    # ── 4. Run Claude conversation with Stratium-enforced tool use ────────────
    try:
        run_claude_session(delegation_token)
    except (anthropic.APIError, anthropic.APIStatusError) as exc:
        fail(f"Anthropic API error: {exc}")
        info("Check your ANTHROPIC_API_KEY environment variable")
    except TypeError as exc:
        if "api_key" in str(exc) or "authentication" in str(exc).lower():
            fail("ANTHROPIC_API_KEY not set")
            info("export ANTHROPIC_API_KEY=sk-ant-...")
        else:
            raise
    finally:
        # ── 5. Cleanup ────────────────────────────────────────────────────────
        section("Cleaning Up")
        delete_agent(token, agent_id)
        ok(f"Demo agent deleted: {DIM}{client_id}{NC}")

    print_summary()


if __name__ == "__main__":
    main()
