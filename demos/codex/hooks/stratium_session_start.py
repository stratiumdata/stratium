#!/usr/bin/env python3
"""Stratium SessionStart hook for OpenAI Codex.

Bootstraps a delegation token on session start by calling the PAP REST API.
The token is written to /tmp/.stratium-delegation.json so PreToolUse hooks
can read it. If the delegation cannot be created, all Bash commands will be
denied (fail-closed).

No binary dependencies — uses only Python stdlib (urllib).

Required environment variables:
    STRATIUM_PAP_URL: PAP server URL (e.g., https://localhost:8090)
    STRATIUM_AGENT_ID: Registered agent UUID
    STRATIUM_AUTH_TOKEN: OIDC access token for the delegating user

Optional environment variables:
    STRATIUM_APPROVED_TOOLS: Comma-separated tool list (default: read_file,write_file,bash)
    STRATIUM_MAX_ACTION_TIER: Max action tier 0-4 (default: 2)
    STRATIUM_CLASSIFICATION_CAP: Classification cap (default: INTERNAL)
    STRATIUM_TTL_SECONDS: Delegation TTL in seconds (default: 1800)
"""
import json
import os
import ssl
import sys
import urllib.request

DELEGATION_FILE = "/tmp/.stratium-delegation.json"


def main():
    hook_input = json.load(sys.stdin)

    pap_url = os.environ.get("STRATIUM_PAP_URL", "")
    agent_id = os.environ.get("STRATIUM_AGENT_ID", "")
    auth_token = os.environ.get("STRATIUM_AUTH_TOKEN", "")

    # If a delegation token was pre-created (backward compat), just validate it
    existing_token = os.environ.get("STRATIUM_DELEGATION_TOKEN", "")
    if existing_token:
        _write_delegation_file(existing_token)
        _emit_context(
            "You are operating under Stratium zero-trust agent authorization. "
            "Every Bash command is checked against your delegation scope before execution. "
            "If a command is denied, you will receive a reason — do NOT retry the same action."
        )
        return

    # Bootstrap: create a delegation via PAP REST API
    if not pap_url or not agent_id or not auth_token:
        missing = []
        if not pap_url:
            missing.append("STRATIUM_PAP_URL")
        if not agent_id:
            missing.append("STRATIUM_AGENT_ID")
        if not auth_token:
            missing.append("STRATIUM_AUTH_TOKEN")
        _emit_context(
            f"WARNING: Cannot bootstrap Stratium delegation — missing env vars: {', '.join(missing)}. "
            "All Bash commands will be denied by PreToolUse hooks."
        )
        # Remove any stale delegation file
        _remove_delegation_file()
        return

    # Build delegation request
    approved_tools = os.environ.get("STRATIUM_APPROVED_TOOLS", "read_file,write_file,bash").split(",")
    max_tier = int(os.environ.get("STRATIUM_MAX_ACTION_TIER", "2"))
    cap = os.environ.get("STRATIUM_CLASSIFICATION_CAP", "INTERNAL")
    ttl = int(os.environ.get("STRATIUM_TTL_SECONDS", "1800"))

    body = json.dumps({
        "agent_id": agent_id,
        "approved_tools": [t.strip() for t in approved_tools],
        "max_action_tier": max_tier,
        "classification_caps": {"commercial": cap},
        "purpose": f"Codex session (auto-delegated)",
        "ttl_seconds": ttl,
    }).encode()

    # Create SSL context that skips verification (self-signed certs in dev)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            f"{pap_url}/api/v1/delegations",
            data=body,
            headers={
                "Authorization": f"Bearer {auth_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
            result = json.loads(resp.read())
    except Exception as e:
        _emit_context(
            f"WARNING: Failed to create Stratium delegation ({e}). "
            "All Bash commands will be denied (fail-closed)."
        )
        _remove_delegation_file()
        return

    delegation_token = result.get("delegation_token") or result.get("delegation_token")
    if not delegation_token:
        _emit_context(
            "WARNING: PAP returned no delegation token. "
            "All Bash commands will be denied (fail-closed)."
        )
        _remove_delegation_file()
        return

    # Write token to file for PreToolUse hook to read
    _write_delegation_file(delegation_token)

    expires = result.get("expires_at", "unknown")
    _emit_context(
        "You are operating under Stratium zero-trust agent authorization. "
        f"Delegation created (expires: {expires}). "
        "Every Bash command is checked against your delegation scope before execution. "
        "If a command is denied, you will receive a reason — do NOT retry the same action. "
        "Non-Bash actions (file writes, web searches) are not intercepted by hooks; "
        "exercise caution and stay within your delegation scope."
    )


def _write_delegation_file(token: str):
    """Write delegation token to a file readable by PreToolUse hook."""
    try:
        with open(DELEGATION_FILE, "w") as f:
            json.dump({"delegation_token": token}, f)
        os.chmod(DELEGATION_FILE, 0o600)
    except Exception:
        pass  # Best effort


def _remove_delegation_file():
    """Remove stale delegation file so PreToolUse denies everything."""
    try:
        os.remove(DELEGATION_FILE)
    except FileNotFoundError:
        pass


def _emit_context(message: str):
    """Emit hook output with additional context for the agent."""
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": message,
        }
    }, sys.stdout)


if __name__ == "__main__":
    main()
