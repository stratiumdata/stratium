#!/usr/bin/env python3
"""Stratium PreToolUse hook for OpenAI Codex.

Intercepts every Bash tool call, classifies the command into a Stratium action
tier, and calls PAP REST API to authorize the action. Returns deny/allow to
the Codex runtime.

No binary dependencies — uses only Python stdlib (urllib).
Delegation token is read from /tmp/.stratium-delegation.json, written by
the SessionStart hook. If the file doesn't exist, hooks never ran → deny all.

Required environment variables:
    STRATIUM_PAP_URL: PAP server URL (e.g., https://localhost:8090)

The delegation token comes from the file, NOT from an env var.
"""
import json
import os
import ssl
import sys
import urllib.request

DELEGATION_FILE = "/tmp/.stratium-delegation.json"


# Patterns for classifying shell commands into action tiers.
# Mirrors the classification in demos/mcp/hooks/pre-tool-use.sh.
DESTRUCTIVE_PATTERNS = [
    "rm -rf", "rm -fr", "drop table", "drop database", "dropdb",
    "truncate", "mkfs", "dd if=",
]

EXTERNAL_PATTERNS = [
    "curl ", "wget ", "ssh ", "scp ", "rsync ", "nc ", "ncat ",
    "git push", "docker push", "npm publish", "aws ", "gcloud ",
]

WRITE_PATTERNS = [
    "tee ", "> ", ">> ", "mv ", "cp ", "mkdir ", "chmod ", "chown ",
    "sed -i", "git commit", "git add", "pip install", "npm install",
    "apt install", "apt-get install", "brew install",
]

READ_PATTERNS = [
    "cat ", "head ", "tail ", "less ", "more ", "grep ", "rg ",
    "find ", "ls ", "wc ", "file ", "stat ",
    "git log", "git status", "git diff", "git show", "git branch",
    "echo ", "printf ", "pwd", "whoami", "id ", "hostname",
    "env", "printenv", "which ", "type ",
]


def classify_command(command: str) -> tuple:
    """Classify a shell command into (tool_name, action_name, action_tier).

    Returns the normalized Stratium tool name (matching agent allowed_tools),
    the action string, and the ActionTier integer.

    Returns:
        Tuple of (tool_name: str, action: str, tier: int)
    """
    cmd_lower = command.strip().lower()

    # Tier 4: Destructive
    if any(p in cmd_lower for p in DESTRUCTIVE_PATTERNS):
        return "bash", "execute", 4

    # Tier 3: External communications
    if any(p in cmd_lower for p in EXTERNAL_PATTERNS):
        return "bash", "send", 3

    # Tier 2: Internal modifications — normalize to specific tool
    if any(p in cmd_lower for p in WRITE_PATTERNS):
        return "write_file", "write", 2

    # Tier 1: Read-only — normalize to specific tool
    if any(p in cmd_lower for p in READ_PATTERNS):
        return "read_file", "read", 1

    # Default: Tier 2 (internal modify) as bash
    return "bash", "execute", 2


def _load_delegation_token() -> str:
    """Load delegation token from file written by SessionStart hook.
    Returns empty string if file doesn't exist (hooks never bootstrapped)."""
    try:
        with open(DELEGATION_FILE) as f:
            data = json.load(f)
            return data.get("delegation_token", "")
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return ""


def main():
    hook_input = json.load(sys.stdin)
    pap_url = os.environ.get("STRATIUM_PAP_URL", "")

    # Load delegation token from file (bootstrapped by SessionStart)
    # Fall back to env var for backward compatibility
    token = _load_delegation_token() or os.environ.get("STRATIUM_DELEGATION_TOKEN", "")

    # Fail closed: no token → SessionStart never ran or failed → deny all
    if not token:
        _deny(
            "No Stratium delegation token. SessionStart hook may not have run. "
            "All actions denied (fail-closed)."
        )
        return

    # Fail closed: no PAP URL → can't check authorization
    if not pap_url:
        _deny("STRATIUM_PAP_URL not configured. Cannot check authorization.")
        return

    # Extract command from hook input
    tool_input = hook_input.get("tool_input", {})
    command = tool_input.get("command", "")

    # Classify the command and normalize to Stratium tool name
    tool_name, action, action_tier = classify_command(command)

    # Call PAP REST API to check authorization
    body = json.dumps({
        "delegation_token": token,
        "tool_name": tool_name,
        "action": action,
        "action_tier": action_tier,
        "resource_id": command[:200],
    }).encode()

    # SSL context (skip verification for self-signed certs)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            f"{pap_url}/api/v1/actions/check",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            decision = json.loads(resp.read())
    except Exception as e:
        # Fail closed on any error
        _deny(f"Stratium authorization check failed: {e}")
        return

    if decision.get("authorized"):
        # Codex-compatible allow: silent exit. Codex rejects
        # `permissionDecision: "allow"` as an unsupported value — its schema
        # only recognizes "deny". Empty output = proceed. (Claude Code's
        # schema does accept "allow", but we target the narrower contract
        # so the same hook works for both harnesses.)
        return
    else:
        # Extract the most relevant reason
        dec = decision.get("decision", {})
        reason = (
            dec.get("delegation_reason")
            or dec.get("agent_reason")
            or dec.get("user_reason")
            or decision.get("error")
            or "Authorization denied"
        )
        _deny(f"Stratium DENY: {reason}")


def _deny(reason: str):
    """Emit a deny decision."""
    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, sys.stdout)


if __name__ == "__main__":
    main()
