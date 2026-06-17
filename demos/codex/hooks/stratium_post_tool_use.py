#!/usr/bin/env python3
"""Stratium PostToolUse hook for OpenAI Codex.

Fires after every Bash tool execution. Best-effort audit logging —
errors are silently ignored to avoid blocking the agent.

No binary dependencies — uses only Python stdlib.
"""
import json
import os
import sys


DELEGATION_FILE = "/tmp/.stratium-delegation.json"


def main():
    hook_input = json.load(sys.stdin)

    # Nothing to log if no delegation is active
    if not os.path.exists(DELEGATION_FILE):
        return

    # PostToolUse is best-effort — just log to stderr for now.
    # Future: call PAP audit endpoint.
    tool_name = hook_input.get("tool_name", "Bash")
    session_id = hook_input.get("session_id", "")

    # Log for observability (stderr goes to hook logs, not agent output)
    print(
        f"[stratium] PostToolUse: tool={tool_name} session={session_id}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
