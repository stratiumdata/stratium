#!/usr/bin/env python3
"""Tests for Stratium Codex hook scripts.

Tests the command classifier, delegation file handling, and hook JSON output
format without requiring a running PAP or Agent Gateway.
"""
import json
import os
import subprocess
import sys
import tempfile

HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
DELEGATION_FILE = "/tmp/.stratium-delegation.json"


def test_classify_command():
    """Test the command classifier in stratium_pre_tool_use.py."""
    sys.path.insert(0, HOOKS_DIR)
    from stratium_pre_tool_use import classify_command

    tests = [
        # (command, expected_tool, expected_action, expected_tier)
        ("cat /etc/passwd", "read_file", "read", 1),
        ("ls -la /tmp", "read_file", "read", 1),
        ("grep -r TODO src/", "read_file", "read", 1),
        ("git log --oneline", "read_file", "read", 1),
        ("git status", "read_file", "read", 1),
        ("echo hello", "read_file", "read", 1),
        ("pwd", "read_file", "read", 1),

        ("tee output.txt", "write_file", "write", 2),
        ("mv old.txt new.txt", "write_file", "write", 2),
        ("cp src.txt dst.txt", "write_file", "write", 2),
        ("mkdir -p new_dir", "write_file", "write", 2),
        ("sed -i 's/old/new/' file.txt", "write_file", "write", 2),
        ("git commit -m 'fix'", "write_file", "write", 2),
        ("npm install express", "write_file", "write", 2),

        ("curl https://api.example.com", "bash", "send", 3),
        ("wget https://example.com/file", "bash", "send", 3),
        ("ssh user@host", "bash", "send", 3),
        ("git push origin main", "bash", "send", 3),
        ("npm publish", "bash", "send", 3),

        ("rm -rf /tmp/test", "bash", "execute", 4),
        ("DROP TABLE users", "bash", "execute", 4),
        ("dd if=/dev/zero of=/dev/sda", "bash", "execute", 4),

        # Unrecognized commands default to tier 2
        ("custom-binary --flag", "bash", "execute", 2),
        ("make build", "bash", "execute", 2),
    ]

    passed = 0
    failed = 0
    for command, expected_tool, expected_action, expected_tier in tests:
        tool, action, tier = classify_command(command)
        if tool == expected_tool and action == expected_action and tier == expected_tier:
            passed += 1
        else:
            print(f"  FAIL: classify_command({command!r})")
            print(f"    got:  ({tool!r}, {action!r}, {tier})")
            print(f"    want: ({expected_tool!r}, {expected_action!r}, {expected_tier})")
            failed += 1

    print(f"classify_command: {passed} passed, {failed} failed")
    return failed == 0


def test_pre_tool_use_no_token():
    """Test PreToolUse hook denies when no delegation token exists (file or env)."""
    # Ensure no delegation file exists
    _remove_delegation_file()

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_pre_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        capture_output=True, text=True,
        env={**os.environ, "STRATIUM_DELEGATION_TOKEN": "", "STRATIUM_PAP_URL": ""},
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert hook_output["permissionDecision"] == "deny", f"Expected deny, got {hook_output['permissionDecision']}"
    assert "No Stratium delegation token" in hook_output["permissionDecisionReason"]
    print("pre_tool_use_no_token: PASS")
    return True


def test_pre_tool_use_no_pap_url():
    """Test PreToolUse hook denies when PAP URL is missing (even with token file)."""
    _write_delegation_file("test-jwt")

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_pre_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        capture_output=True, text=True,
        env={**os.environ, "STRATIUM_PAP_URL": "", "STRATIUM_DELEGATION_TOKEN": ""},
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert hook_output["permissionDecision"] == "deny", f"Expected deny, got {hook_output['permissionDecision']}"
    assert "STRATIUM_PAP_URL" in hook_output["permissionDecisionReason"]
    print("pre_tool_use_no_pap_url: PASS")
    _remove_delegation_file()
    return True


def test_pre_tool_use_unreachable_pap():
    """Test PreToolUse hook denies when PAP is unreachable (fail-closed)."""
    _write_delegation_file("test-jwt")

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_pre_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        capture_output=True, text=True,
        env={
            **os.environ,
            "STRATIUM_PAP_URL": "https://localhost:99999",
            "STRATIUM_DELEGATION_TOKEN": "",
        },
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert hook_output["permissionDecision"] == "deny", f"Expected deny, got {hook_output['permissionDecision']}"
    assert "failed" in hook_output["permissionDecisionReason"].lower()
    print("pre_tool_use_unreachable_pap: PASS")
    _remove_delegation_file()
    return True


def test_session_start_no_config():
    """Test SessionStart hook warns when no env vars are set."""
    _remove_delegation_file()

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_session_start.py")],
        input=json.dumps({"source": "startup"}),
        capture_output=True, text=True,
        env={
            **os.environ,
            "STRATIUM_PAP_URL": "",
            "STRATIUM_AGENT_ID": "",
            "STRATIUM_AUTH_TOKEN": "",
            "STRATIUM_DELEGATION_TOKEN": "",
        },
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert "WARNING" in hook_output["additionalContext"]
    assert "missing env vars" in hook_output["additionalContext"]
    print("session_start_no_config: PASS")
    return True


def test_session_start_with_existing_token():
    """Test SessionStart hook uses pre-created token when STRATIUM_DELEGATION_TOKEN is set."""
    _remove_delegation_file()

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_session_start.py")],
        input=json.dumps({"source": "startup"}),
        capture_output=True, text=True,
        env={
            **os.environ,
            "STRATIUM_DELEGATION_TOKEN": "pre-created-jwt",
            "STRATIUM_PAP_URL": "",
            "STRATIUM_AGENT_ID": "",
            "STRATIUM_AUTH_TOKEN": "",
        },
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert "zero-trust" in hook_output["additionalContext"].lower()

    # Verify token was written to file
    assert os.path.exists(DELEGATION_FILE), "Delegation file should exist"
    with open(DELEGATION_FILE) as f:
        data = json.load(f)
    assert data["delegation_token"] == "pre-created-jwt"

    print("session_start_with_existing_token: PASS")
    _remove_delegation_file()
    return True


def test_delegation_file_creates_authorization():
    """Test that PreToolUse reads token from file written by SessionStart."""
    # Simulate SessionStart writing a token
    _write_delegation_file("file-based-jwt")

    # PreToolUse should find it and try to check (will fail on unreachable PAP)
    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_pre_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        capture_output=True, text=True,
        env={
            **os.environ,
            "STRATIUM_PAP_URL": "https://localhost:99999",
            "STRATIUM_DELEGATION_TOKEN": "",  # No env var — must use file
        },
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    # Should deny because PAP is unreachable, but the key point is it TRIED
    # (meaning it found the token from the file, not from env var)
    assert hook_output["permissionDecision"] == "deny"
    assert "failed" in hook_output["permissionDecisionReason"].lower()

    print("delegation_file_creates_authorization: PASS")
    _remove_delegation_file()
    return True


def test_no_delegation_file_denies_all():
    """Test that PreToolUse denies everything when delegation file doesn't exist."""
    _remove_delegation_file()

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_pre_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
        capture_output=True, text=True,
        env={
            **os.environ,
            "STRATIUM_PAP_URL": "https://localhost:8090",
            "STRATIUM_DELEGATION_TOKEN": "",  # No env var either
        },
    )
    output = json.loads(result.stdout)
    hook_output = output["hookSpecificOutput"]

    assert hook_output["permissionDecision"] == "deny"
    assert "No Stratium delegation token" in hook_output["permissionDecisionReason"]

    print("no_delegation_file_denies_all: PASS")
    return True


def test_post_tool_use_silent():
    """Test PostToolUse hook is silent when no delegation file exists."""
    _remove_delegation_file()

    result = subprocess.run(
        [sys.executable, os.path.join(HOOKS_DIR, "stratium_post_tool_use.py")],
        input=json.dumps({"tool_name": "Bash", "tool_response": "hello world"}),
        capture_output=True, text=True,
    )
    assert result.stdout.strip() == "", f"Expected empty output, got {result.stdout!r}"
    assert result.returncode == 0
    print("post_tool_use_silent: PASS")
    return True


# --- Helpers ---

def _write_delegation_file(token: str):
    with open(DELEGATION_FILE, "w") as f:
        json.dump({"delegation_token": token}, f)

def _remove_delegation_file():
    try:
        os.remove(DELEGATION_FILE)
    except FileNotFoundError:
        pass


if __name__ == "__main__":
    print("Running Stratium Codex hook tests...\n")

    all_passed = True
    all_passed &= test_classify_command()
    all_passed &= test_pre_tool_use_no_token()
    all_passed &= test_pre_tool_use_no_pap_url()
    all_passed &= test_pre_tool_use_unreachable_pap()
    all_passed &= test_session_start_no_config()
    all_passed &= test_session_start_with_existing_token()
    all_passed &= test_delegation_file_creates_authorization()
    all_passed &= test_no_delegation_file_denies_all()
    all_passed &= test_post_tool_use_silent()

    # Cleanup
    _remove_delegation_file()

    print()
    if all_passed:
        print("All tests passed!")
        sys.exit(0)
    else:
        print("Some tests FAILED!")
        sys.exit(1)
