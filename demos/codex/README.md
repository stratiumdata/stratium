# Stratium Codex Hooks

Codex hook scripts that enforce Stratium agent authorization on OpenAI Codex sessions. This is the Codex equivalent of `demos/mcp/hooks/` for Claude Code.

## Architecture

```
Codex → PreToolUse hook → stratium-mcp --mode=check → Agent Gateway → ALLOW/DENY
```

The hooks use the same `stratium-mcp` binary that powers the Claude Code and Claude Desktop integrations. The `--mode=check` flag runs a single-shot authorization check (no MCP handshake, no session loop).

## Setup

### 1. Build the MCP binary

```bash
make build-mcp
```

### 2. Copy hooks to your repo

```bash
# Option A: Repo-level (recommended — enforced for all Codex sessions on this repo)
cp demos/codex/hooks.json <your-repo>/.codex/hooks.json
cp -r demos/codex/hooks/ <your-repo>/.codex/hooks/
chmod +x <your-repo>/.codex/hooks/*.py

# Option B: User-level (applies to all Codex sessions)
cp demos/codex/hooks.json ~/.codex/hooks.json
mkdir -p ~/.codex/hooks/
cp demos/codex/hooks/*.py ~/.codex/hooks/
chmod +x ~/.codex/hooks/*.py
```

### 3. Set environment variables in your Codex task config

```bash
STRATIUM_DELEGATION_TOKEN=<jwt>           # Created via PAP or stratium-mcp
STRATIUM_MCP_BIN=/path/to/stratium-mcp    # Path to binary in sandbox
STRATIUM_GATEWAY_ADDRESS=localhost:50054   # Agent Gateway address
STRATIUM_TLS_CA=/path/to/ca.crt           # TLS CA cert (optional)
```

## Hook Scripts

| Script | Event | Purpose |
|--------|-------|---------|
| `stratium_session_start.py` | `SessionStart` | Validates delegation token, injects auth context |
| `stratium_pre_tool_use.py` | `PreToolUse` (Bash) | Classifies command, calls Gateway, returns allow/deny |
| `stratium_post_tool_use.py` | `PostToolUse` (Bash) | Logs action result to audit trail (best-effort) |

## Command Classification

The `PreToolUse` hook classifies Bash commands into Stratium action tiers:

| Tier | Action | Example Commands |
|------|--------|-----------------|
| 4 — Destructive | `execute` | `rm -rf`, `DROP TABLE`, `dd if=` |
| 3 — External comms | `send` | `curl`, `wget`, `ssh`, `git push` |
| 2 — Internal modify | `write` | `tee`, `>`, `mv`, `cp`, `sed -i` |
| 1 — Read-only | `read` | `cat`, `grep`, `ls`, `git log` |
| 2 — Default | `execute` | Unrecognized commands |

## Limitations

Codex hooks currently **only intercept the Bash tool**. Non-Bash tools (Write, WebSearch) are not intercepted. See the PRD (`docs/PRD_OPENAI_AGENT_AUTHORIZATION.md`) for defense-in-depth mitigations.

## Comparison with Claude Code Hooks

| Aspect | Claude Code (`demos/mcp/hooks/`) | Codex (`demos/codex/hooks/`) |
|--------|----------------------------------|------------------------------|
| Language | Bash (uses `grpcurl`) | Python (uses `stratium-mcp --mode=check`) |
| Coverage | All tools | Bash only |
| Deny format | `exit 2` + JSON reason | JSON `{"permissionDecision":"deny"}` |
| Fail behavior | Fail-open (demo) | **Fail-closed** (production) |
| Gateway access | Direct gRPC via `grpcurl` | Via `stratium-mcp` subprocess |
