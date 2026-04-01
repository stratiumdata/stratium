# @stratium/claude-hooks

Zero-Trust authorization hooks for Claude Code — enforces Stratium agent delegation policies on every tool call.

## How It Works

Once installed, every Claude Code session on a developer's machine is automatically:

- **Identified** — the session creates a per-user delegation token scoped to the project's CLAUDE.md policy
- **Enforced** — every tool call Claude attempts is checked against Stratium's Agent Gateway before execution
- **Audited** — all decisions (ALLOW and DENY) are recorded in `~/.claude/stratium-audit.jsonl`

No code changes are required in any project. Admins push configuration; developers open Claude Code as normal.

## Installation

### Self-Service

```bash
npm install -g @stratium/claude-hooks
stratium-hooks configure --gateway stratium.corp.com:50054
stratium-hooks login
```

### MDM (Jamf / Intune)

```bash
# Deploy via Jamf Policy or Intune Remediation Script
STRATIUM_GATEWAY=stratium.corp.com:50054 \
STRATIUM_PAP=https://stratium.corp.com:8090 \
STRATIUM_KEYCLOAK=https://keycloak.corp.com \
  ./node_modules/.bin/stratium-hooks configure --silent
```

See `scripts/install-hooks.sh` for the full MDM deployment script.

## Prerequisites

- Node.js 18+
- [`grpcurl`](https://github.com/fullstorydev/grpcurl) on PATH (for Agent Gateway calls)
- `curl` on PATH (for Keycloak + PAP REST calls)
- Running Stratium instance (Agent Gateway + PAP + Keycloak)

## Per-Project Configuration (CLAUDE.md)

Add a `stratium:` block to your project's `CLAUDE.md` to define the authorization scope:

```markdown
## Stratium Authorization

stratium:
  enabled: true
  agent_name: claude-code
  max_action_tier: READ_ONLY
  approved_tools:
    - read_file
    - list_files
    - grep_search
    - web_search
  on_unavailable: fail_closed
  purpose: "Development work on my-project"
```

If no `stratium:` block is present, the machine-level defaults from `~/.claude/stratium.json` apply.

### max_action_tier values

| Value | Tier | What it allows |
|-------|------|----------------|
| `REASONING` | 0 | No tool calls at all |
| `READ_ONLY` | 1 | read_file, list_files, grep, web_fetch, web_search |
| `INTERNAL_MODIFY` | 2 | write_file, edit_file, bash (non-network), agent spawning |
| `EXTERNAL_COMMS` | 3 | bash with curl/wget/ssh/git push, cloud CLIs |
| `DESTRUCTIVE` | 4 | rm -rf, drop tables, other irreversible operations |

### Per-tool tier overrides

```markdown
stratium:
  max_action_tier: READ_ONLY
  tool_tiers:
    Bash: INTERNAL_MODIFY   # allow bash up to tier 2 even though default cap is 1
```

## Machine Configuration (~/.claude/stratium.json)

Created by `stratium-hooks configure`:

```json
{
  "gateway": "stratium.corp.com:50054",
  "pap_url": "https://stratium.corp.com:8090",
  "keycloak_url": "https://keycloak.corp.com",
  "realm": "corp",
  "client_id": "claude-code",
  "cacert": "/etc/stratium/certs/ca.crt",
  "default_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "on_unavailable": "fail_closed"
  }
}
```

## CLI Reference

```
stratium-hooks configure --gateway <host:port> [options]
stratium-hooks status
stratium-hooks login [--user <username>]
stratium-hooks logout
stratium-hooks ping
stratium-hooks scope
stratium-hooks version
```

### configure options

| Flag | Description | Default |
|------|-------------|---------|
| `--gateway <host:port>` | Agent Gateway address | required |
| `--pap-url <url>` | PAP REST API URL | derived from gateway |
| `--keycloak <url>` | Keycloak URL | derived from gateway |
| `--realm <realm>` | Keycloak realm | `master` |
| `--client-id <id>` | OAuth client ID | `claude-code` |
| `--cacert <path>` | CA certificate for TLS | none |
| `--fail-closed` | Block all tools if Stratium unreachable | default |
| `--fail-open` | Allow all tools if Stratium unreachable | |
| `--delegation-ttl <secs>` | Delegation TTL | `14400` (4h) |
| `--silent` | Suppress output (for MDM scripts) | |

## Hook Architecture

Three hooks are registered in `~/.claude/settings.json`:

| Hook | Script | Trigger | Behavior |
|------|--------|---------|----------|
| `UserPromptSubmit` | `session-init.js` | First prompt per session | Auth + agent registration + delegation creation |
| `PreToolUse` | `pre-tool-use.js` | Before every tool call | Authorization enforcement |
| `PostToolUse` | `post-tool-use.js` | After every tool call | Audit logging (never blocks) |

### Session State

The session init writes `/tmp/stratium-session-<pid>.json` with:
- Delegation token + ID + expiry
- Agent ID
- User identity
- Project scope (max tier, approved tools)

The pre-tool-use hook reads this file synchronously on every tool call.

## DENY Response Example

When a tool is blocked, Claude Code surfaces the reason inline:

```
I attempted to write to src/auth.go but was blocked by Stratium:

  Tool:     Write
  Decision: DENY
  Reason:   INTERNAL_MODIFY (tier 2) exceeds your delegation cap
            for this project (READ_ONLY, tier 1)

Your delegation for this session allows: read_file, list_files, grep_search
To write files in this project, ask your admin to update the
stratium: block in CLAUDE.md to include Write and set
max_action_tier: INTERNAL_MODIFY.

Delegation ID: cc0c4885 (for your admin's reference)
```

## Audit Log

All tool executions are logged to `~/.claude/stratium-audit.jsonl`:

```jsonl
{"ts":"2026-03-30T10:15:32Z","event":"tool_executed","tool_name":"Read","action":"read","action_tier":1,"tier_label":"READ_ONLY","outcome":"success","user":"alice@corp.com","agent_id":"a3f7c291","delegation_id":"cc0c4885","resource":{"type":"file","path":"src/auth.go"}}
```

## Security

- Token cache stored at `~/.claude/stratium-tokens.json` (chmod 0600)
- Session state stored at `/tmp/stratium-session-<pid>.json` (chmod 0600)
- Agent record stored at `~/.claude/stratium-agent.json` (chmod 0600)
- Fail-closed by default — if Stratium is unreachable, no tools execute

## Environment Variables

| Variable | Description |
|----------|-------------|
| `STRATIUM_OIDC_PASSWORD` | Password for non-interactive auth (CI / MDM) |
| `STRATIUM_OIDC_USER` | Username override |
| `STRATIUM_ON_UNAVAILABLE` | Override fail mode: `fail_closed` or `fail_open` |
| `STRATIUM_GRPCURL_PATH` | Path to grpcurl binary |
| `STRATIUM_CURL_PATH` | Path to curl binary |

## License

Apache-2.0
