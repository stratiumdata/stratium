# Stratium MCP Agent Authorization Demo

Interactive demo showing AI agent authorization via Model Context Protocol.

## Quick Start

```bash
# 1. Start the full backend stack
docker-compose --profile agent-auth up -d

# 2. Seed demo data (users, policies, sample files)
./demos/mcp/seed-demo-data.sh

# 3. Build the MCP server and audit CLI
make build-mcp build-audit
```

### Claude Code (CLI)

The MCP server is configured at the user level in `~/.claude/settings.json` — it's available in every Claude Code session regardless of working directory.

To set it up (already done if you ran `seed-demo-data.sh` instructions):

```bash
# Verify the stratium MCP server is configured
cat ~/.claude/settings.json | jq .mcpServers.stratium.command
# Expected: "/Users/<you>/Development/stratium/bin/stratium-mcp"

# Start Claude Code from anywhere
claude
```

### Claude Desktop (app)

Merge the MCP server config into Claude Desktop's config file:

```bash
# macOS
cat demos/mcp/claude_desktop_config.json
# Copy the "stratium" block into:
#   ~/Library/Application Support/Claude/claude_desktop_config.json

# Or if you have no other MCP servers:
cp demos/mcp/claude_desktop_config.json \
   ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

> **Note:** The Claude Desktop config uses an absolute path to the binary.
> Edit the `command` field if your project is in a different location.

## Demo Personas

| User | Password | Clearance | Use Case |
|------|----------|-----------|----------|
| `demo-analyst` | `demo123` | INTERNAL | Read public + internal financial data |
| `demo-director` | `demo123` | CONFIDENTIAL | Access board materials |
| `demo-admin` | `demo123` | RESTRICTED | Full access, admin operations |

## Available MCP Tools

### Agent Management
- `register_agent` — Register a new AI agent
- `get_agent` — Get agent details
- `list_agents` — List registered agents
- `suspend_agent` — Suspend agent + revoke delegations

### Delegation Lifecycle
- `create_delegation` — Create time-bounded delegation token
- `create_sub_delegation` — Create child delegation (narrower scope)
- `revoke_delegation` — Revoke with cascade to children
- `list_delegations` — List active delegations

### Authorization
- `execute_action` — Execute action through authorization gateway
- `check_permission` — Dry-run permission check
- `validate_action_plan` — Batch validate planned actions
- `get_delegation_chain` — Inspect delegation chain

### Sub-Agent
- `orchestrate_sub_agent` — Spawn real Claude sub-agent with narrower scope

## Admin CLI

```bash
# View recent authorization decisions
./bin/stratium-audit logs --since 10m

# Filter by agent
./bin/stratium-audit logs --agent-id <uuid>

# Show delegation chain
./bin/stratium-audit chain <delegation-id>

# Export for compliance
./bin/stratium-audit export --since 7d -o audit-report.json
```

## Demo Walkthrough

See `docs/PRD_MCP_AGENT_AUTH_DEMO.md` Section 7 for the full investor demo script.
