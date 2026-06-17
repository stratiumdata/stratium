# PRD: Multi-Provider Agent Authorization — OpenAI Codex & Desktop

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-04-10
**Feature Flag:** `agent-auth` (existing)
**Depends On:** PRD_AGENT_AUTHORIZATION, PRD_MCP_AGENT_AUTH_DEMO, PRD_CLAUDE_CODE_HOOKS
**Branch:** `feature/codex-agent-authorization`

---

## Key Insight

The Anthropic and OpenAI agent ecosystems have converged on the same two integration patterns:

| Pattern | Anthropic | OpenAI | Stratium Integration |
|---------|-----------|--------|---------------------|
| **Desktop app** (GUI, conversational) | Claude Desktop | ChatGPT Desktop | **MCP** — reuse `stratium-mcp` |
| **CLI agent** (coding, sandboxed) | Claude Code | OpenAI Codex | **Hooks** — port `@stratium/claude-hooks` |

Stratium already has both layers built for Anthropic. Supporting OpenAI is a **port, not a new architecture**:

1. **MCP layer** — `stratium-mcp` (stdio/JSON-RPC) for desktop agents. Already built for Claude Desktop; works for ChatGPT Desktop when its MCP support ships. Zero changes needed.
2. **Hooks layer** — `PreToolUse`/`PostToolUse` scripts that call the PAP REST API to authorize actions. The PAP already has agent CRUD; new delegation + action-check REST endpoints let hooks operate with **zero binary dependencies** (pure Python `urllib`). SessionStart bootstraps a delegation token and writes it to `/tmp/.stratium-delegation.json`; PreToolUse reads the file and calls the PAP. If hooks don't load → no file → no token → all actions denied (fail-closed).

---

## Design Decisions

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| Primary framing | Two provider-agnostic layers (MCP + Hooks), zero binary dependencies for hooks | Per-provider adapters, separate REST service |
| Codex enforcement | **Native hooks** (`.codex/hooks.json` with `PreToolUse`) — hard enforcement, mirrors Claude Code | Advisory setup script (soft), FUSE shim (invasive), post-task audit-only (reactive) |
| Desktop enforcement | **MCP** — reuse `stratium-mcp` as-is (zero changes) | Custom ChatGPT plugin, REST-only adapter |
| Hook ↔ Gateway bridge | **PAP REST API** — hooks use Python `urllib` to call PAP (HTTPS). No binary dependency. | `stratium-mcp` subprocess (requires binary in sandbox), separate adapter service |
| Delegation bootstrap | **SessionStart hook creates delegation** via `POST /api/v1/delegations` on PAP, writes token to `/tmp/.stratium-delegation.json` | Pre-created env var (requires admin action per task), runtime gRPC call |
| Fail-closed guarantee | **No delegation file = deny all.** If hooks don't load, file never written, PreToolUse denies everything. | Env var model (agent has token even if hooks fail to load) |
| Authentication (hooks) | SessionStart calls PAP with OIDC token to create delegation; PreToolUse reads token from file | OAuth2 client credentials, pre-shared delegation token |
| Authentication (MCP/Desktop) | OIDC browser flow (same as Claude Desktop) | API key only, OAuth2 device flow |
| Provider identity | Existing `provider: "openai"` in agent model (no schema change) | New enum values per product |
| Model identifiers | Match OpenAI model IDs: `codex-mini`, `gpt-4o`, `o3` | Stratium-assigned alias |
| Hook coverage gap (Codex: Bash-only) | Defense-in-depth: SessionStart context + PostToolUse audit | Ignore gap, wait for OpenAI |

---

## 1. Problem Statement

Stratium's agent authorization platform has working integrations for **Anthropic Claude** — MCP for Claude Desktop and hooks for Claude Code. Enterprises use multiple AI providers, and two critical OpenAI products lack integration:

1. **OpenAI Codex** — cloud-based coding agent in a sandboxed Linux VM. Has a native hooks system (`.codex/hooks.json`) with `PreToolUse`, `PostToolUse`, `SessionStart`, `UserPromptSubmit`, and `Stop` events — mirroring Claude Code's hook architecture.

2. **OpenAI Desktop (ChatGPT)** — desktop app that is adding MCP server support, converging with Claude Desktop's integration model.

The convergence means the engineering cost is **porting, not building from scratch**. The hook scripts need adaptation for Codex's JSON format and Bash-only limitation. The MCP server needs no changes for Desktop — just configuration.

### Why This Matters

- **Enterprise reality:** Organizations use Claude for code review and Codex for implementation. They need unified authorization across both.
- **Investor narrative:** Multi-provider support validates Stratium as provider-agnostic infrastructure, not a single-vendor integration.
- **Low marginal cost:** Same binary, same Gateway, same delegation model — just different hook config formats.

---

## 2. Goals

1. **Codex hook enforcement** — port `@stratium/claude-hooks` to `.codex/hooks.json` so every Bash command is authorized through `stratium-mcp` → Agent Gateway.
2. **Desktop MCP reuse** — validate that `stratium-mcp` works with ChatGPT Desktop when MCP support ships.
3. **Unified audit trail** — all actions from Claude, Codex, and Desktop agents in the same audit log with provider attribution.
4. **Cross-provider delegation chains** — Claude parent agent delegates to Codex sub-agent (and vice versa).
5. **Demo parity** — financial records demo works identically with OpenAI agents.

### Non-Goals (V1)

- Custom ChatGPT GPT/plugin marketplace integration.
- OpenAI Assistants API (v2) integration.
- Automated trust tier promotion based on OpenAI safety scores.
- New adapter services or HTTP endpoints.

---

## 3. Architecture

### 3.1 System Diagram — One Binary, Two Layers

```
┌──────────────────────────────────────────────────────────────────┐
│                       AI Agent Clients                            │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐                              │
│  │Claude Desktop │  │ChatGPT Dsktp │   MCP LAYER                 │
│  └──────┬───────┘  └──────┬───────┘   (stdio/JSON-RPC)           │
│         │                 │                                      │
│         ▼                 ▼                                      │
│  ┌─────────────────────────────────┐                             │
│  │      stratium-mcp (existing)    │ ◄── Same binary for both   │
│  │   Provider-agnostic MCP server  │     Anthropic and OpenAI    │
│  └──────────────┬──────────────────┘                             │
│                 │ gRPC + mTLS                                    │
│                 │                                                │
│  ┌──────────────┐  ┌──────────────┐                              │
│  │ Claude Code  │  │ OpenAI Codex │   HOOKS LAYER                │
│  └──────┬───────┘  └──────┬───────┘   (PreToolUse/PostToolUse)   │
│         │                 │                                      │
│         ▼                 ▼                                      │
│  ┌──────────────┐  ┌──────────────┐                              │
│  │ @stratium/   │  │ stratium-    │                              │
│  │ claude-hooks │  │ codex-hooks  │                              │
│  │ (existing)   │  │ (new — port) │                              │
│  └──────┬───────┘  └──────┬───────┘                              │
│         │                 │                                      │
│         ▼                 ▼                                      │
│  ┌─────────────────────────────────┐                             │
│  │      stratium-mcp (same binary) │ ◄── Hook scripts invoke    │
│  │   Called as subprocess by hooks  │     stratium-mcp to check  │
│  └──────────────┬──────────────────┘     authorization           │
│                 │ gRPC + mTLS                                    │
└─────────────────┼────────────────────────────────────────────────┘
                  ▼
        ┌─────────────────────┐
        │   Agent Gateway     │
        │   :50054 (existing) │
        └──────────┬──────────┘
                   │
       ┌───────────┼───────────┐
       │           │           │
  ┌────▼──────┐ ┌──▼──────┐ ┌─▼─────────┐
  │ Platform  │ │Key Mgr  │ │Key Access │
  │ :50051    │ │:50052   │ │:50053     │
  └───────────┘ └─────────┘ └───────────┘
```

### 3.2 How It Works

**Desktop agents (MCP layer):**
- Claude Desktop and ChatGPT Desktop both spawn `stratium-mcp` as a subprocess
- `stratium-mcp` communicates via stdio/JSON-RPC (MCP protocol)
- `stratium-mcp` calls Agent Gateway via gRPC
- **Identical integration path** — zero code changes for OpenAI Desktop

**CLI agents (Hooks layer):**
- Claude Code and OpenAI Codex both have native hook systems
- Hook scripts intercept tool calls (`PreToolUse`) before execution
- **SessionStart hook bootstraps a delegation** by calling the PAP REST API, writes token to `/tmp/.stratium-delegation.json`
- **PreToolUse hook reads the delegation token from file** and calls the PAP REST API to authorize the action
- If hooks don't load → no delegation file → all actions denied (fail-closed)
- **Zero binary dependencies** — hooks use pure Python `urllib` against PAP (HTTPS)

### 3.3 PAP REST Endpoints (New)

The PAP server (`:8090`) gains delegation management and action-check REST endpoints, enabling Codex hooks to operate without the `stratium-mcp` binary or direct gRPC access:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/delegations` | Create root delegation token (HMAC-SHA256 JWT) |
| GET | `/api/v1/delegations` | List active delegations for current user |
| DELETE | `/api/v1/delegations/:id` | Revoke delegation + cascade to children |
| POST | `/api/v1/actions/check` | Validate action against delegation scope |

The PAP uses the **same HMAC-SHA256 signing key** as the Agent Gateway (`STRATIUM_AGENT_GATEWAY_DELEGATION_SIGNING_KEY`), so tokens are interchangeable.

### 3.4 Layer Comparison

| | MCP Layer | Hooks Layer |
|---|-----------|-------------|
| **Transport** | stdio/JSON-RPC (MCP protocol) | Python `urllib` → PAP REST API (HTTPS) |
| **Enforcement** | Agent calls MCP tools; server enforces | Platform intercepts tool calls; hook denies |
| **Authorization backend** | `stratium-mcp` → Agent Gateway (gRPC) | Hook scripts → PAP (HTTPS) |
| **Binary dependencies** | `stratium-mcp` binary | **None** (pure Python stdlib) |
| **Delegation bootstrap** | Interactive (user creates via MCP tool) | **Automatic** (SessionStart hook calls PAP) |
| **Fail-closed guarantee** | Agent must call `execute_action` MCP tool | **No delegation file = deny all** |
| **Coverage** | All tools the MCP server exposes | Claude Code: all tools; Codex: **Bash only** |
| **Used by** | Claude Desktop, ChatGPT Desktop | Claude Code, OpenAI Codex |
| **Config location** | `claude_desktop_config.json` / ChatGPT equivalent | `.claude/settings.json` / `.codex/hooks.json` |

### 3.5 What's New vs What's Reused

| Component | Status | Work Required |
|-----------|--------|---------------|
| `stratium-mcp` | **Existing** | Add `--mode=check` flag (single-shot mode for Claude Code hooks) |
| `@stratium/claude-hooks` | **Existing** | Zero changes — reference implementation |
| Agent Gateway (:50054) | **Existing** | Zero changes |
| Agent model (`provider: "openai"`) | **Existing** | Zero changes |
| Delegation chain model | **Existing** | Zero changes — JWTs are transport-agnostic |
| PAP delegation REST endpoints | **New** | `POST /delegations`, `POST /actions/check`, `GET /delegations`, `DELETE /delegations/:id` |
| `stratium-codex-hooks` | **New (port)** | Pure Python hooks using PAP REST + command classifier |

**No new services. No new binaries for Codex. REST endpoints added to existing PAP server.**

---

## 4. Hooks Layer: `stratium-codex-hooks`

Port of `@stratium/claude-hooks` for OpenAI Codex. Same enforcement model, adapted for Codex's hook format and Bash-only limitation.

### 4.1 Configuration: `.codex/hooks.json`

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume",
        "hooks": [
          {
            "type": "command",
            "command": "$(git rev-parse --show-toplevel)/.codex/hooks/stratium_session_start.py",
            "statusMessage": "Initializing Stratium agent authorization...",
            "timeout": 10
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$(git rev-parse --show-toplevel)/.codex/hooks/stratium_pre_tool_use.py",
            "statusMessage": "Checking Stratium authorization...",
            "timeout": 5
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$(git rev-parse --show-toplevel)/.codex/hooks/stratium_post_tool_use.py",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

### 4.2 Hook Lifecycle

```
Codex task starts (sandboxed VM)
  │
  ├─ Env vars set by admin/user in task config:
  │   STRATIUM_PAP_URL=https://pap.stratium.io:8090
  │   STRATIUM_AGENT_ID=<registered-agent-uuid>
  │   STRATIUM_AUTH_TOKEN=<oidc-access-token>
  │
  ├─ SessionStart hook fires:
  │   → Calls PAP: POST /api/v1/delegations (creates delegation token)
  │   → Writes token to /tmp/.stratium-delegation.json
  │   → If PAP unreachable or env vars missing: no file written
  │   → Injects authorization context into agent system prompt
  │
  ├─ Codex generates a Bash command...
  │
  ├─ PreToolUse hook fires (BEFORE execution):
  │   → Reads token from /tmp/.stratium-delegation.json
  │   → If file missing → DENY (SessionStart never ran = fail-closed)
  │   → Classifies command → normalized tool_name + action + tier
  │   → Calls PAP: POST /api/v1/actions/check
  │   → If ALLOW: { permissionDecision: "allow" } → command executes
  │   → If DENY:  { permissionDecision: "deny", reason: "..." } → BLOCKED
  │
  ├─ PostToolUse hook fires (AFTER execution):
  │   → Best-effort audit logging
  │
  └─ Delegation auto-expires when task completes
```

**Fail-closed guarantee:** If hooks don't load at all (not in repo, not in `~/.codex/`), the delegation file is never created. If the agent somehow bypasses hooks and accesses Stratium-protected resources, it has no delegation token — the Gateway rejects the request.

### 4.3 Hook Scripts

The hook scripts use **pure Python stdlib** (`urllib`, `json`, `ssl`) — no binary dependencies, no `pip install`. They call the PAP REST API directly over HTTPS.

Full source code is in `demos/codex/hooks/`:
- `stratium_session_start.py` — Bootstraps delegation via `POST /api/v1/delegations`, writes token to file
- `stratium_pre_tool_use.py` — Reads token from file, classifies command, calls `POST /api/v1/actions/check`
- `stratium_post_tool_use.py` — Best-effort audit logging

### 4.4 Installation

**Option 1: Checked into the repo (recommended — Codex loads hooks from the repo)**

```bash
cp demos/codex/hooks.json <target-repo>/.codex/hooks.json
mkdir -p <target-repo>/.codex/hooks/
cp demos/codex/hooks/stratium_*.py <target-repo>/.codex/hooks/
chmod +x <target-repo>/.codex/hooks/*.py
git add .codex/ && git commit -m "chore: add Stratium agent authorization hooks"
```

**Option 2: User-level hooks (local sessions only — NOT for remote Codex sandboxes)**

```bash
cp demos/codex/hooks.json ~/.codex/hooks.json
mkdir -p ~/.codex/hooks/
cp demos/codex/hooks/stratium_*.py ~/.codex/hooks/
```

**Environment variables (set in Codex task config):**

```bash
STRATIUM_PAP_URL=https://pap.stratium.io:8090  # PAP server URL
STRATIUM_AGENT_ID=<registered-agent-uuid>        # From agent registration
STRATIUM_AUTH_TOKEN=<oidc-access-token>           # User's OIDC token for delegation creation

# Optional overrides:
STRATIUM_APPROVED_TOOLS=read_file,write_file,bash  # Comma-separated (default)
STRATIUM_MAX_ACTION_TIER=2                          # 0-4 (default: 2)
STRATIUM_CLASSIFICATION_CAP=INTERNAL                # Default cap
STRATIUM_TTL_SECONDS=1800                           # Delegation TTL (default: 30min)

# Backward compatible: if set, SessionStart skips PAP call and uses this directly
STRATIUM_DELEGATION_TOKEN=<jwt>                     # Pre-created delegation token
```

### 4.6 Hook Coverage & Limitations

Codex hooks currently **only intercept the `Bash` tool**. OpenAI's docs note: "The model can still work around this by writing its own script to disk and then running that script with Bash, so treat this as a useful guardrail rather than a complete enforcement boundary."

**Comparison with Claude Code hooks:**

| Capability | Claude Code | Codex | Notes |
|-----------|------------|-------|-------|
| PreToolUse scope | **All tools** | **Bash only** | Codex gap — non-Bash tools unintercepted |
| PostToolUse scope | All tools | Bash only | |
| SessionStart | Yes | Yes | Identical |
| UserPromptSubmit | Yes | Yes | Identical |
| Stop | Yes | Yes | Identical |
| Fail-closed | Yes (non-zero exit) | Yes (exit code 2) | Same intent, different signal |
| Deny response | `{"decision":"block"}` | `{"permissionDecision":"deny"}` | Different JSON schema |
| Config location | `.claude/settings.json` | `.codex/hooks.json` | Different file, same concept |
| Deployment | npm package or MDM | Python scripts in repo or `~/.codex/` | |

**Defense-in-depth for the Bash-only gap:**

| Gap | Mitigation |
|-----|-----------|
| Non-Bash tools not intercepted | `SessionStart` injects instructions for agent to stay within delegation scope |
| Script-to-disk bypass | `PreToolUse` still fires on the Bash call that executes the script |
| No Write tool interception | Codex primarily operates via Bash; direct Write usage is less common |

### 4.7 Codex AGENTS.md Instructions (Defense-in-Depth)

```markdown
## Authorization Protocol

You are operating under Stratium zero-trust agent authorization.

**Enforced automatically (via hooks):**
- All Bash commands are checked against your delegation before execution.
- If denied, you will see the reason. Do NOT retry denied commands.
- If the authorization service is unreachable, ALL commands are blocked (fail-closed).

**Your responsibility (not enforced by hooks):**
- Non-Bash tool actions are not intercepted. Stay within your delegation scope.
- Report any access attempts to classified resources to the user.
- Do not circumvent authorization by writing scripts to disk.
```

---

## 5. MCP Layer: Desktop Integration

### 5.1 ChatGPT Desktop (When MCP ships)

**Zero code changes.** ChatGPT Desktop spawns `stratium-mcp` as a subprocess — identical to the Claude Desktop integration.

```json
{
  "mcpServers": {
    "stratium": {
      "command": "/path/to/stratium-mcp",
      "env": {
        "STRATIUM_TLS_CA": "/path/to/ca.crt"
      }
    }
  }
}
```

The same MCP tools (`register_agent`, `create_delegation`, `execute_action`, etc.) are available to ChatGPT Desktop as they are to Claude Desktop. The agent registers with `provider: "openai"` instead of `provider: "anthropic"` — that's the only difference.

### 5.2 ChatGPT Desktop (Interim — before MCP)

Until ChatGPT Desktop's MCP support is GA, use the AGENTS.md behavioral instructions approach (same as the Codex defense-in-depth model). The user creates a delegation manually and the agent self-reports actions.

---

## 6. Cross-Provider Delegation Chains

The delegation chain model is transport-agnostic. A chain can span providers and layers:

```
Root: Claude Code (hooks layer, Anthropic, CERTIFIED, CONFIDENTIAL)
  └─ Child: Codex (hooks layer, OpenAI, REGISTERED, INTERNAL)
```

**Flow:**
1. Claude creates sub-delegation via MCP `create_sub_delegation` tool
2. Sub-delegation token passed to Codex (via `STRATIUM_DELEGATION_TOKEN` env var, bypassing SessionStart bootstrap)
3. Codex PreToolUse hook reads token from file and calls PAP `POST /api/v1/actions/check`
4. PAP verifies the delegation JWT chain — denial at any depth blocks the action

**No protocol changes required** — delegation tokens (JWTs) are transport-agnostic.

---

## 7. Data Model Changes

### 7.1 Agent Model — No Schema Changes

The existing `agents` table already supports `provider: "openai"` and free-form `model_id`. No migration needed.

### 7.2 Audit Log — Transport Column (Minor)

```sql
ALTER TABLE audit_logs ADD COLUMN transport VARCHAR(20) DEFAULT 'mcp';
-- Values: 'mcp' (stdio), 'rest' (PAP REST from Codex hooks), 'mcp-check' (single-shot), 'grpc' (direct)
```

---

## 8. Demo Scenario: Multi-Provider Financial Records

### 8.1 Personas

| Persona | Client | Layer | Provider | Trust Tier | Clearance |
|---------|--------|-------|----------|------------|-----------|
| `demo-analyst` | Claude Code | Hooks | anthropic | 1 (REGISTERED) | INTERNAL |
| `codex-impl` | OpenAI Codex | Hooks | openai | 1 (REGISTERED) | INTERNAL |
| `desktop-reviewer` | ChatGPT Desktop | MCP | openai | 1 (REGISTERED) | INTERNAL |
| `demo-director` | Claude Code | Hooks | anthropic | 2 (CERTIFIED) | CONFIDENTIAL |

### 8.2 Demo Script

```
Scene 1: Claude analyst reads INTERNAL forecast
  → Claude Code hooks → stratium-mcp → Agent Gateway → ALLOW

Scene 2: Codex writes implementation code
  → Codex hooks → PAP REST /actions/check → ALLOW
  → Command executes

Scene 3: Codex tries to read CONFIDENTIAL board deck
  → Codex hooks → PAP REST /actions/check → DENY
  → "classification CONFIDENTIAL > cap INTERNAL"
  → Command BLOCKED — never executes

Scene 4: Cross-provider delegation chain
  → Claude director delegates to Codex (narrower scope: PUBLIC only)
  → Codex hooks evaluate with sub-delegation token
  → Gateway checks 2-hop chain → DENY for INTERNAL data

Scene 5: Real-time cascade revocation
  → Admin revokes Claude root delegation
  → Codex sub-delegation auto-revoked
  → Codex next command → DENY (delegation revoked)
  → Audit trail shows cascade across providers
```

### 8.3 Audit Trail

```
TIMESTAMP            AGENT               PROVIDER   LAYER   TOOL        TIER  DECISION
2026-04-11 14:23:01  claude-analyst       anthropic  hooks   read_file   1     ALLOW
2026-04-11 14:23:05  codex-impl           openai     rest    Bash        2     ALLOW
2026-04-11 14:23:08  codex-impl           openai     rest    Bash        1     DENY
2026-04-11 14:23:12  desktop-reviewer     openai     mcp     read_file   1     ALLOW
2026-04-11 14:23:15  codex-sub [chain:2]  openai     rest    Bash        1     DENY (depth:1)
```

---

## 9. Implementation Phases

### Phase 1: PAP REST Endpoints + Codex Hooks (1.5 weeks)

| Task | Files | Effort |
|------|-------|--------|
| PAP delegation REST endpoints (create, list, revoke) | `go/services/pap/delegation_handlers.go` | 2 days |
| PAP action check endpoint (`POST /actions/check`) | `go/services/pap/delegation_handlers.go` | 1 day |
| Codex hooks package (SessionStart bootstrap, PreToolUse, PostToolUse) | `demos/codex/hooks/stratium_*.py` | 2 days |
| Command classifier (Bash → normalized tool_name + tier) | `demos/codex/hooks/stratium_pre_tool_use.py` | 0.5 day |
| Add `--mode=check` to `stratium-mcp` (for Claude Code hooks) | `go/internal/mcp/check.go` | 1 day |
| Unit + integration tests | `go/internal/mcp/check_test.go`, `demos/codex/hooks/test_hooks.py` | 1.5 days |

### Phase 2: Desktop MCP Validation + Cross-Provider Tests (1 week)

| Task | Files | Effort |
|------|-------|--------|
| Validate `stratium-mcp` with ChatGPT Desktop (or mock) | Manual testing + docs | 1 day |
| Cross-provider delegation chain tests | `go/services/agent-gateway/cross_provider_test.go` | 1 day |
| `stratium-audit` provider/layer filtering | `go/cmd/stratium-audit/` | 0.5 day |
| Demo seed data for OpenAI agents | `demos/openai/seed-data.sh` | 0.5 day |
| Audit `transport` column migration | `deployment/postgres/05-audit-transport.sql` | 0.5 day |

### Phase 3: Demo + Docs (3 days)

| Task | Files | Effort |
|------|-------|--------|
| Multi-provider demo script | `demos/openai/demo-script.md` | 1 day |
| Testing guide | `docs/TESTING_OPENAI_AGENT_AUTH.md` | 1 day |
| Architecture codemap updates | `docs/CODEMAPS/architecture.md` | 0.5 day |
| README updates | `README.md` | 0.5 day |

**Total: ~3 weeks** (down from ~3.5 weeks with the adapter service)

---

## 10. Testing Strategy

### 10.1 Unit Tests

- `--mode=check` reads stdin, calls Gateway, writes stdout
- `--mode=check` fail-closed on Gateway unreachable
- `--mode=check` with expired/revoked delegation token
- Command classifier (Bash → tier mapping edge cases)

### 10.2 Integration Tests

- `stratium-mcp --mode=check` → Agent Gateway round-trip
- Cross-provider delegation chain (Claude hooks → Codex hooks → Gateway)
- Cascade revocation across providers
- Concurrent actions from multiple providers

### 10.3 E2E Tests

- Codex hooks: env var → hooks fire → PreToolUse deny/allow → task completion
- Codex fail-closed: no delegation token → all Bash commands denied
- Codex script-to-disk: verify PreToolUse still fires on script execution
- Desktop MCP: OIDC login → delegation → action checks → session end
- Multi-provider demo scenario end-to-end

### 10.4 Test Accounts

| User | Agent Name | Provider | Layer | Trust Tier |
|------|-----------|----------|-------|------------|
| demo-analyst | codex-impl | openai | hooks | 1 |
| demo-analyst | desktop-reviewer | openai | mcp | 1 |
| demo-director | codex-sub-agent | openai | hooks | 1 |

---

## 11. Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Hooks don't load (not in repo) | **Fail-closed:** no delegation file = no token = all Stratium-protected resources denied |
| OIDC token in Codex env var | Short-lived; scoped to delegation creation only; sandbox-isolated |
| Delegation token on disk (`/tmp/`) | Short-lived (default 30min); sandbox is ephemeral; file permissions 0600 |
| Token replay from sandbox | Tokens bound to specific agent_id; expire with TTL |
| Cross-provider privilege escalation | Chain always narrows; child ⊆ parent enforced by PAP/Gateway |
| PAP unreachable from sandbox | Hooks fail-closed — all commands denied |
| Codex hooks only cover Bash tool | Defense-in-depth: SessionStart instructions + PostToolUse audit |
| Script-to-disk bypass | PreToolUse still fires on the Bash call that executes the script |
| Hook scripts tampered with | CODEOWNERS / branch protection; hooks checked into repo |
| Concurrent hooks | Stratium hook is independent; others cannot suppress its deny |
| PAP signing key != Gateway key | Use same `STRATIUM_AGENT_GATEWAY_DELEGATION_SIGNING_KEY` env var; tokens are interchangeable |

---

## 12. Success Metrics

| Metric | Target |
|--------|--------|
| Codex hooks deny unauthorized Bash commands (hard enforcement) | Pass |
| Codex hooks fail-closed when PAP unreachable | Pass |
| Codex hooks fail-closed when delegation file missing (hooks not loaded) | Pass |
| SessionStart bootstraps delegation via PAP REST | Pass |
| `stratium-mcp` works with ChatGPT Desktop (when MCP ships) | Pass |
| Cross-provider delegation chain (Claude → Codex) | Pass |
| Cascade revocation across providers | Pass |
| Unified audit trail with provider + layer attribution | Pass |
| PAP action check latency | < 100ms p99 (HTTPS) |
| Demo scenario end-to-end with OpenAI agents | Pass |
| Zero changes to existing Claude integrations | Pass |

---

## 13. Open Questions

| # | Question | Owner | Status |
|---|----------|-------|--------|
| 1 | ~~Can the `stratium-mcp` binary be pre-installed in Codex sandboxes?~~ | Ben | **Resolved** — hooks now use PAP REST (no binary needed) |
| 2 | Do Codex hook scripts have access to env vars set in the task config? | Ben | Open |
| 3 | When will ChatGPT Desktop MCP support ship? | Ben | Open |
| 4 | When will Codex expand hook coverage beyond Bash? | Ben | Open |
| 5 | Should the PAP action-check endpoint do full compound policy evaluation or just delegation scope? | Ben | Open |
| 6 | ~~Does Codex allow spawning arbitrary subprocesses from hook scripts?~~ | Ben | **Resolved** — hooks use `urllib` only, no subprocesses |
| 7 | Should the PAP delegation endpoint support sub-delegation creation (with parent token) for cross-provider chains? | Ben | Open |
