# PRD: Stratium Authorization Hooks for Claude Code
**Status:** Draft
**Author:** Engineering
**Date:** 2026-03-30

---

## 1. Executive Summary

Today, enforcing Zero-Trust access control on AI agents requires custom integration code per project. This PRD describes `@stratium/claude-hooks` — an npm package that embeds Stratium's agent authorization directly into Claude Code's hook system, making authorization **automatic and invisible** to developers.

Once installed (via MDM or self-service), every Claude Code session on a developer's machine is automatically:
- **Identified** — the session creates a per-user delegation token scoped to the project's CLAUDE.md policy
- **Enforced** — every tool call Claude attempts is checked against Stratium's Agent Gateway before execution
- **Audited** — all decisions (ALLOW and DENY) are recorded in Stratium's audit log with full user, agent, and delegation context

No code changes are required in any project. Admins push configuration; developers open Claude Code as normal.

---

## 2. Problem Statement

### Current State

AI agents like Claude Code operate with broad ambient authority — once a developer opens Claude Code, it can read any file, write any file, run any shell command, and make any network call that the OS permits. There is no:
- Per-session scoping of what tools Claude is allowed to use
- Audit record of what tools were actually used under whose authority
- Enforcement of data classification policies (e.g., "Claude cannot read TOP-SECRET documents")
- Revocation mechanism if a session is compromised

### Why This Matters

Enterprise environments have existing access control policies that govern what humans can do with sensitive data. AI agents operating on behalf of those humans inherit their ambient permissions but bypass the policy controls that govern humans. This creates a **privilege amplification gap**: Claude Code running as `alice@corp.com` can read files Alice herself would be blocked from reading via normal tooling, because the tooling enforces policy but Claude Code does not.

### The Opportunity

Claude Code's hook system (`PreToolUse`, `UserPromptSubmit`) provides a native interception point between Claude's intent and tool execution. Stratium already has the authorization infrastructure: delegation tokens, compound decisions, audit logging, revocation. Connecting the two closes the privilege gap without requiring application-level changes.

---

## 3. Goals

| # | Goal |
|---|------|
| G1 | Every tool call Claude Code makes is checked against a Stratium delegation before execution |
| G2 | A device admin can push the integration to all developer machines via MDM (Jamf/Intune) with zero developer action required |
| G3 | Authorization scope is declared per-project in CLAUDE.md, not globally — different repos get different delegation scopes |
| G4 | When Stratium is unreachable, Claude Code fails closed — no tools execute without authorization |
| G5 | DENY decisions return a human-readable explanation that Claude can relay to the developer inline |
| G6 | The user's real identity (Keycloak OIDC) is established once per session and embedded in the delegation token |
| G7 | The package installs in < 2 minutes and requires no changes to any existing project |

## 4. Non-Goals

| # | Non-Goal | Rationale |
|---|----------|-----------|
| NG1 | Replacing Claude Code's built-in `allowedTools` or permission system | Stratium sits on top of, not instead of, Claude Code's existing controls |
| NG2 | Providing a UI / dashboard | Out of scope for v1; use Stratium's existing PAP UI |
| NG3 | Encrypting Claude's tool inputs/outputs | Key Access service integration is a future phase |
| NG4 | Supporting non-Claude-Code AI agents in v1 | Other agents (Cursor, Copilot) can be added post-v1 using the same Stratium infrastructure |
| NG5 | Fine-grained per-file authorization | v1 scopes at the tool+tier level; path-level rules are a future enhancement |

---

## 5. User Stories

### Developer (end user)

> **US-1:** As a developer, I want Claude Code to automatically respect my project's authorization policy so I never accidentally trigger a tool that could violate data handling rules.

> **US-2:** As a developer, when Claude Code is blocked from doing something, I want a clear explanation of why so I know whether to escalate to my admin or rephrase my request.

> **US-3:** As a developer, I want session authentication to happen once at the start of my Claude Code session, not before every tool call.

### Security Admin

> **US-4:** As a security admin, I want to define per-project authorization policies in CLAUDE.md and have them enforced on all developer machines without requiring developer action.

> **US-5:** As a security admin, I want a complete audit trail of every tool Claude Code called, who authorized it, and whether it was allowed or denied.

> **US-6:** As a security admin, I want to remotely revoke a delegation if a session is compromised, and have the revocation take effect immediately on the affected machine.

> **US-7:** As a security admin, I want to push the hooks package to all developer devices via MDM and configure the Stratium gateway endpoint centrally.

### Platform Admin (Stratium)

> **US-8:** As a platform admin, I want the Claude Code agent to auto-register the first time it runs on a machine so I don't need to pre-provision every developer's workstation.

---

## 6. Architecture

### 6.1 System Overview

```
Developer Machine                      Stratium (corporate network / local)
─────────────────────────────────      ────────────────────────────────────
  Claude Code (IDE/CLI)
       │
       │ UserPromptSubmit hook
       ▼
  stratium-session-init.js
  ┌────────────────────────┐            Keycloak
  │ 1. Load CLAUDE.md      │ ──OIDC──▶  :8080
  │    policy              │ ◀──token── (password / device flow)
  │ 2. Get/refresh OIDC    │
  │    token               │            PAP REST API
  │ 3. Ensure agent is     │ ──POST──▶  :8090 /api/v1/agents
  │    registered          │ ◀──────── (idempotent, cached)
  │ 4. Create session      │
  │    delegation          │            Agent Gateway (gRPC)
  │                        │ ──gRPC──▶  :50054 CreateDelegation
  │ → stores delegation    │ ◀──token──
  │   token in session env │
  └────────────────────────┘
       │
       │ (Claude reasons, plans tool calls)
       │
       │ PreToolUse hook  (fires per tool call)
       ▼
  stratium-pre-tool-use.js
  ┌────────────────────────┐
  │ 1. Read tool name +    │            Agent Gateway (gRPC)
  │    input from env      │ ──gRPC──▶  :50054 ExecuteAction
  │ 2. Map to action tier  │ ◀──────── {authorized, error}
  │ 3. Call ExecuteAction  │
  │ 4a. ALLOW → exit 0    │            Platform (gRPC, internal)
  │ 4b. DENY  → exit 2 +  │ ◀──────── GetDecision (compound)
  │     JSON block reason  │
  └────────────────────────┘
       │
       │ ALLOW: Claude tool executes normally
       │ DENY:  Claude sees error, explains to developer
```

### 6.2 Hook Roles

| Hook | Script | Responsibility |
|------|--------|----------------|
| `UserPromptSubmit` | `stratium-session-init.js` | Auth, agent registration, delegation creation — runs once per session on first prompt |
| `PreToolUse` | `stratium-pre-tool-use.js` | Authorization check — runs before every tool execution |

`PostToolUse` is used for audit enrichment only (appending execution metadata to the Stratium audit log). It never blocks.

### 6.3 Session State

The session init script writes session state to a temp file scoped to the Claude Code process:

```
/tmp/stratium-session-<pid>.json
{
  "agent_id": "a3f7c291-...",
  "delegation_token": "eyJ...",
  "delegation_id": "cc0c4885-...",
  "expires_at": "2026-03-30T14:00:00Z",
  "user": "alice@corp.com",
  "project_scope": {
    "max_action_tier": 1,
    "approved_tools": ["read_file", "list_files"]
  }
}
```

The `PreToolUse` script reads this file on every invocation. Token expiry triggers a silent refresh via the stored refresh token; if refresh fails, the hook blocks all tools until the user re-authenticates.

---

## 7. Configuration Schema

### 7.1 Project-level: CLAUDE.md

Each project declares its Stratium authorization policy in CLAUDE.md:

```markdown
## Stratium Authorization

stratium:
  enabled: true
  agent_name: claude-code           # registered agent name in PAP
  max_action_tier: READ_ONLY        # READ_ONLY | INTERNAL_MODIFY | EXTERNAL_COMMS | DESTRUCTIVE
  approved_tools:
    - read_file
    - list_files
    - search_files
    - grep_search
  classification_caps:
    nato: CONFIDENTIAL              # cannot read SECRET or above
  on_unavailable: fail_closed       # fail_closed | fail_open
  purpose: "Development work on {{repo_name}}"
```

If no `stratium:` block is present, the package falls back to the global default scope (see 7.2).

### 7.2 Machine-level: ~/.claude/stratium.json

Created by `stratium-hooks configure` during install (MDM or manual):

```json
{
  "gateway": "stratium.corp.com:50054",
  "pap_url": "https://stratium.corp.com:8090",
  "keycloak_url": "https://keycloak.corp.com",
  "realm": "corp",
  "cacert": "/etc/stratium/certs/ca.crt",
  "default_scope": {
    "max_action_tier": "READ_ONLY",
    "approved_tools": ["read_file", "list_files"],
    "on_unavailable": "fail_closed"
  }
}
```

### 7.3 Auto-registered Agent: ~/.claude/stratium-agent.json

Created automatically on first run. Checked on every session init; re-registration is idempotent:

```json
{
  "agent_id": "a3f7c291-4c9e-4a1f-b8d3-0cf4e1a2b3c4",
  "client_id": "agent_a3f7c291",
  "registered_at": "2026-03-30T08:00:00Z",
  "machine_id": "mbp-ben",
  "stratium_gateway": "stratium.corp.com:50054"
}
```

### 7.4 Hook Registration: ~/.claude/settings.json

Installed automatically by `stratium-hooks configure`:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx @stratium/claude-hooks session-init"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "npx @stratium/claude-hooks pre-tool-use"
          }
        ]
      }
    ]
  }
}
```

---

## 8. Tool Tier Mapping

The package ships a default tier map. Projects can override it in CLAUDE.md:

| Claude Code Tool | Action | Default Tier | Tier Name |
|------------------|--------|-------------|-----------|
| `read_file` | read | 1 | READ_ONLY |
| `list_files` / `ls` | read | 1 | READ_ONLY |
| `grep_search` / `search_files` | read | 1 | READ_ONLY |
| `write_file` / `create_file` | write | 2 | INTERNAL_MODIFY |
| `edit_file` | write | 2 | INTERNAL_MODIFY |
| `move_file` / `delete_file` | modify | 2 | INTERNAL_MODIFY |
| `bash` (read-only commands) | read | 1 | READ_ONLY |
| `bash` (write/modify commands) | execute | 2 | INTERNAL_MODIFY |
| `bash` (network/curl/wget) | network | 3 | EXTERNAL_COMMS |
| `bash` (rm -rf, destructive) | execute | 4 | DESTRUCTIVE |
| `web_fetch` / `web_search` | read | 1 | READ_ONLY |
| `mcp_*` (MCP tools) | varies | configurable | — |

**Bash tier detection:** For `bash` tool calls, the hook inspects the command string against a regex ruleset to determine the appropriate tier. This is heuristic — admins can configure `bash_default_tier` to set a floor.

---

## 9. Hook Behavior Detail

### 9.1 UserPromptSubmit: Session Init

```
Trigger: first user prompt in a Claude Code session

1. Check if /tmp/stratium-session-<pid>.json exists and token is valid
   → if yes: skip (idempotent, session already initialized)
   → if no: proceed

2. Load ~/.claude/stratium.json (machine config)
   → if missing: warn + proceed in fail_open/fail_closed per default

3. Parse CLAUDE.md in current working directory
   → extract stratium: block
   → if absent: use default_scope from machine config

4. Authenticate user (Keycloak password grant, cached in OS keychain)
   → prompt developer: "Stratium: authenticating as alice@corp.com..."
   → on failure: block if fail_closed, warn if fail_open

5. Ensure agent is registered (idempotent PAP call)
   → uses ~/.claude/stratium-agent.json
   → if agent not found in Stratium: re-register and update file

6. Create delegation (Agent Gateway CreateDelegation)
   → scope from CLAUDE.md stratium: block
   → TTL: 4 hours (configurable)
   → conversation_id: Claude Code session ID

7. Write /tmp/stratium-session-<pid>.json

8. Return success (empty stdout, exit 0)
   → Claude Code session starts normally
```

### 9.2 PreToolUse: Authorization Check

The hook receives tool information via environment variables set by Claude Code:

```
CLAUDE_TOOL_NAME=write_file
CLAUDE_TOOL_INPUT={"path":"src/auth.go","content":"..."}
```

```
Trigger: Claude is about to execute any tool

1. Read /tmp/stratium-session-<pid>.json
   → if missing/expired and fail_closed: block with message
     "Stratium session not initialized. Start a new Claude Code session."

2. Determine action tier for tool name
   → check CLAUDE.md overrides first
   → fall back to built-in tier map (section 8)
   → for bash: inspect command string for tier classification

3. Extract resource attributes from tool input
   → file path → {resource_type: "file", path: "..."}
   → if path matches classification_caps pattern → add classification attr

4. Call Agent Gateway ExecuteAction (gRPC, < 50ms p99)
   → delegation_token from session file
   → tool_name, action, action_tier, resource_attributes

5a. Response: authorized=true
    → exit 0 (tool executes normally, Claude Code unaware of check)

5b. Response: authorized=false
    → exit 2 (Claude Code block)
    → stdout: JSON block reason Claude reads
      {
        "decision": "block",
        "reason": "Stratium DENY: write_file requires INTERNAL_MODIFY (tier 2) but your delegation is scoped to READ_ONLY (tier 1). Ask your admin to update the stratium: block in CLAUDE.md."
      }

5c. Stratium unreachable (timeout / connection refused)
    → if fail_closed: exit 2 with reason "Stratium authorization service unavailable"
    → if fail_open: exit 0, append warning to stderr for audit
```

---

## 10. DENY Response Design

When a tool is blocked, the hook returns a structured block reason. Claude Code surfaces this as a tool error. Claude then explains it to the developer naturally:

**Example DENY for `write_file`:**
```
I attempted to write to src/auth.go but was blocked by Stratium:

  Tool:     write_file
  Decision: DENY
  Reason:   INTERNAL_MODIFY (tier 2) exceeds your delegation cap
            for this project (READ_ONLY, tier 1)

Your delegation for this session allows: read_file, list_files, grep_search
To write files in this project, ask your admin to update the
stratium: block in CLAUDE.md to include write_file and set
max_action_tier: INTERNAL_MODIFY.

Delegation ID: cc0c4885 (for your admin's reference)
```

This keeps the developer in flow — they understand what happened, why, and what to do next without leaving the Claude Code interface.

---

## 11. MDM Rollout (Jamf / Intune)

### 11.1 Admin Setup (one-time, Stratium side)

1. Create a `claude-code` agent template in Stratium PAP with base trust tier
2. Define per-project CLAUDE.md policies in each repo
3. Publish `@stratium/claude-hooks` to the company's private npm registry (Artifactory/Verdaccio) or use the public registry

### 11.2 MDM Script (runs on each managed device)

```bash
#!/bin/bash
# Deployed via Jamf Policy / Intune Remediation Script
# Runs as the logged-in user

set -euo pipefail

STRATIUM_GATEWAY="${STRATIUM_GATEWAY:-stratium.corp.com:50054}"
STRATIUM_PAP="${STRATIUM_PAP:-https://stratium.corp.com:8090}"
KEYCLOAK_URL="${KEYCLOAK_URL:-https://keycloak.corp.com}"
NPM_REGISTRY="${NPM_REGISTRY:-https://npm.corp.com}"

# Install package
npm install -g @stratium/claude-hooks \
  --registry "$NPM_REGISTRY" \
  --quiet

# Configure machine-level settings
stratium-hooks configure \
  --gateway     "$STRATIUM_GATEWAY" \
  --pap-url     "$STRATIUM_PAP" \
  --keycloak    "$KEYCLOAK_URL" \
  --realm       corp \
  --fail-closed \
  --silent

echo "Stratium Claude Code hooks installed and configured."
```

### 11.3 Developer Experience After MDM Push

1. MDM script runs silently in background (< 30 seconds)
2. Developer opens Claude Code — no visible change yet
3. On first prompt: "Authenticating with Stratium as alice@corp.com..." (< 2 seconds if token cached in OS keychain)
4. Session runs normally — ALLOW'd tools are invisible
5. If Claude attempts a blocked tool, Claude explains inline
6. Developer never installs anything, edits any config, or knows the hook exists unless they hit a DENY

---

## 12. Security Model

### 12.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Developer bypasses hook by uninstalling package | MDM re-runs install script hourly; `settings.json` is MDM-managed |
| Developer edits CLAUDE.md to widen their own scope | CLAUDE.md scope is validated against the Stratium PAP's registered agent policy; widening requires admin action in Stratium, not just a file edit |
| Delegation token stolen from /tmp | Token TTL is 4 hours; `/tmp/stratium-session-<pid>.json` is mode 0600; pid-scoped so tokens don't persist between sessions |
| Clock skew causing token expiry | Hook refreshes token when within 5 minutes of expiry |
| gRPC call adds latency to every tool call | Target: < 50ms p99; local Stratium < 10ms; token TTL caching prevents per-call network cost for identical tool+tier combinations |
| Developer runs Claude Code offline | Configurable: `fail_closed` blocks tools; `fail_open` allows with audit warning |

### 12.2 What CLAUDE.md Can and Cannot Do

CLAUDE.md controls the **requested scope** for a project. It **cannot**:
- Grant a scope wider than the developer's user entitlements in Stratium
- Override the registered agent's `allowed_tools` in the PAP
- Bypass classification caps set by the platform admin

The Stratium Platform's compound decision (user decision × agent decision × delegation decision) ensures CLAUDE.md is only additive within what the user is already entitled to.

---

## 13. Package Design

### 13.1 Package Structure

```
@stratium/claude-hooks/
├── bin/
│   └── stratium-hooks           # CLI: configure, status, revoke
├── src/
│   ├── session-init.js          # UserPromptSubmit handler
│   ├── pre-tool-use.js          # PreToolUse handler
│   ├── post-tool-use.js         # PostToolUse audit handler
│   ├── tier-map.js              # default tool → tier mapping
│   ├── claude-md-parser.js      # reads stratium: block from CLAUDE.md
│   ├── grpc-client.js           # thin grpcurl subprocess wrapper (no native grpc dep)
│   ├── auth.js                  # Keycloak OIDC + keychain token cache
│   └── agent-registry.js       # auto-register + ~/.claude/stratium-agent.json
├── package.json
└── README.md
```

### 13.2 Runtime Dependencies

The package uses `grpcurl` (already required by Stratium's dev tooling) via subprocess to avoid native gRPC compilation issues on developer machines. This trades a small process-spawn overhead (< 5ms) for zero native dependency problems.

| Dependency | Source | Notes |
|------------|--------|-------|
| `grpcurl` | PATH (pre-installed by MDM or Stratium setup) | gRPC calls |
| `curl` | System (macOS/Linux) | HTTP calls to PAP + Keycloak |
| `node` ≥ 18 | System | Hook runtime |
| `keychain` / `secret-tool` | OS | Token caching |

---

## 14. CLI Reference

```bash
# Initial setup (run by MDM or developer)
stratium-hooks configure \
  --gateway stratium.corp.com:50054 \
  --pap-url https://stratium.corp.com:8090 \
  --keycloak https://keycloak.corp.com \
  --realm corp \
  --fail-closed

# Show current session status
stratium-hooks status
# → Session: active | User: alice@corp.com | Delegation: cc0c4885 | Expires: 13:45

# Revoke current session delegation
stratium-hooks revoke

# Test connectivity to Stratium
stratium-hooks ping
# → ✓ PAP healthy | ✓ Agent Gateway reachable | ✓ Keycloak realm: corp

# Show effective scope for current project
stratium-hooks scope
# → Project: stratium (from CLAUDE.md)
# → Approved tools: read_file, list_files, grep_search
# → Max tier: READ_ONLY (1)
# → Classification caps: nato=CONFIDENTIAL
```

---

## 15. Observability

All authorization decisions are recorded in Stratium's existing audit log with the following additional fields for Claude Code sessions:

| Field | Value |
|-------|-------|
| `entity_type` | `tool_use` |
| `actor` | `alice@corp.com` (Keycloak subject) |
| `agent_id` | UUID of the claude-code agent |
| `delegation_id` | Session delegation UUID |
| `tool_name` | e.g., `write_file` |
| `action_tier` | numeric tier |
| `decision` | `ALLOW` / `DENY` |
| `project` | git repo name from cwd |
| `session_id` | Claude Code session/conversation ID |

This produces an auditable record: *"At 11:32 on 2026-03-30, alice@corp.com's Claude Code session attempted to write src/auth.go (INTERNAL_MODIFY, tier 2) and was DENIED because her delegation for the stratium project was scoped to READ_ONLY."*

---

## 16. Implementation Phases

### Phase 1 — MVP (local Stratium, single developer) ✅ COMPLETE

**Goal:** End-to-end working hooks on a single developer machine pointing at local docker-compose Stratium.

- [x] `session-init.js`: OIDC auth, auto-register agent, create delegation
- [x] `pre-tool-use.js`: ExecuteAction check with hard block on DENY
- [x] `tier-map.js`: default Claude Code tool → tier mapping
- [x] `claude-md-parser.js`: parse `stratium:` block from CLAUDE.md
- [x] `stratium-hooks configure` CLI command
- [x] `stratium-hooks status` / `ping` CLI commands
- [x] Fail-closed behavior when Stratium unreachable
- [x] Tested against local docker-compose stack (see docs/TESTING_CLAUDE_HOOKS.md)
- [x] README with setup instructions

**Acceptance test:** Developer running local Stratium can open Claude Code in a repo with a CLAUDE.md stratium block, have read tools ALLOW'd, and have write/execute tools DENY'd without any manual steps after initial `stratium-hooks configure`.

### Phase 2 — Enterprise hardening ✅ COMPLETE

- [x] OS keychain integration for token caching (macOS Keychain / GNOME Keyring via `src/keychain.js`)
- [x] `post-tool-use.js` audit enrichment (JSONL audit log at `~/.claude/stratium-audit.jsonl`)
- [x] MDM install script + Jamf-compatible packaging (`scripts/install-hooks.sh`, `deployment/jamf/`)
- [x] Bash command tier classification (regex rules for common dangerous patterns in `tier-map.js`)
- [x] Token refresh on expiry during long sessions (silent refresh in `auth.js`)
- [x] CLAUDE.md scope validation against PAP entitlements (`src/scope-validator.js`)
- [x] `stratium-hooks scope` CLI
- [x] `stratium-hooks revoke` CLI

### Phase 3 — Enterprise scale ✅ COMPLETE

- [x] Private npm registry publishing (`package.json` publishConfig, `.npmrc.template`, `.github/workflows/publish.yml` with public/private registry dispatch)
- [x] Intune / Jamf policy templates (`deployment/jamf/`, `deployment/intune/`)
- [x] MCP tool tier configuration (`mcp_tools:` block in CLAUDE.md, wired into `claude-md-parser.js`)
- [x] Admin override / emergency break-glass flow (`stratium-hooks override --reason <...>`)
- [x] Webhook notifications to Slack/Teams on DENY events (`src/notifications.js`)
- [x] Per-path classification detection (`globToRegex` + `detectClassification` in `pre-tool-use.js`)

---

## 17. Success Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Hook invocation latency (p99) | < 100ms | Stratium audit log timestamps |
| Session init time | < 3s (cold), < 500ms (warm) | Telemetry |
| DENY enforcement rate | 100% of out-of-scope tool calls blocked | Audit log analysis |
| MDM deployment time | < 2 min per device | MDM reporting |
| Developer friction (session auth) | 0 prompts after first session per day | Keychain cache hit rate |
| False positive rate | < 1% of expected-ALLOW calls denied | Error rate monitoring |

---

## 18. Open Questions

| # | Question | Owner | Resolution | Status |
|---|----------|-------|-----------|--------|
| OQ1 | Should `bash` command classification be static regex or LLM-assisted? | Security | **Static regex** (Phase 2 implementation): pattern arrays in `tier-map.js` for destructive (`rm -rf`, `dd`, `mkfs`), external (`curl`, `wget`, `ssh`), and read-only (`cat`, `ls`, `git log`) patterns. LLM-assisted classification deferred — would add latency and an LLM dependency to a security-critical code path. | ✅ Resolved |
| OQ2 | How should MCP tool tiers be configured? CLAUDE.md extension? | Platform | **CLAUDE.md `mcp_tools:` block** (Phase 3 implementation): per-server default tier + per-tool overrides injected into `tool_tiers` as `mcp__server__tool` entries. Parsed by `claude-md-parser.js`, enforced identically to built-in tools. | ✅ Resolved |
| OQ3 | Should `stratium-hooks configure` support SSO/device-flow auth (no password prompt)? | Auth | **Deferred to Phase 4**: current implementation uses Keycloak password grant + keychain caching. Once Keycloak device flow endpoint is exposed, `auth.js` can be extended with `keycloakDeviceGrant()`. For now, `STRATIUM_OIDC_PASSWORD` env var + cached keychain token covers the MDM deployment use case (password entered once per device). | 🔜 Phase 4 |
| OQ4 | Should delegation TTL be per-project (sensitive repos get shorter TTLs)? | Security | Phase 2 |
| OQ5 | What happens when a developer has multiple Claude Code windows open simultaneously? | Engineering | Phase 1 — each PID gets its own delegation |

---

## Appendix A: Hook Environment Variables

Claude Code passes the following to `PreToolUse` hook scripts:

| Variable | Content |
|----------|---------|
| `CLAUDE_TOOL_NAME` | e.g., `write_file` |
| `CLAUDE_TOOL_INPUT` | JSON string of tool arguments |
| `CLAUDE_SESSION_ID` | Claude Code session identifier |
| `CLAUDE_CWD` | Current working directory |
| `CLAUDE_PROJECT_ROOT` | Git repo root (if detected) |

## Appendix B: Hook Exit Codes

| Exit Code | Meaning | Claude Code Behavior |
|-----------|---------|----------------------|
| `0` | Allow | Tool executes normally |
| `2` | Block | Tool blocked; stdout JSON returned as tool error to Claude |
| non-zero (other) | Error | Claude Code behavior configurable; default: allow with warning |

## Appendix C: Relation to Existing Stratium Components

```
This PRD                    Existing Stratium
─────────────────────────── ─────────────────────────────────────
@stratium/claude-hooks  ──▶  PAP REST API       (agent registration)
  session-init.js        ──▶  Agent Gateway gRPC  (CreateDelegation)
  pre-tool-use.js        ──▶  Agent Gateway gRPC  (ExecuteAction)
  post-tool-use.js       ──▶  PAP REST API       (audit log read)
  stratium-hooks status  ──▶  PAP REST API       (health, delegation status)
  CLAUDE.md stratium:    ──▶  Platform Service   (compound decision policy)
```

The hooks package adds no new Stratium backend infrastructure. It is purely a client-side integration layer.
