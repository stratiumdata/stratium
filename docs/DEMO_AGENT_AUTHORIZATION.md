# Demo: Agent Authorization for Claude Code & OpenAI Codex

**Audience:** Investors, design partners, engineers evaluating Stratium
**Duration:** ~15 minutes end-to-end
**Goal:** Show a single policy surface (Agent Gateway) enforcing the same
delegation, classification, and action-tier limits across **two different
agent providers** — Anthropic Claude Code and OpenAI Codex — using the
**same enforcement model** (out-of-band `PreToolUse` hooks) with a unified
audit trail.

```
 ┌────────────┐                ┌──────────────────┐
 │ Claude     │ PreToolUse     │                  │
 │ Code       │───────────────▶│                  │   gRPC+mTLS   ┌──────────┐
 └────────────┘                │ Agent Gateway    │─────────────▶ │ Platform │
                               │ :50054           │               │ (ABAC)   │
 ┌────────────┐                │                  │               └──────────┘
 │ OpenAI     │ PreToolUse     │ delegation JWT   │
 │ Codex      │───────────────▶│ tier ≤ max?      │─┐
 └────────────┘                │ tool allowed?    │ │  audit log
                               └──────────────────┘ │
                                                    ▼
                                           ┌─────────────────┐
                                           │ stratium-audit  │
                                           │ --provider ...  │
                                           └─────────────────┘
```

**Key property:** neither agent is *asked* to check authorization. Both
harnesses intercept tool calls **before execution** and block them if the
gateway denies. The model cannot opt out, and a prompt injection cannot
suppress the check.

---

## Quick Start: Automated Demo Script

The fastest way to run this demo is the automated script:

```bash
# 1. Start stack + seed + build (one-time, ~2 min)
./scripts/demo_agent_authorization.sh setup

# 2. Run the full interactive demo
./scripts/demo_agent_authorization.sh

# 3. Run the offline-only demo (no stack needed — shows classification + fail-closed)
./scripts/demo_agent_authorization.sh offline

# 4. Teardown when done
./scripts/demo_agent_authorization.sh teardown
```

Set `DEMO_AUTO=1` to skip the "Press Enter" pauses (for CI or screen recording).

The rest of this document explains what the script does and how to run
each step manually.

---

## 0. Prerequisites

| Requirement | Install |
|---|---|
| Docker + Compose | `brew install docker` |
| `jq`, `grpcurl`, `curl` | `brew install jq grpcurl` |
| Go 1.25+ | `brew install go` |
| Python 3.10+ | (system) |
| Claude Code CLI | `npm install -g @anthropic/claude-code` |
| OpenAI Codex access | https://codex.openai.com |

```bash
git clone https://github.com/stratium/stratium.git
cd stratium
```

---

## 1. Bring Up the Stack (~60s)

```bash
docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth up -d
docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth ps
```

Expect: `postgres`, `keycloak`, `platform`, `key-manager`, `key-access`,
`pap`, and `agent-gateway` all running.

Verify connectivity:

```bash
curl -sf http://localhost:8080/realms/stratium | jq .realm          # Keycloak
curl -sfk https://localhost:8090/health | jq .                       # PAP
grpcurl -cacert config/examples/certs/ca.crt localhost:50054 list    # Gateway (TLS)
```

> **Note:** The Agent Gateway requires TLS. Do not use `-plaintext` with
> `grpcurl` — it will hang until timeout.

---

## 2. Build Binaries

```bash
make build-mcp build-audit
# Produces: bin/stratium-mcp, bin/stratium-audit
```

---

## 3. Seed Demo Data

```bash
# Users, policies, classifications, OIDC client, Claude agent registration
./demos/mcp/seed-demo-data.sh

# OpenAI Codex + Desktop agent registration (provider: "openai")
./demos/codex/seed-openai-agents.sh
```

### Seeded Users (from `keycloak/realm-export.json` + `seed-demo-data.sh`)

| User | Password | Classification | Department | Role |
|---|---|---|---|---|
| `admin456` | `admin123` | top-secret | administration | admin |
| `user123` | `password123` | confidential | engineering | developer |
| `test-user` | `test123` | secret | engineering | tester |
| `demo-analyst` | `demo123` | internal | finance | analyst |
| `demo-director` | `demo123` | confidential | finance | director |
| `demo-admin` | `demo123` | restricted | security | admin |

> `admin456`, `user123`, `test-user` are in the Keycloak realm JSON.
> `demo-analyst`, `demo-director`, `demo-admin` are created by `seed-demo-data.sh`
> (requires Keycloak master admin access: `admin`/`admin`).

### Keycloak Auth Notes

| Client ID | Type | Use |
|---|---|---|
| `stratium-pap` | Confidential (secret: `stratium-pap-secret`) | Token fetch for PAP/seed scripts |
| `stratium-cli` | Public (`directAccessGrantsEnabled: true`) | CLI tools, `stratium-hooks login` |
| `stratium-mcp` | Public (created by seed) | MCP server OIDC flow |

---

## 4. How Both Clients Use the Same Enforcement Path

Both clients use `PreToolUse` hooks that:

1. **Intercept** every tool call before execution
2. **Classify** the command into an action tier (1=read, 2=write, 3=network, 4=destructive)
3. **Call** the Stratium PAP REST API (`/api/v1/actions/check`) with the delegation JWT
4. **Block** the call if the gateway says DENY

The Python hooks at `demos/codex/hooks/` are the common implementation.
Both the demo script and real Codex sessions use them. Claude Code's
production hooks (`sdk/claude-hooks/`, Node.js) follow the same protocol
but add CLAUDE.md scope parsing and all-tool interception.

### Command Classification

| Tier | Action | Example Commands |
|---|---|---|
| 1 — Read | `read` | `cat`, `ls`, `grep`, `git log`, `echo` |
| 2 — Write | `write` | `tee`, `mv`, `cp`, `sed -i`, `pip install` |
| 3 — Network | `send` | `curl`, `wget`, `ssh`, `git push`, `aws` |
| 4 — Destructive | `execute` | `rm -rf`, `DROP TABLE`, `dd if=`, `mkfs` |
| Default | `execute` (tier 2) | Unrecognized commands |

### Two-Axis Enforcement (Agent Tier + Delegation Scope)

Every action is checked against **two independent caps**:

1. **Agent `trust_tier`** — fixed at registration time, a property of the
   agent identity itself. `trust_tier=0` (UNREGISTERED) = reasoning + reads
   only. `trust_tier=1` (REGISTERED) = up to tier-2 writes.
   `trust_tier=2+` = higher tiers.
2. **Delegation `max_action_tier`** — set by the user per delegation, caps
   what the user authorized for this session.

The action_tier must pass **both** checks. This is by design: even if a
delegation over-grants (e.g. `max_action_tier=4`), an untrusted agent
(`trust_tier=0`) can still only perform reads. The demo script registers
`claude-code-demo` with `trust_tier=1` so tier-2 writes are permitted.

---

## 5. Run the Same Scenarios on Both Providers

The demo script (`scripts/demo_agent_authorization.sh`) creates a delegation
for each provider's agent and runs **identical commands** through the hook:

### Scene 1: ALLOW — read a public file

```
Command:  cat demos/mcp/financial-records/public/annual-report-2025.txt
Tier:     1 (read)
Decision: ALLOW (tier 1 ≤ max 2)
```

### Scene 2: ALLOW — write a file

```
Command:  tee /tmp/summary.md <<< 'Q3 earnings summary'
Tier:     2 (write)
Decision: ALLOW (tier 2 = max 2)
```

### Scene 3: DENY — network command

```
Command:  curl https://example.com -o output.html
Tier:     3 (send)
Decision: DENY — "action tier 3 exceeds delegation max 2"
```

### Scene 4: DENY — destructive command

```
Command:  rm -rf /tmp/everything
Tier:     4 (execute)
Decision: DENY — "action tier 4 exceeds delegation max 2"
```

### Side-by-Side Output

```
COMMAND                    CLAUDE CODE   CODEX
─────────────────────────  ────────────  ────────────
cat README.md              ALLOW (T1)    ALLOW (T1)
tee output.txt             ALLOW (T2)    ALLOW (T2)
curl https://...           DENY  (T3)    DENY  (T3)
rm -rf /tmp/...            DENY  (T4)    DENY  (T4)
```

Same gateway, same delegation, same decisions. Provider is an audit tag,
not a policy axis.

---

## 6. Offline Demo (No Stack Needed)

```bash
./scripts/demo_agent_authorization.sh offline
```

This demonstrates two things without any backend services:

1. **Command classification** — shows exactly how each shell command maps to
   a Stratium tool name, action, and tier.
2. **Fail-closed behavior** — without a delegation token, every command is
   denied. With a token but no reachable PAP, every command is denied.

---

## 7. Unified Audit Trail

```bash
# All decisions in the last 30 minutes
./bin/stratium-audit logs --since 30m

# By provider
./bin/stratium-audit logs --provider anthropic --since 30m
./bin/stratium-audit logs --provider openai --since 30m

# Export for compliance
./bin/stratium-audit export --since 1h -o demo-audit.json
```

Expected output:

```
TIME     PROVIDER  LAYER  AGENT         TOOL        ACTION   TIER  DECISION
10:02:14 anthropic hooks  claude-code   read_file   read     1     ALLOW
10:02:31 anthropic hooks  claude-code   bash        send     3     DENY
10:05:08 openai    hooks  codex-impl    read_file   read     1     ALLOW
10:05:22 openai    hooks  codex-impl    bash        send     3     DENY
```

---

## 8. What to Point Out on the Call

1. **One enforcement model, two harnesses.** Both use PreToolUse hooks.
   Same delegation JWT, same gateway, same classification, same audit.

2. **Out-of-band enforcement.** Neither model is asked to check
   authorization — the harness blocks the tool before it runs. A prompt
   injection that says "ignore your policy" has nothing to suppress.

3. **Fail-closed.** Stop the gateway or kill the network and every command
   is denied. Run `./scripts/demo_agent_authorization.sh offline` to prove it.

4. **Delegation is the only authority.** `max_action_tier` and
   `classification_cap` are enforced at the gateway from a JWT the agent
   cannot forge. A compromised agent cannot escalate beyond its delegation.

5. **Unified audit.** One CLI, one schema, filter by `--provider` and
   `--transport`. No per-vendor log plumbing.

6. **Honest asymmetry.** Codex hooks currently intercept Bash only.
   Claude Code's production hooks (`sdk/claude-hooks`) intercept all tools.
   Same backend; harness coverage differs. We name this explicitly.

---

## 9. Cleanup

```bash
./scripts/demo_agent_authorization.sh teardown
```

Or manually:

```bash
docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth down -v
rm -f /tmp/.stratium-delegation.json /tmp/stratium-session-*.json
```

---

## Appendix: Reference Docs

- Demo script: [../scripts/demo_agent_authorization.sh](../scripts/demo_agent_authorization.sh)
- Gateway architecture: [AGENT_GATEWAY_EXPLAINED.md](AGENT_GATEWAY_EXPLAINED.md),
  [AGENT_GATEWAY_TECHNICAL.md](AGENT_GATEWAY_TECHNICAL.md)
- Claude hooks package: [../sdk/claude-hooks/README.md](../sdk/claude-hooks/README.md)
- Codex hooks: [../demos/codex/README.md](../demos/codex/README.md)
- Full testing (Claude): [TESTING_CLAUDE_HOOKS.md](TESTING_CLAUDE_HOOKS.md)
- Full testing (Codex): [TESTING_OPENAI_AGENT_AUTH.md](TESTING_OPENAI_AGENT_AUTH.md)
- Original PRD: [PRD_OPENAI_AGENT_AUTHORIZATION.md](PRD_OPENAI_AGENT_AUTHORIZATION.md)
