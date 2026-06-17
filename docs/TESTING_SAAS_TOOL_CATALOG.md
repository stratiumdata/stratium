# Manual Testing — SaaS Tool Catalog (GitHub)

How to verify the SaaS tool catalog end-to-end: the GitHub reference tool, Keycloak-brokered
credentials, and the classification-aware authorization that gates every tool call.

- **Feature spec:** `docs/superpowers/specs/2026-06-17-saas-tool-catalog-design.md`
- **Demo quickstart:** `demos/catalog-github/README.md`
- **Audience:** engineers verifying the feature on a local stack.

---

## 0. What you are testing

A catalog tool call (e.g. `github_read_file`) flows through three checks before any GitHub API
request is made:

```
Claude/Codex agent
  │  MCP call: github_read_file{repo, path}
  ▼
stratium-mcp catalog handler
  │  1. resolve repo classification (config map; fail-closed)
  │  2. ExecuteAction → Agent Gateway (:50054)  ── compound decision: user ∧ agent ∧ delegation
  │       (approved_tools? action_tier ≤ max? classification ≤ cap?)
  │  3. if authorized: fetch GitHub token from Keycloak /broker/github/token
  ▼
GitHub REST API → result   (DENY short-circuits here — GitHub is never called)
```

You are verifying: **(a)** the authorization gate allows/denies correctly, **(b)** classification
is enforced and **fails closed**, **(c)** brokered credentials are retrieved, and **(d)** denials
never reach GitHub.

---

## 1. Layer 1 — Automated tests (fast confidence, no infra)

Run from the repo's `go/` directory. None of this needs Docker.

```bash
cd go

# Catalog feature packages (unit + handler tests, race + coverage)
go test ./internal/catalog/... ./internal/tools/ -race -cover
#   expect: ok  stratium/internal/catalog          ~85%
#           ok  stratium/internal/catalog/github   ~93%
#           ok  stratium/internal/tools

# The shared classification primitive the gate relies on
go test ./pkg/classification/ -race -cover     # expect 100%

# Whole module builds + vets clean
go build ./...
go vet ./internal/catalog/... ./internal/tools/ ./pkg/classification/ ./cmd/stratium-mcp/

# Full suite (should be green)
go test ./...                                   # expect: no FAIL lines

# Optional: security scan of the catalog code (needs gosec installed)
gosec -quiet ./internal/catalog/... ./pkg/classification/   # expect 0 issues
```

What the automated tests already prove (so you don't have to re-check by hand): the action-tier
ladder, fail-closed classification resolution, URL-input encoding, the credential-error path, and
the hierarchy-aware/fail-closed cap comparison. The manual tests below verify the **wiring** that
unit tests can't: real Keycloak brokering, the live gateway, and the agent experience.

---

## 2. Layer 2 — Manual end-to-end setup

### 2.1 Start the backend stack

```bash
make docker-up        # = docker-compose -f deployment/docker/docker-compose.yml --profile agent-auth up -d
```

Wait until healthy, then confirm the services you need:

| Service | Address | Used by the catalog |
|---|---|---|
| Agent Gateway (gRPC) | `localhost:50054` | `ExecuteAction` authorization |
| PAP API (REST) | `https://localhost:8090` | delegations + `/actions/check` |
| Keycloak | `http://localhost:8080` | identity + GitHub brokering |
| PostgreSQL | `localhost:5432` | delegations, audit |

Realm is `stratium`. Keycloak master admin is `admin` / `admin`.

### 2.2 Seed demo identities

```bash
make seed-demo        # = ./demos/mcp/seed-demo-data.sh
```

Creates the `stratium-mcp` OIDC client and demo users (e.g. `demo-analyst` / `demo123`).

### 2.3 Build the MCP server and audit CLI

```bash
make build-mcp build-audit     # → bin/stratium-mcp, bin/stratium-audit
```

### 2.4 Catalog-specific: GitHub OAuth app + Keycloak brokering

This is the only catalog-unique infra. It is what makes `github_*` tools able to call GitHub on the
user's behalf without you wiring OAuth yourself.

1. **Create a GitHub OAuth App** (GitHub → Settings → Developer settings → OAuth Apps → New):
   - Homepage URL: `http://localhost:8080`
   - Authorization callback URL:
     `http://localhost:8080/realms/stratium/broker/github/endpoint`
   - Note the **Client ID** and generate a **Client secret**.

2. **Provide the credentials to Keycloak.** The realm export (`keycloak/realm-export.json`) declares
   the `github` IdP with `${GITHUB_OAUTH_CLIENT_ID}` / `${GITHUB_OAUTH_CLIENT_SECRET}` placeholders.
   Set those in the Keycloak container environment (or replace them in a local realm import), then
   restart Keycloak so the import picks them up. Confirm the IdP exists:
   - Keycloak Admin Console → realm `stratium` → Identity providers → **github** should be present
     with **Store tokens = ON** and **Stored tokens readable = ON**, scope `repo`.

3. **Link your GitHub account to your Stratium user.** Log in to the Keycloak Account Console as the
   user you'll test with (`http://localhost:8080/realms/stratium/account`) → **Account security →
   Linked accounts → GitHub → Link**. Approve the GitHub consent. This is what populates the brokered
   token that `github_*` tools retrieve.

> Verify the broker endpoint works (optional): with a Keycloak access token for the linked user that
> carries the `broker` `read-token` role, `GET http://localhost:8080/realms/stratium/broker/github/token`
> returns the GitHub token. The catalog does this for you; this is only to debug "not linked" errors.

### 2.5 Create the catalog config file

The catalog is **opt-in**. Without a config file it is invisible (zero `github_*` tools registered).
Create `~/.stratium/catalog.json`. **Classification level names must match `pkg/classification`**
(see the table in §4) — use canonical NATO names for the clearest examples:

```json
{
  "enabled": true,
  "providers": ["github"],
  "github": {
    "base_url": "https://api.github.com",
    "default_classification": { "classification": "UNCLASSIFIED", "hierarchy": "nato" },
    "repo_classifications": {
      "<your-org>/internal-svc": { "classification": "CONFIDENTIAL", "hierarchy": "nato" },
      "<your-org>/secret-svc":   { "classification": "SECRET",       "hierarchy": "nato" }
    }
  }
}
```

Replace `<your-org>/...` with two real repositories your GitHub account can access (a lower- and a
higher-classified one). `default_classification` applies to any repo not listed; **remove it** to
test the fail-closed path in §3 Scenario 5.

### 2.6 Register the catalog-enabled MCP server

Point your MCP client at `bin/stratium-mcp` with the `-catalog-config` flag. For **Claude Code**,
in `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "stratium": {
      "command": "/ABSOLUTE/PATH/stratium/bin/stratium-mcp",
      "args": [
        "-catalog-config", "/ABSOLUTE/PATH/.stratium/catalog.json",
        "-gateway", "localhost:50054",
        "-keycloak", "http://localhost:8080/realms/stratium"
      ]
    }
  }
}
```

(For Claude Desktop, put the same block in
`~/Library/Application Support/Claude/claude_desktop_config.json`.) Restart the client. On startup
`stratium-mcp` logs `catalog enabled: registered 4 GitHub tools`. If you don't see the `github_*`
tools, the catalog config is missing or `enabled` is false.

---

## 3. Track A — Conversational end-to-end (Claude)

This is how a real user exercises the feature. In a Claude session with the stratium MCP connected,
drive the tools in natural language; Claude calls the MCP tools. First register an agent and a scoped
delegation, then attempt the catalog actions.

**Setup (once per session):**
1. "Register an agent" → calls `register_agent` (provider `anthropic`, trust_tier 1).
2. "Create a delegation scoped to `github_read_file` and `github_create_issue`, max action tier 2,
   classification cap `nato: CONFIDENTIAL`, purpose 'manual catalog test'." → calls
   `create_delegation`. Note the returned delegation token/id.

**Scenarios** (expected outcomes assume the config + delegation above):

| # | What you ask | Tool | Expected |
|---|---|---|---|
| 1 | "Read `README.md` from `<org>/internal-svc`" | `github_read_file` | **ALLOWED** — returns file content. (CONFIDENTIAL ≤ cap CONFIDENTIAL; tier 1 ≤ 2; tool in scope.) |
| 2 | "Read `README.md` from `<org>/secret-svc`" | `github_read_file` | **DENIED** — reason: classification SECRET exceeds delegation cap CONFIDENTIAL. GitHub is never called. |
| 3 | "Open an issue titled 'test' on `<org>/internal-svc`" | `github_create_issue` | **ALLOWED** — returns issue number/URL. (tier 2 ≤ 2; tool in scope.) |
| 4 | "Delete the branch `tmp` on `<org>/internal-svc`" | `github_delete_branch` | **DENIED** — tool not in `approved_tools`, and tier 4 > max 2. |
| 5 | "Read `README.md` from `<org>/unlisted-repo`" (a repo NOT in `repo_classifications`, with `default_classification` removed) | `github_read_file` | **DENIED** — fail-closed: "classification unknown and no default configured". |

Scenario 1 succeeding also proves **brokering** (Scenario 4 of §0): the handler retrieved the GitHub
token from Keycloak and made a real API call. If Scenario 1 returns "GitHub account not linked or token
unavailable," revisit §2.4 step 3.

---

## 4. Track B — Scriptable authorization checks (the security behavior)

The authorization logic — especially the classification cap fix — is deterministically testable via
the PAP REST endpoint `POST /api/v1/actions/check`, the same gate catalog tools call. This needs no
GitHub and no Claude.

**Canonical classification levels** (from `go/pkg/classification/classification.go`; anything else is
"unknown" and **denies**):

| Hierarchy | Levels (low → high) |
|---|---|
| `nato` | UNCLASSIFIED, RESTRICTED, CONFIDENTIAL, SECRET, TOP-SECRET |
| `commercial` | PUBLIC, INTERNAL, CONFIDENTIAL-COMMERCIAL, RESTRICTED-COMMERCIAL, HIGHLY-CONFIDENTIAL |

**Get a delegation token** with a known cap. The easiest path is the `create_delegation` MCP tool
(Track A) — copy the returned `delegation_token`. Then:

```bash
TOKEN='<paste delegation_token; created with classification_caps {"nato":"CONFIDENTIAL"}>'
PAP='https://localhost:8090'

check() {  # usage: check <classification> <hierarchy> <tool> <action> <tier>
  curl -sk -X POST "$PAP/api/v1/actions/check" \
    -H "Content-Type: application/json" \
    -d "{\"delegation_token\":\"$TOKEN\",\"tool_name\":\"$3\",\"action\":\"$4\",\"action_tier\":$5,\"resource_classification\":\"$1\",\"resource_hierarchy\":\"$2\"}" | jq .
}
```

| Test | Command | Expected |
|---|---|---|
| Within cap | `check CONFIDENTIAL nato github_read_file read 1` | `authorized: true` |
| Over cap | `check SECRET nato github_read_file read 1` | `authorized: false`, reason "exceeds delegation cap" |
| **Fail-closed: missing hierarchy** | `check SECRET "" github_read_file read 1` | `authorized: false`, reason "…without a hierarchy attribute (ambiguous)" |
| **Fail-closed: unknown level** | `check ULTRA nato github_read_file read 1` | `authorized: false`, reason "unknown classification level" |
| Different hierarchy than cap | `check INTERNAL commercial github_read_file read 1` | `authorized: true` (no commercial cap set) |
| Tier over max | `check CONFIDENTIAL nato github_delete_branch delete 4` | `authorized: false`, reason "exceeds max_action_tier" |

The two **fail-closed** rows are the regression checks for the security fixes — an empty/omitted
hierarchy or an unrecognized level must **deny**, never silently allow.

---

## 5. Verify via the audit trail

Every decision (allow and deny) is recorded.

```bash
./bin/stratium-audit logs --since 10m          # recent decisions with tool, tier, decision, reason
./bin/stratium-audit chain <delegation-id>     # the delegation chain that authorized a call
./bin/stratium-audit export --since 1h -o catalog-test-audit.json
```

For each scenario above, confirm an audit row exists with the expected `tool_name`, `action_tier`,
and `decision`. A correct DENY shows the denying principal and reason; a correct ALLOW shows the tool
proceeded. (Claude Code also writes a local JSONL trail at `~/.claude/stratium-audit.jsonl`.)

---

## 6. Expected-results matrix (the success criteria)

The feature passes manual testing when all of these hold, with a delegation scoped to
`["github_read_file","github_create_issue"]`, `max_action_tier: 2`, cap `nato: CONFIDENTIAL`:

- [ ] CONFIDENTIAL-repo read → **ALLOWED**, returns content (proves brokering + read path).
- [ ] SECRET-repo read → **DENIED** (classification > cap).
- [ ] `github_create_issue` on an in-cap repo → **ALLOWED**.
- [ ] `github_delete_branch` → **DENIED** (out of scope; tier 4 > 2).
- [ ] Unlisted repo with no default → **DENIED** (fail-closed).
- [ ] `/actions/check` with classification but no hierarchy → **DENIED** (fail-closed).
- [ ] `/actions/check` with unknown level → **DENIED**.
- [ ] Every decision appears in `stratium-audit logs`.
- [ ] A normal `stratium-mcp` run **without** `-catalog-config` registers **no** `github_*` tools
      (catalog stays opt-in / off by default).

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| No `github_*` tools in the client | Catalog disabled | `-catalog-config` flag missing, file absent, or `"enabled": false` |
| "GitHub account not linked or token unavailable" | Brokered token missing | Link GitHub in the Keycloak Account Console (§2.4 step 3); confirm `read-token` role |
| Every classified read DENIES as "unknown classification level" | Non-canonical level name | Use the exact level strings in §4 (commercial uses `CONFIDENTIAL-COMMERCIAL`, not `CONFIDENTIAL`) |
| Reads of unlisted repos unexpectedly ALLOWED | `default_classification` set | Remove it to fail-closed, or set it to your intended floor |
| `ExecuteAction` / `/actions/check` errors with connection refused | Gateway/PAP not up | `make docker-up`; check `localhost:50054` and `https://localhost:8090/health` |
| `/actions/check` returns 501 "not enabled" | Agent-auth feature off | The PAP image must be built with `agent-auth` (the compose `agent-auth` profile) |

---

## 8. Teardown

```bash
make docker-down            # stop services
# make docker-down-volumes  # also wipe Postgres/Keycloak state for a clean re-test
```

---

## Appendix — automated test → behavior map

| Test file | Covers |
|---|---|
| `go/internal/catalog/classifier_test.go` | classification resolution, fail-closed on unknown |
| `go/internal/catalog/tier_test.go` | action-tier mapping + anti-spoofing guard |
| `go/internal/catalog/credential_test.go` | Keycloak broker retrieval, static token, broker-token parsing |
| `go/internal/catalog/config_test.go` | catalog config loading + defaults |
| `go/internal/catalog/github/client_test.go` | GitHub REST client, URL encoding, API errors |
| `go/internal/catalog/github/tools_test.go` | handler allow/deny/fail-closed, repo validation, credential-error path |
| `go/internal/tools/catalog_github_test.go` | gateway adapter reason extraction |
| `go/pkg/classification/classification_test.go` | hierarchy index + fail-closed cap comparison (incl. empty-value regression) |
