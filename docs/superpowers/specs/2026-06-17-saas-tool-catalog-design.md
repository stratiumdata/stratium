# Pre-Built SaaS Tool Catalog — Design Spec (v1)

- **Date:** 2026-06-17
- **Status:** Approved for implementation planning
- **Feature:** Workstream A, sub-project 1 — catalog framework + first reference tool
- **Owner:** Stratium

---

## 1. Context & motivation

Stratium ships an MCP server (`stratium-mcp`) with authorization-domain tools (`register_agent`,
`create_delegation`, `execute_action`, etc.) but **no catalog of pre-built SaaS-app tools**. Competitors
(Arcade) ship Gmail/Slack/Salesforce/Microsoft tools out of the box with managed OAuth, which lets a casual
evaluator wire an agent to a real SaaS app in minutes. The absence of such a catalog is a first-order product
gap for the SaaS-integration segment.

This spec closes the *first slice* of that gap **without diluting Stratium's differentiator**. A Stratium
catalog tool is not a generic API wrapper — every call routes through `ExecuteAction` and carries
**classification attributes**, so the same compound-decision engine that authorizes the action also enforces
clearance. The wedge is "GitHub access that is classification-aware and per-hop attributable," not "we have
GitHub too."

### Positioning guardrail (load-bearing)

The catalog is **opt-in and disabled by default**. A regulated, sovereign, or air-gapped deployment runs with
the catalog off and loses nothing — it remains a pure policy-decision plane. This preserves the regulated-ICP
brand: the catalog *extends* the differentiator (classification-gated tools) rather than adopting the
"agents-as-users" model Stratium argues against.

---

## 2. Scope

### In scope (v1)

- A reusable **catalog framework**:
  - A `CredentialProvider` abstraction (Keycloak brokering + static-token fallback).
  - A **tool-definition standard**: naming conventions, MCP schema standard, declared action + action-tier,
    classification-relevant input fields. (This is the "tool catalog spec doc + naming conventions + MCP tool
    schema standard" deliverable.)
  - A config-gated registration group (`registerCatalogTools`).
  - A default-policy-template format (JSON baseline + Cedar variant).
- **One reference tool — GitHub** — minimal surface spanning the tier ladder:
  - `github_read_file` (tier 1)
  - `github_search_code` (tier 1)
  - `github_create_issue` (tier 2)
  - `github_delete_branch` (tier 4)
- **Keycloak GitHub brokering** wired end-to-end: a catalog tool obtains a live GitHub token via
  `/realms/{realm}/broker/github/token`.
- **Classification-aware enforcement**: repo/file classification flows into `resource_attributes` and is
  evaluated by `ExecuteAction`.
- Tests (≥80% coverage) and a runnable demo.

### Out of scope (deferred, intentionally)

| Deferred item | Why / where it lands |
|---|---|
| Token auto-refresh | GitHub tokens don't expire; proven by the next tool (M365). |
| Tier-3 external-comms egress wedge | No natural GitHub egress; proven by M365 (mail send). |
| The other five catalog tools (M365, ServiceNow, Slack, Splunk, Salesforce) | Each gets its own thin spec on this framework. |
| Standalone `stratium-oauth` coordinator | Keycloak **is** the coordinator (see §4). |
| Separate `stratium-catalog` service | In-process module for now; extract later only if the catalog grows large. |
| In-repo classification marker file | Future enhancement; v1 uses a config-driven map. |
| Path/file-level classification granularity | v1 resolves at repo level. |

---

## 3. Key decisions (with rationale)

| # | Decision | Chosen | Alternatives considered | Why |
|---|---|---|---|---|
| 1 | Spec scope | Framework + 1 reference tool | Framework-only; one-tool-no-framework | Proves the reusable pattern end-to-end while shipping something real. |
| 2 | SaaS credential layer | **Keycloak Identity Brokering** | Dedicated `stratium-oauth` coordinator; hybrid (Keycloak + KEK re-cache) | No second OAuth subsystem; reuses the IdP already deployed. Keycloak 26.4+ auto-refreshes brokered tokens on retrieval, removing the historical reason to build a coordinator. |
| 3 | Reference tool | **GitHub** | M365 mail; Slack | Dogfoodable, trivial credentials, no Microsoft-tenant setup friction; proves framework on the simplest tool. M365 becomes tool #2 (proves refresh + tier-3 egress). |
| 4 | GitHub credential path | **Brokered via Keycloak** | Static PAT | Keeps the brokering architecture honest by exercising the brokered-retrieval path in v1 (refresh still deferred — GitHub tokens don't expire). |

### Note on the two "OAuth" directions

These are distinct layers and do not conflict:
- **Inbound** (exists today): Keycloak authenticates the *user to Stratium*; Stratium is the relying party.
- **Outbound** (this gap): Stratium calls *GitHub on the user's behalf*; Stratium is the OAuth client and GitHub
  is the authority. Decision #2 makes Keycloak provide the outbound token too (via brokering), so there is one
  identity system, not two.

---

## 4. Architecture

### 4.1 Where it lives

**In-process module** in the existing `stratium-mcp` binary. A new package `go/internal/catalog/` exposes a
`registerCatalogTools(server)` group, called from `Registry.RegisterAll()`
(`go/internal/tools/registry.go:71`), gated by a `catalog.enabled` config flag. Reuses the existing gateway
client, auth provider, and registry. The alternative (a separate `stratium-catalog` gRPC service like
agent-gateway) is deferred — premature for framework + 1 tool.

### 4.2 Components

1. **`CredentialProvider` interface**
   - `GetToken(ctx context.Context, userID, provider string) (string, error)`
   - Implementations:
     - `KeycloakBroker` — calls `GET /realms/{realm}/broker/{provider_alias}/token` with the user's Keycloak
       access token (which must carry the `broker` client role `read-token`); returns the live external-IdP
       token. Relies on Keycloak's **Store Token** setting on the brokered IdP. Auto-refresh (Keycloak 26.4+)
       applies to tokens that expire — not exercised by GitHub in v1.
     - `StaticToken` — config/env fallback for tokens-only SaaS (PATs, bearer tokens). Defined but **not** the
       reference path.
   - The reference tool uses `KeycloakBroker`.

2. **Tool-definition standard** (the catalog "schema standard"):
   - **Naming:** `<provider>_<verb>_<object>` (e.g., `github_read_file`).
   - **Schema:** standard `mcp.Tool` + `mcp.ToolSchema` (`go/internal/mcp/types.go:64-85`).
   - Each tool declares: `action` (string), `action_tier` (`models.ActionTier`), and which input fields identify
     classification-relevant resources.
   - **Anti-spoofing guard:** the framework validates each tool's declared tier against `assessActionTier`
     (`go/services/agent-gateway/server.go:966-979`) at registration time; a tool whose declared tier is lower
     than the assessed tier for its action fails to register (hard startup error).

3. **GitHub tool package** (`go/internal/catalog/github/`):
   - The four operations (§5).
   - A thin GitHub REST client (standard library HTTP or `google/go-github`; chosen at implementation time).
   - Repo→classification resolution (§6).

4. **Handler pattern** (identical for every future tool):
   ```
   parse args
     → resolve classification → resource_attributes
     → gateway.ExecuteAction(delegationToken, tool_name, action, action_tier, resource_attributes)
     → if !Authorized: return structured denial (reason, denied_principal, denied_at_depth)  [GitHub NOT called]
     → else: token := CredentialProvider.GetToken(userID, provider); call GitHub API; return result
   ```
   This mirrors the existing `handleExecuteAction` pattern (`go/internal/tools/actions.go:84-158`).

5. **Config + Keycloak realm**:
   - A `catalog` config block in `go/config/config.go` (see §8).
   - GitHub registered as a brokered IdP in the `keycloak/` realm config with **Store Token = ON** and
     **Stored Tokens Readable** so users get the `read-token` role.

### 4.3 Extension points (code anchors)

| Concern | File | Anchor |
|---|---|---|
| Register catalog tools | `go/internal/tools/registry.go` | `RegisterAll()` (line ~71) — add `registerCatalogTools(server)` |
| Tool / schema types | `go/internal/mcp/types.go` | `Tool`, `ToolSchema`, `PropertySchema` (lines 64–85) |
| Tool handler signature | `go/internal/mcp/server.go` | `ToolHandler` (line 16), `RegisterTool` (lines 36–40) |
| Authorization gate | `go/services/agent-gateway/server.go` | `ExecuteAction` (lines 246–336) |
| Action-tier assessment | `go/services/agent-gateway/server.go` | `assessActionTier` (lines 966–979) |
| Handler reference pattern | `go/internal/tools/actions.go` | `handleExecuteAction` (lines 84–158) |
| Delegation model | `go/pkg/models/delegation.go` | `Delegation`, `ActionTier` |
| Cross-provider guarantee | `go/services/agent-gateway/cross_provider_test.go` | extend with a GitHub catalog tool case |

---

## 5. Reference tool: GitHub

Minimal surface chosen to span the tier ladder and exercise classification caps on both read and destructive
paths. (GitHub has no natural tier-3 egress; that wedge is proven by M365 next.)

| Tool | `action` | `action_tier` | Classification check | Inputs |
|---|---|---|---|---|
| `github_read_file` | `read` | 1 (READ_ONLY) | repo classification ≤ cap | `repo`, `path`, `ref?` |
| `github_search_code` | `search` | 1 (READ_ONLY) | repo classification ≤ cap (per hit) | `repo`, `query` |
| `github_create_issue` | `create` | 2 (INTERNAL_MODIFY) | repo classification ≤ cap | `repo`, `title`, `body` |
| `github_delete_branch` | `delete` | 4 (DESTRUCTIVE) | repo classification ≤ cap; tier ≤ `max_action_tier` | `repo`, `branch` |

Declared tiers match `assessActionTier` mappings (`read`/`search`→1, `create`→2, `delete`→4), so all four pass
the anti-spoofing guard.

---

## 6. Classification model

GitHub has no native classification field, so classification is **supplied by Stratium**:

- **Source (v1): config-driven repo→classification map.**
  ```
  catalog.github.repo_classifications:
    "acme/secret-repo":   { classification: "CONFIDENTIAL", hierarchy: "commercial" }
    "acme/public-docs":   { classification: "PUBLIC",       hierarchy: "commercial" }
  catalog.github.default_classification: { classification: "INTERNAL", hierarchy: "commercial" }
  ```
- **Granularity:** repo level (path/file level deferred).
- **`resource_attributes` emitted:** `{ resource_id: "<owner>/<repo>[:<path>]", classification, hierarchy, provider: "github" }`.
- **Fail-closed:** if a repo cannot be resolved **and** no default is configured, the resolver returns the
  maximum classification (→ deny). Unknown never resolves to PUBLIC. This is a security-critical invariant.

Future enhancement: an in-repo `.stratium/classification.yaml` marker, which (because it is writable by anyone
with repo access) may only **raise** classification relative to the config map, never lower it.

---

## 7. Data flow

```
Agent (Claude / Codex)
  │  MCP call: github_read_file{repo, path, ref}
  ▼
Catalog handler (in-process, stratium-mcp)
  │  1. parse args
  │  2. resolve repo classification  → resource_attributes
  │  3. ExecuteAction(delegationToken, "github_read_file", "read", 1, resource_attributes)
  ▼
Agent Gateway — compound decision
  │  user policy ∧ agent policy ∧ delegation scope
  │   (approved_tools? tier ≤ max_action_tier? classification ≤ cap[hierarchy]?)
  ├── Authorized=false → structured denial (reason, denied_principal, denied_at_depth)  ──► returned to agent
  │                                                                                         (GitHub NOT called)
  └── Authorized=true
         │  CredentialProvider.GetToken(userID, "github")
         ▼
       Keycloak  GET /realms/{realm}/broker/github/token  (Bearer = user's Keycloak token w/ read-token)
         │  → live GitHub access token
         ▼
       GitHub REST API  → result  ──► returned to agent
  ▼
Audit (existing path): tool_name, action_tier, decision, transport written by gateway/PAP
```

---

## 8. Configuration

New `catalog` block in `go/config/config.go`:

```
catalog:
  enabled: false                 # opt-in; off by default (positioning guardrail)
  providers: ["github"]          # which catalog providers are active
  github:
    broker_alias: "github"       # Keycloak IdP alias
    default_classification: { classification: "INTERNAL", hierarchy: "commercial" }
    repo_classifications: { ... } # see §6
```

Keycloak realm (`keycloak/`): add GitHub as a brokered Identity Provider, **Store Token = ON**,
**Stored Tokens Readable = ON** (assigns `read-token`), with the OAuth app's `client_id`/`client_secret` and the
scopes required for repo read + issue create + branch delete.

---

## 9. Default policy templates

Each catalog tool ships a default, adoptable-or-overridable policy template. v1 ships:
- **JSON** (always-supported baseline).
- **Cedar** variant (recently added engine; expresses tier/classification rules cleanly).

Template intent (illustrative): allow `github_read_file`/`github_search_code` when repo classification ≤
subject cap; allow `github_create_issue` for trust tier ≥ Registered; allow `github_delete_branch` only for
trust tier ≥ Certified **and** `max_action_tier ≥ 4` **and** repo classification ≤ cap.

---

## 10. Error handling

Principles: fail closed, never leak tokens, never conflate "Stratium denied" with "GitHub errored."

| Condition | Behavior |
|---|---|
| Authz denial (`Authorized=false`) | **Not** an error — successful tool result explaining *why* (reason, denied principal/depth), so the agent self-corrects within scope. |
| Credential failure (GitHub not linked, missing `read-token`, broker returns nothing) | Typed error: "link GitHub via the Keycloak account console." v1's minimal broken-auth surface. |
| GitHub API error (404 / 403 / rate-limit / 5xx) | Mapped to a clear message; token never echoed; kept distinct from authz denial. |
| Classification resolution failure | **Fail closed** → deny. |
| Declared tier < assessed tier | Hard error at startup (developer mistake; anti-spoofing). |

---

## 11. Testing strategy (TDD, ≥80% coverage)

- **Unit:** both `CredentialProvider` implementations (mock Keycloak broker HTTP); each GitHub handler (mock
  GitHub API + mock `ExecuteAction` returning allow/deny); classification resolver including the fail-closed
  path; the declared-tier enforcement guard.
- **Integration:** brokered-token retrieval against a Keycloak test realm (or mocked broker endpoint); the three
  deny paths end-to-end (tool not in `approved_tools`; tier > `max_action_tier`; classification > cap).
- **Cross-provider:** extend `go/services/agent-gateway/cross_provider_test.go` to confirm a GitHub catalog tool
  authorizes identically whether the calling agent's provider is Anthropic or OpenAI (provider-agnostic token
  guarantee preserved).
- **Demo:** `demos/catalog-github/` — register an agent, create a delegation scoped to
  `["github_read_file","github_create_issue"]` with `classification_cap: INTERNAL`, run an allowed call plus the
  denied calls, and show the resulting audit entries. Mirrors existing demos.

---

## 12. Success criteria

An agent with a delegation scoped to `["github_read_file","github_create_issue"]` and
`classification_cap: INTERNAL`:

- **CAN** read a file from an INTERNAL repo and open an issue on it.
- **IS DENIED** reading a CONFIDENTIAL repo (classification > cap).
- **IS DENIED** `github_delete_branch` (tool not in `approved_tools`; tier 4 > cap) — with the denial reason
  surfaced from the compound decision.
- Brokered-token retrieval works end-to-end via Keycloak.
- ≥80% test coverage; demo runs green.

---

## 13. Risks & open questions

| Risk / question | Notes |
|---|---|
| Keycloak version | Brokered-token retrieval works on current Keycloak; auto-refresh requires **26.4+**. Not exercised by GitHub in v1, but confirm the deployment's Keycloak version before M365. |
| Autonomous-agent token access | The broker endpoint needs a user-tied Keycloak token. For agents acting with no interactive user, an **offline token** (`offline_access`) is required. v1 demo can use an interactive user session; offline access is a design item for M365. |
| GitHub OAuth scopes | The brokered GitHub app must request scopes covering repo read, issue create, and branch delete. Confirm minimum scope set during implementation. |
| Token-at-rest | Brokered tokens live in Keycloak's store (not Stratium KEK/DEK). Acceptable for v1 (same trust boundary that already holds identity tokens). The hybrid KEK-re-cache option remains available for a future high-assurance tier. |
| GitHub client library | `google/go-github` vs raw REST — decide at implementation time (raw REST keeps dependencies minimal for four operations). |

---

## 14. Downstream

This framework is the substrate for the rest of Workstream A. Tool #2 (**Microsoft 365 mail**) will reuse the
`CredentialProvider`, tool-definition standard, handler pattern, and policy-template format unchanged, and will
additionally prove **token auto-refresh** and the **tier-3 external-comms classification wedge** (e.g.,
"CONFIDENTIAL mail cannot be sent to an external recipient").
