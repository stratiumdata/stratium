# GitHub Catalog Demo

Demonstrates Stratium's classification-aware GitHub catalog tools, authorized via
the Agent Gateway and credentialed via Keycloak identity brokering.

## Prerequisites

1. **GitHub OAuth App** with callback `{KEYCLOAK_URL}/realms/stratium/broker/github/endpoint`.
2. Keycloak env: `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET` (see `keycloak/realm-export.json`).
3. Each user links GitHub: Keycloak Account Console -> Linked accounts -> GitHub.
4. A catalog config file (see `seed-catalog-demo.sh` for a sample) at `~/.stratium/catalog.json`.
5. Start the MCP server with `stratium-mcp -catalog-config ~/.stratium/catalog.json`.

## Tools

| Tool | Tier | Classification gate |
|---|---|---|
| `github_read_file` | 1 | repo classification <= cap |
| `github_search_code` | 1 | repo classification <= cap |
| `github_create_issue` | 2 | repo classification <= cap |
| `github_delete_branch` | 4 | repo classification <= cap; tier <= max_action_tier |

## Walkthrough

Run `bash seed-catalog-demo.sh` for the scoped delegation and expected allow/deny outcomes.

## Security notes

- **Brokered token storage is intentional.** The GitHub IdP sets `storeToken: true` and
  `addReadTokenRoleOnCreate: true` so the catalog can retrieve the user's GitHub token via
  `/realms/stratium/broker/github/token`. This means GitHub access tokens are stored in
  Keycloak's federated-identity store. This is the documented trade-off of the Keycloak
  brokering approach (the tokens live in the same trust boundary that already holds identity
  tokens). For a production/regulated tier, scope the `broker` `read-token` role to the
  specific client(s) that need it instead of auto-granting on creation, and define a token
  rotation/revocation policy.
- **`trustEmail` is off.** First-broker-login verifies account ownership before linking a
  GitHub identity to an existing user — do not enable `trustEmail` for this IdP.
- **Scope is `repo`.** The catalog's write/delete tools require the classic `repo` scope.
  Restrict the catalog delegation's `approved_tools` to read-only tools where write access
  is not needed, so the ExecuteAction gate — not the OAuth scope — bounds what agents can do.
