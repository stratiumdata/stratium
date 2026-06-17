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
