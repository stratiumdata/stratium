#!/usr/bin/env bash
# Demo: classification-aware GitHub catalog via Stratium agent authorization.
# Prereqs: stratium-mcp built, Agent Gateway running, GitHub linked in Keycloak,
#          and a catalog config at ~/.stratium/catalog.json (see README).
set -euo pipefail

GW="${STRATIUM_GATEWAY_ADDRESS:-localhost:50054}"
echo "Using Agent Gateway: ${GW}"

cat <<'EOF'
This demo expects a delegation scoped to:
  approved_tools:    ["github_read_file", "github_create_issue"]
  max_action_tier:   2
  classification_cap: { commercial: "INTERNAL" }

Expected outcomes:
  1. github_read_file on an INTERNAL repo  -> ALLOWED
  2. github_read_file on a CONFIDENTIAL-COMMERCIAL repo -> DENIED (classification > cap)
  3. github_delete_branch on any repo      -> DENIED (tool not in scope; tier 4 > cap)
EOF

echo
echo "Run these via your MCP client (Claude Code / Desktop) with stratium-mcp started as:"
echo "  stratium-mcp -catalog-config ~/.stratium/catalog.json"
echo
echo "Sample catalog config (~/.stratium/catalog.json):"
cat <<'EOF'
{
  "enabled": true,
  "providers": ["github"],
  "github": {
    "repo_classifications": {
      "your-org/internal-svc":  { "classification": "INTERNAL",     "hierarchy": "commercial" },
      "your-org/secret-svc":    { "classification": "CONFIDENTIAL-COMMERCIAL", "hierarchy": "commercial" }
    },
    "default_classification": { "classification": "INTERNAL", "hierarchy": "commercial" }
  }
}
EOF
