#!/bin/bash
# install-hooks.sh
#
# MDM deployment script for @stratium/claude-hooks.
# Deploys via Jamf Policy or Intune Remediation Script.
# Runs as the logged-in user (not root).
#
# Required environment variables (set by MDM before deployment):
#   STRATIUM_GATEWAY     - Agent Gateway host:port
#
# Optional environment variables:
#   STRATIUM_PAP         - PAP REST API URL
#   STRATIUM_KEYCLOAK    - Keycloak URL
#   STRATIUM_REALM       - Keycloak realm (default: master)
#   STRATIUM_CLIENT_ID   - OAuth client ID (default: claude-code)
#   STRATIUM_CACERT      - Path to CA cert
#   STRATIUM_FAIL_MODE   - fail_closed (default) | fail_open
#   NPM_REGISTRY         - Private npm registry URL
#   STRATIUM_NPM_PACKAGE - Package name/version (default: @stratium/claude-hooks)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

STRATIUM_GATEWAY="${STRATIUM_GATEWAY:-}"
STRATIUM_PAP="${STRATIUM_PAP:-}"
STRATIUM_KEYCLOAK="${STRATIUM_KEYCLOAK:-}"
STRATIUM_REALM="${STRATIUM_REALM:-master}"
STRATIUM_CLIENT_ID="${STRATIUM_CLIENT_ID:-claude-code}"
STRATIUM_CACERT="${STRATIUM_CACERT:-}"
STRATIUM_FAIL_MODE="${STRATIUM_FAIL_MODE:-fail_closed}"
NPM_REGISTRY="${NPM_REGISTRY:-}"
STRATIUM_NPM_PACKAGE="${STRATIUM_NPM_PACKAGE:-@stratium/claude-hooks}"

# ── Validation ────────────────────────────────────────────────────────────────

if [[ -z "$STRATIUM_GATEWAY" ]]; then
  echo "Error: STRATIUM_GATEWAY is required" >&2
  exit 1
fi

# ── Helpers ───────────────────────────────────────────────────────────────────

log() { echo "[stratium-install] $*"; }
err() { echo "[stratium-install] ERROR: $*" >&2; exit 1; }

check_tool() {
  local tool="$1"
  if ! command -v "$tool" &>/dev/null; then
    err "$tool not found on PATH. Install it before running this script."
  fi
}

# ── Prerequisites check ───────────────────────────────────────────────────────

check_tool "node"
check_tool "npm"
check_tool "curl"

# grpcurl is optional at install time (warn only)
if ! command -v grpcurl &>/dev/null; then
  log "Warning: grpcurl not found. Install it for full functionality."
  log "  macOS: brew install grpcurl"
  log "  Linux: https://github.com/fullstorydev/grpcurl/releases"
fi

NODE_VERSION=$(node --version | sed 's/v//')
NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  err "Node.js 18+ required (found: v${NODE_VERSION})"
fi

# ── Install npm package ───────────────────────────────────────────────────────

log "Installing ${STRATIUM_NPM_PACKAGE}..."

INSTALL_ARGS=("-g" "--quiet" "--no-fund" "--no-audit")
if [[ -n "$NPM_REGISTRY" ]]; then
  INSTALL_ARGS+=("--registry" "$NPM_REGISTRY")
fi

npm install "${INSTALL_ARGS[@]}" "$STRATIUM_NPM_PACKAGE"
log "Package installed."

# ── Configure machine settings ────────────────────────────────────────────────

log "Configuring machine settings..."

CONFIGURE_ARGS=("configure" "--gateway" "$STRATIUM_GATEWAY" "--silent")

if [[ -n "$STRATIUM_PAP" ]];       then CONFIGURE_ARGS+=("--pap-url"   "$STRATIUM_PAP"); fi
if [[ -n "$STRATIUM_KEYCLOAK" ]];  then CONFIGURE_ARGS+=("--keycloak"  "$STRATIUM_KEYCLOAK"); fi
if [[ "$STRATIUM_REALM" != "master" ]]; then CONFIGURE_ARGS+=("--realm" "$STRATIUM_REALM"); fi
if [[ "$STRATIUM_CLIENT_ID" != "claude-code" ]]; then CONFIGURE_ARGS+=("--client-id" "$STRATIUM_CLIENT_ID"); fi
if [[ -n "$STRATIUM_CACERT" ]];    then CONFIGURE_ARGS+=("--cacert"    "$STRATIUM_CACERT"); fi

if [[ "$STRATIUM_FAIL_MODE" == "fail_open" ]]; then
  CONFIGURE_ARGS+=("--fail-open")
else
  CONFIGURE_ARGS+=("--fail-closed")
fi

stratium-hooks "${CONFIGURE_ARGS[@]}"

log "Configuration complete."

# ── Verify installation ───────────────────────────────────────────────────────

log "Verifying installation..."

stratium-hooks status

log "────────────────────────────────────────────────────"
log "Stratium Claude Code hooks installed successfully."
log "  Gateway:    ${STRATIUM_GATEWAY}"
log "  Fail mode:  ${STRATIUM_FAIL_MODE}"
log ""
log "Developers will be prompted to authenticate with"
log "Stratium on their next Claude Code session."
log "────────────────────────────────────────────────────"
