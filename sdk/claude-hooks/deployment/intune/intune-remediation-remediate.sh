#!/bin/bash
# ============================================================
# Intune Remediation (macOS/Linux): Install Stratium Hooks
# ============================================================
# Shell variant of the Intune remediation script for macOS.
# Used when Intune manages macOS devices alongside Windows.
#
# Configure via Intune custom attributes or update defaults below.
# ============================================================

set -euo pipefail

STRATIUM_GATEWAY="${STRATIUM_GATEWAY:-}"
STRATIUM_PAP="${STRATIUM_PAP:-}"
STRATIUM_KEYCLOAK="${STRATIUM_KEYCLOAK:-}"
STRATIUM_REALM="${STRATIUM_REALM:-master}"
STRATIUM_CACERT="${STRATIUM_CACERT:-}"
NPM_REGISTRY="${NPM_REGISTRY:-}"
FAIL_MODE="${FAIL_MODE:-fail_closed}"
REQUIRED_VERSION="1.0.0"

if [[ -z "$STRATIUM_GATEWAY" ]]; then
  echo "ERROR: STRATIUM_GATEWAY is required" >&2
  exit 1
fi

# Same logic as install-hooks.sh — reuse it
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SCRIPT="$(cd "$SCRIPT_DIR/../../scripts" && pwd)/install-hooks.sh"

if [[ -f "$INSTALL_SCRIPT" ]]; then
  exec "$INSTALL_SCRIPT"
else
  # Fallback: direct install
  npm install -g --quiet --no-fund --no-audit \
    ${NPM_REGISTRY:+--registry "$NPM_REGISTRY"} \
    "@stratium/claude-hooks@$REQUIRED_VERSION"

  CONFIGURE_ARGS=("configure" "--gateway" "$STRATIUM_GATEWAY" "--silent")
  [[ -n "$STRATIUM_PAP" ]]      && CONFIGURE_ARGS+=("--pap-url" "$STRATIUM_PAP")
  [[ -n "$STRATIUM_KEYCLOAK" ]] && CONFIGURE_ARGS+=("--keycloak" "$STRATIUM_KEYCLOAK")
  [[ "$STRATIUM_REALM" != "master" ]] && CONFIGURE_ARGS+=("--realm" "$STRATIUM_REALM")
  [[ -n "$STRATIUM_CACERT" ]]   && CONFIGURE_ARGS+=("--cacert" "$STRATIUM_CACERT")
  [[ "$FAIL_MODE" == "fail_open" ]] && CONFIGURE_ARGS+=("--fail-open") || CONFIGURE_ARGS+=("--fail-closed")

  stratium-hooks "${CONFIGURE_ARGS[@]}"
fi
