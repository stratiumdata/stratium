#!/bin/bash
# ============================================================
# Jamf Pro Policy Script: Install Stratium Claude Code Hooks
# ============================================================
#
# Deployment: Jamf Pro > Policies > Scripts
# Execution:  Once per device (with update check on re-run)
# Frequency:  Ongoing (script checks version before re-installing)
# Context:    Runs as the logged-in user (not root)
#
# Script Parameters (configure in Jamf Policy → Scripts → Parameters):
#   $4  STRATIUM_GATEWAY     e.g. stratium.corp.com:50054
#   $5  STRATIUM_PAP         e.g. https://stratium.corp.com:8090
#   $6  STRATIUM_KEYCLOAK    e.g. https://keycloak.corp.com
#   $7  STRATIUM_REALM       e.g. corp
#   $8  STRATIUM_CACERT      e.g. /etc/stratium/certs/ca.crt  (or leave empty)
#   $9  NPM_REGISTRY         e.g. https://npm.corp.com        (or leave empty for public)
#   $10 FAIL_MODE            fail_closed (default) | fail_open
#
# ============================================================

set -euo pipefail

# ── Read Jamf Parameters ──────────────────────────────────────────────────────
STRATIUM_GATEWAY="${4:-}"
STRATIUM_PAP="${5:-}"
STRATIUM_KEYCLOAK="${6:-}"
STRATIUM_REALM="${7:-master}"
STRATIUM_CACERT="${8:-}"
NPM_REGISTRY="${9:-}"
FAIL_MODE="${10:-fail_closed}"

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "$STRATIUM_GATEWAY" ]]; then
  echo "ERROR: Parameter 4 (STRATIUM_GATEWAY) is required." >&2
  exit 1
fi

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE="/var/log/stratium-hooks-install.log"
# Fall back to /tmp when running without write access to /var/log (e.g. dry-run tests)
if ! touch "$LOG_FILE" 2>/dev/null; then
  LOG_FILE="/tmp/stratium-hooks-install.log"
fi
log() {
  local ts
  ts=$(date '+%Y-%m-%dT%H:%M:%S')
  echo "[$ts] $*" | tee -a "$LOG_FILE"
}
log "Starting Stratium hooks installation for gateway: $STRATIUM_GATEWAY"

# ── Environment detection ─────────────────────────────────────────────────────
LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || echo "$USER")
if [[ -z "$LOGGED_IN_USER" || "$LOGGED_IN_USER" == "root" ]]; then
  log "ERROR: Cannot determine logged-in user or running as root."
  exit 1
fi

log "Installing for user: $LOGGED_IN_USER"

# Run as the logged-in user
run_as_user() {
  sudo -u "$LOGGED_IN_USER" "$@"
}

# ── Check existing installation ───────────────────────────────────────────────
INSTALLED_VERSION=$(run_as_user stratium-hooks version 2>/dev/null | awk '{print $2}' || echo "")
REQUIRED_VERSION="1.0.0"

if [[ -n "$INSTALLED_VERSION" && "$INSTALLED_VERSION" == "$REQUIRED_VERSION" ]]; then
  log "Stratium hooks $INSTALLED_VERSION already installed. Verifying configuration..."
  run_as_user stratium-hooks status >> "$LOG_FILE" 2>&1 || true
  log "Installation already current. Exiting."
  exit 0
fi

# ── Check prerequisites ───────────────────────────────────────────────────────
for tool in node npm curl; do
  if ! run_as_user command -v "$tool" &>/dev/null; then
    log "ERROR: $tool not found. Ensure it is installed before running this script."
    exit 1
  fi
done

NODE_VERSION=$(run_as_user node --version | sed 's/v//')
NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 18 ]]; then
  log "ERROR: Node.js 18+ required (found v$NODE_VERSION)"
  exit 1
fi

# Install grpcurl if missing
if ! run_as_user command -v grpcurl &>/dev/null; then
  log "grpcurl not found — attempting install via Homebrew"
  if run_as_user command -v brew &>/dev/null; then
    run_as_user brew install grpcurl --quiet
    log "grpcurl installed via Homebrew"
  else
    log "WARNING: grpcurl not installed and Homebrew not available. Install manually."
  fi
fi

# ── Install npm package ───────────────────────────────────────────────────────
log "Installing @stratium/claude-hooks@$REQUIRED_VERSION..."

INSTALL_ARGS=("-g" "--quiet" "--no-fund" "--no-audit")
if [[ -n "$NPM_REGISTRY" ]]; then
  INSTALL_ARGS+=("--registry" "$NPM_REGISTRY")
fi

run_as_user npm install "${INSTALL_ARGS[@]}" "@stratium/claude-hooks@$REQUIRED_VERSION" >> "$LOG_FILE" 2>&1
log "Package installed."

# ── Configure ─────────────────────────────────────────────────────────────────
log "Configuring machine settings..."

CONFIGURE_ARGS=("configure" "--gateway" "$STRATIUM_GATEWAY" "--silent")
[[ -n "$STRATIUM_PAP" ]]       && CONFIGURE_ARGS+=("--pap-url"   "$STRATIUM_PAP")
[[ -n "$STRATIUM_KEYCLOAK" ]]  && CONFIGURE_ARGS+=("--keycloak"  "$STRATIUM_KEYCLOAK")
[[ "$STRATIUM_REALM" != "master" ]] && CONFIGURE_ARGS+=("--realm" "$STRATIUM_REALM")
[[ -n "$STRATIUM_CACERT" ]]    && CONFIGURE_ARGS+=("--cacert"    "$STRATIUM_CACERT")
[[ "$FAIL_MODE" == "fail_open" ]] && CONFIGURE_ARGS+=("--fail-open") || CONFIGURE_ARGS+=("--fail-closed")

run_as_user stratium-hooks "${CONFIGURE_ARGS[@]}" >> "$LOG_FILE" 2>&1
log "Configuration complete."

# ── Report to Jamf ────────────────────────────────────────────────────────────
log "Stratium Claude Code hooks installed and configured successfully."
run_as_user stratium-hooks status >> "$LOG_FILE" 2>&1

# Jamf extension attribute: report installed version for inventory
echo "<result>stratium-hooks ${REQUIRED_VERSION}</result>"
exit 0
