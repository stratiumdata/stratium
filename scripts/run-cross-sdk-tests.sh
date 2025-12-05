#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_ENV_FILE="$REPO_ROOT/scripts/cross-sdk.env"
ENV_FILE="${1:-$DEFAULT_ENV_FILE}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Environment file '$ENV_FILE' not found."
  echo "Copy scripts/cross-sdk.env.example to scripts/cross-sdk.env and update the values, or pass a custom path."
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "Missing required environment variable: $name"
    exit 1
  fi
}

require_env "STRATIUM_KEY_ACCESS_URL"
require_env "STRATIUM_KEY_MANAGER_URL"
require_env "STRATIUM_KEYCLOAK_URL"
require_env "STRATIUM_KEYCLOAK_REALM"
require_env "STRATIUM_BEARER_TOKEN"
require_env "STRATIUM_POLICY_BASE64"

export STRATIUM_KEY_ACCESS_ADDR="${STRATIUM_KEY_ACCESS_ADDR:-$STRATIUM_KEY_ACCESS_URL}"
export STRATIUM_KEY_ACCESS_URI="${STRATIUM_KEY_ACCESS_URI:-$STRATIUM_KEY_ACCESS_URL}"
export STRATIUM_KEY_MANAGER_ADDR="${STRATIUM_KEY_MANAGER_ADDR:-$STRATIUM_KEY_MANAGER_URL}"
export STRATIUM_KEY_MANAGER_URI="${STRATIUM_KEY_MANAGER_URI:-$STRATIUM_KEY_MANAGER_URL}"
export STRATIUM_PLATFORM_ADDR="${STRATIUM_PLATFORM_ADDR:-${STRATIUM_PLATFORM_URL:-}}"

export STRATIUM_RESOURCE="${STRATIUM_RESOURCE:-integration-resource}"
export STRATIUM_FILENAME="${STRATIUM_FILENAME:-interop.txt}"
export STRATIUM_CONTENT_TYPE="${STRATIUM_CONTENT_TYPE:-text/plain}"

GO_KEY_DIR="${STRATIUM_GO_KEY_DIR:-$REPO_ROOT/artifacts/client-keys/go}"
JS_KEY_DIR="${STRATIUM_JS_KEY_DIR:-$REPO_ROOT/artifacts/client-keys/js}"

mkdir -p "$GO_KEY_DIR" "$JS_KEY_DIR"

export STRATIUM_GO_KEY_DIR="$GO_KEY_DIR"
export STRATIUM_JS_KEY_DIR="$JS_KEY_DIR"

pushd "$REPO_ROOT/sdk/go" > /dev/null
echo "Running cross-SDK integration tests..."
go test -count=1 ./integration
popd > /dev/null
