#!/usr/bin/env bash
set -euo pipefail

# Usage: configure via environment variables and run this script to produce a customer bundle.
# Required:
#   LICENSE_CUSTOMER_ID
#   LICENSE_DEPLOYMENT_ID
# Optional:
#   LICENSE_CUSTOMER_NAME
#   LICENSE_ALLOWED_SERVICES (comma-separated)
#   LICENSE_FEATURES (comma-separated)
#   LICENSE_MAX_NODES
#   LICENSE_EXPIRES_IN (e.g., 720h) OR LICENSE_EXPIRES_AT (RFC3339)
#   LICENSE_KEY_ID (override key id)
#   LICENSE_PRIVATE_KEY_PATH (use existing key instead of generating)
#   LICENSE_PRIVATE_KEY_OUT (default: artifacts/license/license-private.pem)
#   LICENSE_PUBLIC_KEY_OUT (default: artifacts/license/license-public.pem)
#   LICENSE_OUTPUT (default: artifacts/license/license.jwt)
#   LICENSE_BUNDLE_DIR (default: artifacts/license/bundle)
#   LICENSE_BUNDLE_ZIP (optional)

if [[ -z "${LICENSE_CUSTOMER_ID:-}" ]]; then
  echo "LICENSE_CUSTOMER_ID is required" >&2
  exit 1
fi

if [[ -z "${LICENSE_DEPLOYMENT_ID:-}" ]]; then
  echo "LICENSE_DEPLOYMENT_ID is required" >&2
  exit 1
fi

LICENSE_OUTPUT=${LICENSE_OUTPUT:-artifacts/license/license.jwt}
LICENSE_PRIVATE_KEY_OUT=${LICENSE_PRIVATE_KEY_OUT:-artifacts/license/license-private.pem}
LICENSE_PUBLIC_KEY_OUT=${LICENSE_PUBLIC_KEY_OUT:-artifacts/license/license-public.pem}
LICENSE_BUNDLE_DIR=${LICENSE_BUNDLE_DIR:-artifacts/license/bundle}

mkdir -p "$(dirname "$LICENSE_OUTPUT")"
mkdir -p "$(dirname "$LICENSE_PRIVATE_KEY_OUT")"
mkdir -p "$(dirname "$LICENSE_PUBLIC_KEY_OUT")"
if [[ -z "${LICENSE_BUNDLE_ZIP:-}" ]]; then
  mkdir -p "$LICENSE_BUNDLE_DIR"
else
  mkdir -p "$(dirname "$LICENSE_BUNDLE_ZIP")"
fi

args=(
  --output "$LICENSE_OUTPUT"
  --customer-id "$LICENSE_CUSTOMER_ID"
  --deployment-id "$LICENSE_DEPLOYMENT_ID"
  --public-key-out "$LICENSE_PUBLIC_KEY_OUT"
)

if [[ -n "${LICENSE_CUSTOMER_NAME:-}" ]]; then
  args+=(--customer-name "$LICENSE_CUSTOMER_NAME")
fi
if [[ -n "${LICENSE_ALLOWED_SERVICES:-}" ]]; then
  args+=(--allowed-services "$LICENSE_ALLOWED_SERVICES")
fi
if [[ -n "${LICENSE_FEATURES:-}" ]]; then
  args+=(--features "$LICENSE_FEATURES")
fi
if [[ -n "${LICENSE_MAX_NODES:-}" ]]; then
  args+=(--max-nodes "$LICENSE_MAX_NODES")
fi
if [[ -n "${LICENSE_KEY_ID:-}" ]]; then
  args+=(--key-id "$LICENSE_KEY_ID")
fi
if [[ -n "${LICENSE_EXPIRES_IN:-}" ]]; then
  args+=(--expires-in "$LICENSE_EXPIRES_IN")
elif [[ -n "${LICENSE_EXPIRES_AT:-}" ]]; then
  args+=(--expires-at "$LICENSE_EXPIRES_AT")
fi

if [[ -n "${LICENSE_BUNDLE_ZIP:-}" ]]; then
  args+=(--bundle-zip "$LICENSE_BUNDLE_ZIP")
else
  args+=(--bundle-dir "$LICENSE_BUNDLE_DIR")
fi

if [[ -n "${LICENSE_PRIVATE_KEY_PATH:-}" ]]; then
  args+=(--private-key "$LICENSE_PRIVATE_KEY_PATH")
else
  args+=(--generate-key --private-key-out "$LICENSE_PRIVATE_KEY_OUT")
fi

if [[ -x "./bin/license-signer" ]]; then
  ./bin/license-signer "${args[@]}"
else
  (cd go && go run ./cmd/license-signer "${args[@]}")
fi
