#!/bin/sh
set -eu

if [ "${STRATIUM_ENABLE_YUBIKEY:-false}" = "true" ]; then
  if ! command -v pcscd >/dev/null 2>&1; then
    echo "STRATIUM_ENABLE_YUBIKEY=true requires pcscd in the container image" >&2
    exit 1
  fi

  mkdir -p /run/pcscd
  rm -f /run/pcscd/pcscd.pid /run/pcscd/pcscd.comm
  pcscd --foreground &
fi

exec "$@"
