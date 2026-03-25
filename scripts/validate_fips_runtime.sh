#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STRICT="${STRICT:-0}"

FAIL=0
SKIP=0

log() {
  echo "==> $*"
}

warn() {
  echo "WARN: $*" >&2
  SKIP=1
}

fail() {
  echo "FAIL: $*" >&2
  FAIL=1
}

resolve_openssl_defaults() {
  if [[ -n "${OPENSSL_BIN:-}" || -n "${OPENSSL_CONF:-}" || -n "${OPENSSL_MODULES:-}" ]]; then
    return
  fi

  local prefix="${FIPS_OPENSSL_PREFIX:-$HOME/.local/openssl-3.0.8-fips}"
  if [[ -x "$prefix/bin/openssl" ]]; then
    export OPENSSL_BIN="${OPENSSL_BIN:-$prefix/bin/openssl}"
    export OPENSSL_CONF="${OPENSSL_CONF:-$prefix/ssl/openssl-fips.cnf}"
    export OPENSSL_MODULES="${OPENSSL_MODULES:-$prefix/lib/ossl-modules}"
  fi
}

resolve_go_defaults() {
  if [[ -n "${GO_BIN_PATH:-}" ]]; then
    return
  fi
  local candidates=(
    "$ROOT_DIR/bin/platform-server"
    "$ROOT_DIR/bin/stratium"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      GO_BIN_PATH="$candidate"
      return
    fi
  done
}

resolve_python_defaults() {
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    return
  fi
  local candidates=(
    "$ROOT_DIR/sdk/python/.venv-py313-fips/bin/python"
    "$ROOT_DIR/sdk/python/.venv-py314-fips/bin/python"
    "$ROOT_DIR/sdk/python/.venv-py314/bin/python"
    "$ROOT_DIR/sdk/python/.venv/bin/python"
  )
  for candidate in "${candidates[@]}"; do
    if [[ -x "$candidate" ]]; then
      PYTHON_BIN="$candidate"
      return
    fi
  done
}

resolve_java_defaults() {
  if [[ -z "${JAVA_SECURITY_PROPERTIES:-}" ]]; then
    local security_props="$ROOT_DIR/sdk/java/config/java.security.fips"
    if [[ -f "$security_props" ]]; then
      JAVA_SECURITY_PROPERTIES="$security_props"
    fi
  fi

  if [[ -n "${JAVA_FIPS_CLASSPATH:-}" ]]; then
    return
  fi
  local gradle_home="${GRADLE_USER_HOME:-$HOME/.gradle}"
  local bc_fips_jar
  local bcpkix_fips_jar
  local bctls_fips_jar

  bc_fips_jar="$(ls -1 "$gradle_home"/caches/modules-2/files-2.1/org.bouncycastle/bc-fips/*/*/bc-fips-*.jar 2>/dev/null | tail -n 1)"
  bcpkix_fips_jar="$(ls -1 "$gradle_home"/caches/modules-2/files-2.1/org.bouncycastle/bcpkix-fips/*/*/bcpkix-fips-*.jar 2>/dev/null | tail -n 1)"
  bctls_fips_jar="$(ls -1 "$gradle_home"/caches/modules-2/files-2.1/org.bouncycastle/bctls-fips/*/*/bctls-fips-*.jar 2>/dev/null | tail -n 1)"

  if [[ -n "$bc_fips_jar" && -n "$bcpkix_fips_jar" && -n "$bctls_fips_jar" ]]; then
    JAVA_FIPS_CLASSPATH="${bc_fips_jar}:${bcpkix_fips_jar}:${bctls_fips_jar}"
  fi
}

resolve_openssl_defaults
resolve_go_defaults
resolve_python_defaults
resolve_java_defaults

check_go() {
  log "Go: GOFIPS140 build setting"

  local bin="${GO_BIN_PATH:-}"

  if [[ -z "$bin" ]]; then
    warn "GO_BIN_PATH not set and no default binary found under $ROOT_DIR/bin"
    return
  fi
  if ! command -v go >/dev/null 2>&1; then
    warn "go toolchain not found; cannot read build info for $bin"
    return
  fi

  local info
  if ! info="$(go version -m "$bin" 2>/dev/null)"; then
    fail "unable to read build info for $bin"
    return
  fi

  local gofips
  gofips="$(echo "$info" | awk '
    $1 == "build" && $2 ~ /^GOFIPS140(=|$)/ {
      if ($2 ~ /^GOFIPS140=/) {
        sub(/^GOFIPS140=/, "", $2)
        print $2
      } else {
        print $3
      }
    }
  ' | head -n 1)"
  if [[ -z "$gofips" ]]; then
    fail "GOFIPS140 build setting not found in $bin"
    return
  fi
  echo "GOFIPS140=$gofips"

  if [[ "${GODEBUG:-}" == *"fips140=off"* ]]; then
    fail "GODEBUG disables FIPS (fips140=off)"
  fi
}

check_java() {
  log "Java: AES/GCM provider must be FIPS"

  if ! command -v java >/dev/null 2>&1; then
    warn "java not found"
    return
  fi
  local out
  if command -v javac >/dev/null 2>&1; then
    local tmpdir
    tmpdir="$(mktemp -d)"
    cat > "$tmpdir/FipsProviderCheck.java" <<'EOF'
import javax.crypto.Cipher;
import java.security.Provider;

public class FipsProviderCheck {
    public static void main(String[] args) throws Exception {
        Provider p = Cipher.getInstance("AES/GCM/NoPadding").getProvider();
        System.out.println("FIPS_PROVIDER_NAME=" + p.getName());
        System.out.println("FIPS_PROVIDER_INFO=" + p.getInfo());
    }
}
EOF
    if javac "$tmpdir/FipsProviderCheck.java" >/dev/null 2>&1; then
      local classpath="$tmpdir"
      if [[ -n "${JAVA_FIPS_CLASSPATH:-}" ]]; then
        classpath="${JAVA_FIPS_CLASSPATH}:$tmpdir"
      fi
      local java_opts=()
      if [[ -n "${JAVA_SECURITY_PROPERTIES:-}" ]]; then
        java_opts+=("-Djava.security.properties=${JAVA_SECURITY_PROPERTIES}")
      fi
      out="$(java "${java_opts[@]}" -cp "$classpath" FipsProviderCheck 2>&1)"
    else
      out=""
    fi
    rm -rf "$tmpdir"
    if [[ -z "$out" ]]; then
      fail "failed to query AES/GCM provider"
      return
    fi
  elif command -v jshell >/dev/null 2>&1; then
    if ! out="$(jshell --execution local -q <<'EOF' 2>&1
import javax.crypto.Cipher;
var p = Cipher.getInstance("AES/GCM/NoPadding").getProvider();
System.out.println("FIPS_PROVIDER_NAME=" + p.getName());
System.out.println("FIPS_PROVIDER_INFO=" + p.getInfo());
/exit
EOF
    )"; then
      fail "failed to query AES/GCM provider"
      return
    fi
  else
    warn "javac/jshell not found; cannot inspect JCE provider"
    return
  fi

  local name
  local info
  name="$(echo "$out" | sed -n 's/^FIPS_PROVIDER_NAME=//p' | tail -n 1)"
  info="$(echo "$out" | sed -n 's/^FIPS_PROVIDER_INFO=//p' | tail -n 1)"
  if [[ -z "$name" ]]; then
    fail "could not determine AES/GCM provider name"
    return
  fi
  echo "JCE_PROVIDER_NAME=$name"
  if [[ "${name}${info}" != *FIPS* && "${name}${info}" != *fips* ]]; then
    fail "AES/GCM provider does not appear to be FIPS-capable"
  fi
}

check_python() {
  log "Python: OpenSSL FIPS provider"

  local py="${PYTHON_BIN:-python3}"
  if [[ -x "$py" ]]; then
    : # explicit binary provided
  elif ! command -v "$py" >/dev/null 2>&1; then
    warn "python3 not found"
    return
  fi

  local rc
  set +e
  "$py" - <<'PY'
import ssl
import sys

try:
    from stratium_sdk.crypto import ensure_fips_mode
except Exception as exc:
    print(f"IMPORT_ERROR: {exc}", file=sys.stderr)
    sys.exit(2)

try:
    ensure_fips_mode()
except Exception as exc:
    print(f"FIPS_ERROR: {exc}", file=sys.stderr)
    sys.exit(1)

print(f"OPENSSL_VERSION={ssl.OPENSSL_VERSION}")
PY
  rc=$?
  set -e
  if [[ $rc -eq 2 ]]; then
    warn "stratium_sdk not importable in python3"
  elif [[ $rc -ne 0 ]]; then
    fail "python OpenSSL is not in FIPS mode"
  else
    local openssl_version
    openssl_version="$($py - <<'PY'
import ssl
print(ssl.OPENSSL_VERSION)
PY
    )"

    if [[ -n "${OPENSSL_CONF:-}" && -z "${OPENSSL_MODULES:-}" ]]; then
      fail "OPENSSL_CONF is set but OPENSSL_MODULES is not; provide both to enforce the FIPS provider"
      return
    fi
    if [[ -n "${OPENSSL_MODULES:-}" && -z "${OPENSSL_CONF:-}" ]]; then
      fail "OPENSSL_MODULES is set but OPENSSL_CONF is not; provide both to enforce the FIPS provider"
      return
    fi

    if [[ -z "${OPENSSL_CONF:-}" && -z "${OPENSSL_MODULES:-}" ]]; then
      if [[ "${openssl_version}" != *FIPS* && "${openssl_version}" != *fips* ]]; then
        fail "OPENSSL_CONF/OPENSSL_MODULES are not set and OpenSSL version does not indicate FIPS; set env vars to enforce the FIPS provider"
      fi
    fi
  fi
}

check_node() {
  log "Node: OpenSSL FIPS"

  if ! command -v node >/dev/null 2>&1; then
    warn "node not found"
    return
  fi

  local rc
  set +e
  node - <<'NODE'
const crypto = require('crypto');
if (typeof crypto.setFips !== 'function' || typeof crypto.getFips !== 'function') {
  console.error('NO_FIPS_SUPPORT');
  process.exit(2);
}
try {
  crypto.setFips(1);
} catch (err) {
  console.error(`SETFIPS_ERROR: ${err.message}`);
  process.exit(1);
}
if (crypto.getFips() !== 1) {
  console.error('FIPS_NOT_ACTIVE');
  process.exit(1);
}
console.log(`FIPS_ACTIVE=${crypto.getFips()}`);
console.log(`OPENSSL_VERSION=${process.versions.openssl}`);
NODE
  rc=$?
  set -e
  if [[ $rc -eq 2 ]]; then
    warn "node build does not expose OpenSSL FIPS support"
  elif [[ $rc -ne 0 ]]; then
    fail "node OpenSSL FIPS mode could not be enabled"
  fi
}

log "Validating FIPS runtime crypto modules"
check_go
check_java
check_python
check_node

if [[ $FAIL -ne 0 ]]; then
  exit 1
fi

if [[ $SKIP -ne 0 && $STRICT -ne 0 ]]; then
  exit 1
fi

echo "FIPS runtime validation complete."
