#!/usr/bin/env bash
#
# hit_observability.sh
# --------------------
# Convenience script that generates traffic against the Stratium services so all
# telemetry exporters (metrics + traces) receive fresh samples.
# The script performs the following steps:
#   1. Runs the platform client to exercise PDP decision APIs.
#   2. Runs the key-manager client to exercise provider/key workflows.
#   3. Runs the key-access client (when client credentials are available) to
#      trigger wrap/unwrap flows and service-key cache usage.
#   4. Scrapes each service's Prometheus endpoint so you can confirm metrics data.
#
# Environment overrides:
#   PLATFORM_ADDR            gRPC address for the platform service (default localhost:50051)
#   KEY_MANAGER_ADDR         gRPC address for the key manager service (default localhost:50052)
#   KEY_ACCESS_ADDR          gRPC address for the key access service (default localhost:50053)
#   KEY_ACCESS_TOKEN         JWT token for the key access client (default user-token)
#   KEY_ACCESS_CLIENT_KEY_ID Optional client key ID to reuse (falls back to metadata file)
#   KEY_ACCESS_CLIENT_KEY_FILE Path to RSA private key PEM (default load-testing/k6/client-keys/private_key.pem)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
TMP_DIR="$(mktemp -d)"

cleanup() {
	rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

PLATFORM_ADDR="${PLATFORM_ADDR:-localhost:50051}"
KEY_MANAGER_ADDR="${KEY_MANAGER_ADDR:-localhost:50052}"
KEY_ACCESS_ADDR="${KEY_ACCESS_ADDR:-localhost:50053}"
KEY_ACCESS_TOKEN="${KEY_ACCESS_TOKEN:-user-token}"
KEY_ACCESS_CLIENT_KEY_FILE="${KEY_ACCESS_CLIENT_KEY_FILE:-${ROOT_DIR}/load-testing/k6/client-keys/private_key.pem}"
KEY_ACCESS_POLICY_FILE="${KEY_ACCESS_POLICY_FILE:-${ROOT_DIR}/scripts/test-policy.json}"

discover_key_access_token() {
	local token_source="${HOME}/.ztdf/token.json"
	if [[ -n "${KEY_ACCESS_TOKEN}" && "${KEY_ACCESS_TOKEN}" != "user-token" ]]; then
		return
	fi
	if [[ -f "${token_source}" ]]; then
		if command -v jq >/dev/null 2>&1; then
			local token
			token="$(jq -r '.access_token // empty' "${token_source}" 2>/dev/null || true)"
			if [[ -n "${token}" ]]; then
				KEY_ACCESS_TOKEN="${token}"
				return
			fi
		fi
		if command -v python3 >/dev/null 2>&1; then
			local token
			token="$(python3 - <<'PY' "${token_source}" || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    token = data.get("access_token")
    if token:
        print(token.strip())
except Exception:
    pass
PY
)"
			if [[ -n "${token}" ]]; then
				KEY_ACCESS_TOKEN="${token}"
			fi
		fi
	fi
}

ensure_rsa_private_key() {
	local key_path="$1"
	if [[ ! -f "${key_path}" ]]; then
		printf '%s' "${key_path}"
		return
	fi
	if grep -q "BEGIN RSA PRIVATE KEY" "${key_path}"; then
		printf '%s' "${key_path}"
		return
	fi
	if ! command -v openssl >/dev/null 2>&1; then
		printf '%s' "${key_path}"
		return
	fi
	local converted="${TMP_DIR}/key-access-rsa.pem"
	if openssl pkey -inform PEM -outform PEM -in "${key_path}" -traditional -out "${converted}" >/dev/null 2>&1; then
		printf '%s' "${converted}"
	else
		printf '%s' "${key_path}"
	fi
}

default_client_key_id() {
	if [[ -n "${KEY_ACCESS_CLIENT_KEY_ID:-}" ]]; then
		printf '%s' "${KEY_ACCESS_CLIENT_KEY_ID}"
		return
	fi

	local metadata_file="${ROOT_DIR}/load-testing/k6/client-keys/key_metadata.json"
	if [[ -f "${metadata_file}" && -x "$(command -v python3)" ]]; then
		python3 - <<'PY' "${metadata_file}" || true
import json, os, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        data = json.load(fh)
    print(data.get("key_id", "").strip())
except Exception:
    pass
PY
	fi
}

KEY_ACCESS_CLIENT_KEY_ID="$(default_client_key_id)"
discover_key_access_token
KEY_ACCESS_CLIENT_KEY_FILE="$(ensure_rsa_private_key "${KEY_ACCESS_CLIENT_KEY_FILE}")"

build_client() {
	local name="$1"
	local target="$2"
	if [[ -x "${BIN_DIR}/${name}" ]]; then
		return
	fi
	echo "Building ${name}..."
	(
		cd "${ROOT_DIR}/go"
		go build -o "../bin/${name}" "./cmd/${target}"
	)
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "error: required command '$1' not found in PATH" >&2
		exit 1
	fi
}

require_command curl
require_command go

mkdir -p "${BIN_DIR}"

build_client "platform-client" "platform-client"
build_client "key-manager-client" "key-manager-client"
build_client "key-access-client" "key-access-client"

echo ">>> Exercising platform-service PDP endpoints"
for round in 1 2; do
	echo "--- Platform client run ${round} ---"
	"${BIN_DIR}/platform-client" -addr "${PLATFORM_ADDR}" >/tmp/platform-observability.log 2>&1 && cat /tmp/platform-observability.log
done

echo
echo ">>> Exercising key-manager workflows"
"${BIN_DIR}/key-manager-client" -addr "${KEY_MANAGER_ADDR}" >/tmp/key-manager-observability.log 2>&1 && cat /tmp/key-manager-observability.log

extract_created_key_id() {
	awk -F': ' '/Created key with ID:/ {print $2}' /tmp/key-manager-observability.log | tail -1 | tr -d '[:space:]'
}

KEY_MANAGER_CREATED_KEY_ID="$(extract_created_key_id)"

compile_km_probe() {
	local probe_file="${TMP_DIR}/km_probe.go"
	if [[ -f "${probe_file}" ]]; then
		printf '%s' "${probe_file}"
		return
	fi
	cat <<'EOF' >"${probe_file}"
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	keyManager "stratium/services/key-manager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	addr := flag.String("addr", "localhost:50052", "key-manager address")
	keyID := flag.String("key-id", "", "key id to fetch")
	mode := flag.String("mode", "cache", "probe mode (cache|missing)")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	client := keyManager.NewKeyManagerServiceClient(conn)

	switch *mode {
	case "cache":
		if *keyID == "" {
			log.Fatalf("cache mode requires -key-id")
		}
		for i := 0; i < 2; i++ {
			_, err := client.GetKey(ctx, &keyManager.GetKeyRequest{
				KeyId:            *keyID,
				IncludePublicKey: true,
			})
			if err != nil {
				log.Fatalf("GetKey probe failed: %v", err)
			}
		}
		log.Printf("Probed key cache for %s", *keyID)
	case "missing":
		_, err := client.GetKey(ctx, &keyManager.GetKeyRequest{
			KeyId: fmt.Sprintf("missing-%d", time.Now().UnixNano()),
		})
		if err == nil {
			log.Fatalf("expected GetKey error for missing key")
		}
		log.Printf("Probed missing key path (expected error): %v", err)
	default:
		log.Fatalf("unknown mode %s", *mode)
	}
}
EOF
	printf '%s' "${probe_file}"
}

if [[ -n "${KEY_MANAGER_CREATED_KEY_ID}" ]]; then
	echo
	echo ">>> Priming key-manager caches & error paths"
	KM_PROBE_FILE="$(compile_km_probe)"
	go run "${KM_PROBE_FILE}" -addr "${KEY_MANAGER_ADDR}" -key-id "${KEY_MANAGER_CREATED_KEY_ID}" -mode cache >/tmp/key-manager-cache-probe.log 2>&1 && cat /tmp/key-manager-cache-probe.log
	go run "${KM_PROBE_FILE}" -addr "${KEY_MANAGER_ADDR}" -mode missing >/tmp/key-manager-miss-probe.log 2>&1 && cat /tmp/key-manager-miss-probe.log
else
	echo "WARN: unable to extract created key ID from key-manager client output; skipping cache probe"
fi

if [[ -f "${KEY_ACCESS_CLIENT_KEY_FILE}" && -s "${KEY_ACCESS_CLIENT_KEY_FILE}" && -n "${KEY_ACCESS_CLIENT_KEY_ID}" ]]; then
	echo
	echo ">>> Exercising key-access wrap / unwrap flows"
	policy_base64="${KEY_ACCESS_POLICY_B64:-}"
	if [[ -z "${policy_base64}" && -f "${KEY_ACCESS_POLICY_FILE}" && -s "${KEY_ACCESS_POLICY_FILE}" ]]; then
		policy_base64="$(python3 - <<'PY' "${KEY_ACCESS_POLICY_FILE}" || true
import base64, json, sys
from pathlib import Path
try:
    text = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
    try:
        data = json.loads(text)
        payload = json.dumps(data).encode("utf-8")
        print(base64.b64encode(payload).decode("ascii").strip())
    except json.JSONDecodeError:
        # Assume file already contains base64 text
        print(text)
except Exception:
    pass
PY
)"
	fi

	"${BIN_DIR}/key-access-client" \
		-addr "${KEY_ACCESS_ADDR}" \
		-token "${KEY_ACCESS_TOKEN}" \
		-client-key-id "${KEY_ACCESS_CLIENT_KEY_ID}" \
		-client-key-file "${KEY_ACCESS_CLIENT_KEY_FILE}" \
		-policy "${policy_base64}" \
		>/tmp/key-access-observability.log 2>&1 || {
		echo "Key Access client encountered an error (see /tmp/key-access-observability.log)."
	}
	cat /tmp/key-access-observability.log || true
else
	echo
	echo "!!! Skipping key-access client (missing KEY_ACCESS_CLIENT_KEY_ID or KEY_ACCESS_CLIENT_KEY_FILE)"
	echo "    Set KEY_ACCESS_CLIENT_KEY_ID/KEY_ACCESS_CLIENT_KEY_FILE and re-run to exercise wrap/unwrap telemetry."
fi

echo
echo ">>> Scraping Prometheus exporters"
curl -sf "http://localhost:9090/metrics" >/tmp/platform-metrics.txt && echo "platform-server metrics scraped (http://localhost:9090/metrics)"
curl -sf "http://localhost:9093/metrics" >/tmp/key-access-metrics.txt && echo "key-access-server metrics scraped (http://localhost:9093/metrics)"
curl -sf "http://localhost:9095/targets" >/dev/null && echo "Prometheus targets page reachable at http://localhost:9095/targets"

echo
echo "Telemetry stimulus complete. Check Grafana (http://localhost:3001) after the next scrape interval to see updated panels."
