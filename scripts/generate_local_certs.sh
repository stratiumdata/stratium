#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="${CERT_DIR:-/etc/stratium/certs}"
VALID_DAYS="${VALID_DAYS:-825}"
CA_SUBJECT="${CA_SUBJECT:-/C=US/ST=CA/L=Local/O=Stratium/OU=Development/CN=Stratium Local CA}"
SERVER_SUBJECT="${SERVER_SUBJECT:-/C=US/ST=CA/L=Local/O=Stratium/OU=Development/CN=stratium-local}"

SAN_DNS=(
  "localhost"
  "platform"
  "key-manager"
  "key-access"
  "pap"
  "platform-server"
  "key-manager-server"
  "key-access-server"
  "pap-server"
  "host.docker.internal"
)
SAN_IP=(
  "127.0.0.1"
  "::1"
)

umask 077
mkdir -p "${CERT_DIR}"

CA_KEY="${CERT_DIR}/ca.key"
CA_CERT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CERT="${CERT_DIR}/server.crt"
CA_SERIAL="${CERT_DIR}/ca.srl"

tmp_cfg="$(mktemp)"
cleanup() {
  rm -f "${tmp_cfg}" "${SERVER_CSR}"
}
trap cleanup EXIT

{
  echo "[req]"
  echo "distinguished_name = req_distinguished_name"
  echo "req_extensions = v3_req"
  echo "prompt = no"
  echo
  echo "[req_distinguished_name]"
  echo "C = US"
  echo "ST = CA"
  echo "L = Local"
  echo "O = Stratium"
  echo "OU = Development"
  echo "CN = stratium-local"
  echo
  echo "[v3_req]"
  echo "keyUsage = keyEncipherment, dataEncipherment, digitalSignature"
  echo "extendedKeyUsage = serverAuth"
  echo "subjectAltName = @alt_names"
  echo
  echo "[alt_names]"
  i=1
  for dns in "${SAN_DNS[@]}"; do
    echo "DNS.${i} = ${dns}"
    i=$((i+1))
  done
  i=1
  for ip in "${SAN_IP[@]}"; do
    echo "IP.${i} = ${ip}"
    i=$((i+1))
  done
} > "${tmp_cfg}"

if [[ ! -f "${CA_KEY}" || ! -f "${CA_CERT}" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${CA_KEY}"
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${VALID_DAYS}" -out "${CA_CERT}" -subj "${CA_SUBJECT}"
fi

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${SERVER_KEY}"
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -subj "${SERVER_SUBJECT}" -config "${tmp_cfg}"
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_CERT}" -CAkey "${CA_KEY}" -CAcreateserial -out "${SERVER_CERT}" -days "${VALID_DAYS}" -sha256 -extensions v3_req -extfile "${tmp_cfg}"

chmod 600 "${CA_KEY}" "${SERVER_KEY}"
chmod 644 "${CA_CERT}" "${SERVER_CERT}"

echo "Generated local TLS assets in ${CERT_DIR}"
echo "CA:     ${CA_CERT}"
echo "Server: ${SERVER_CERT}"
