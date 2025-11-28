#!/usr/bin/env bash
# Populate AWS Secrets Manager with the Stratium secrets expected by the Helm chart.
# This is the inverse of sync-aws-secrets.sh (which pulls from AWS into Kubernetes).
set -euo pipefail

AWS_REGION="${AWS_REGION:-us-east-2}"

# Secret IDs in AWS Secrets Manager (names or full ARNs)
STRATIUM_SECRET_ID="${STRATIUM_SECRET_ID:-stratium-aws-sm}"
KEYCLOAK_SECRET_ID="${KEYCLOAK_SECRET_ID:-keycloak-aws-sm}"
POSTGRESQL_SECRET_ID="${POSTGRESQL_SECRET_ID:-postgresql-aws-sm}"
ADMIN_KEY_SECRET_ID="${ADMIN_KEY_SECRET_ID:-stratium-admin-key}"

gen_secret() { openssl rand -hex 24; }
gen_admin_key() { openssl rand -base64 32 | tr -d '\n'; }

# Stratium app secrets (defaults auto-generated)
DB_PASSWORD="${DB_PASSWORD:-$(gen_secret)}"
KM_OIDC_SECRET="${KM_OIDC_SECRET:-$(gen_secret)}"
KA_OIDC_SECRET="${KA_OIDC_SECRET:-$(gen_secret)}"
PAP_OIDC_SECRET="${PAP_OIDC_SECRET:-$(gen_secret)}"

# Keycloak admin
KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
KEYCLOAK_ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-$(gen_secret)}"

# PostgreSQL creds
PG_SUPER_PASSWORD="${PG_SUPER_PASSWORD:-$(gen_secret)}"
PG_USERNAME="${PG_USERNAME:-keycloak}"
PG_PASSWORD="${PG_PASSWORD:-$(gen_secret)}"
STRATIUM_DB_USER="${STRATIUM_DB_USER:-stratium}"
STRATIUM_DB_PASSWORD="${STRATIUM_DB_PASSWORD:-$(gen_secret)}"

# Admin key (used by key-manager); provide either ADMIN_KEY_VALUE or ADMIN_KEY_FILE; default auto-generated
ADMIN_KEY_VALUE="${ADMIN_KEY_VALUE:-}"
ADMIN_KEY_FILE="${ADMIN_KEY_FILE:-}"

command -v aws >/dev/null 2>&1 || { echo "aws CLI is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }
command -v base64 >/dev/null 2>&1 || { echo "base64 utility is required" >&2; exit 1; }

ADMIN_KEY_PAYLOAD="$ADMIN_KEY_VALUE"
if [[ -z "$ADMIN_KEY_PAYLOAD" && -n "$ADMIN_KEY_FILE" ]]; then
  ADMIN_KEY_PAYLOAD="$(cat "$ADMIN_KEY_FILE")"
fi
if [[ -z "$ADMIN_KEY_PAYLOAD" ]]; then
  ADMIN_KEY_PAYLOAD="$(gen_admin_key)"
fi

validate_admin_key() {
  local value="$1"
  local decoded_len
  if ! decoded_len=$(printf '%s' "$value" | base64 --decode 2>/dev/null | wc -c | tr -d ' '); then
    echo "Admin key must be valid base64 (32-byte decoded)" >&2
    exit 1
  fi
  if [[ "$decoded_len" -ne 32 ]]; then
    echo "Admin key must decode to 32 bytes, got $decoded_len" >&2
    exit 1
  fi
}
validate_admin_key "$ADMIN_KEY_PAYLOAD"

echo "---- Secrets to be written (generated defaults shown) ----"
echo "AWS_REGION=${AWS_REGION}"
echo "STRATIUM_SECRET_ID=${STRATIUM_SECRET_ID}"
echo "KEYCLOAK_SECRET_ID=${KEYCLOAK_SECRET_ID}"
echo "POSTGRESQL_SECRET_ID=${POSTGRESQL_SECRET_ID}"
echo "ADMIN_KEY_SECRET_ID=${ADMIN_KEY_SECRET_ID}"
echo "DB_PASSWORD=${DB_PASSWORD}"
echo "KM_OIDC_SECRET=${KM_OIDC_SECRET}"
echo "KA_OIDC_SECRET=${KA_OIDC_SECRET}"
echo "PAP_OIDC_SECRET=${PAP_OIDC_SECRET}"
echo "KEYCLOAK_ADMIN_USER=${KEYCLOAK_ADMIN_USER}"
echo "KEYCLOAK_ADMIN_PASSWORD=${KEYCLOAK_ADMIN_PASSWORD}"
echo "PG_SUPER_PASSWORD=${PG_SUPER_PASSWORD}"
echo "PG_USERNAME=${PG_USERNAME}"
echo "PG_PASSWORD=${PG_PASSWORD}"
echo "STRATIUM_DB_USER=${STRATIUM_DB_USER}"
echo "STRATIUM_DB_PASSWORD=${STRATIUM_DB_PASSWORD}"
echo "ADMIN_KEY=<hidden>"
echo "----------------------------------------------------------"

upsert_secret_json() {
  local secret_id="$1" payload="$2"
  if aws secretsmanager describe-secret --region "$AWS_REGION" --secret-id "$secret_id" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value --region "$AWS_REGION" --secret-id "$secret_id" --secret-string "$payload" >/dev/null
    echo "Updated secret $secret_id"
  else
    aws secretsmanager create-secret --region "$AWS_REGION" --name "$secret_id" --secret-string "$payload" >/dev/null
    echo "Created secret $secret_id"
  fi
}

echo "Writing Stratium application secret to $STRATIUM_SECRET_ID"
stratium_payload="$(
  jq -n \
    --arg db "$DB_PASSWORD" \
    --arg km "$KM_OIDC_SECRET" \
    --arg ka "$KA_OIDC_SECRET" \
    --arg pap "$PAP_OIDC_SECRET" \
    '{ "database-password": $db, "key-manager-oidc-secret": $km, "key-access-oidc-secret": $ka, "pap-oidc-secret": $pap }'
)"
upsert_secret_json "$STRATIUM_SECRET_ID" "$stratium_payload"

echo "Writing Keycloak admin secret to $KEYCLOAK_SECRET_ID"
keycloak_payload="$(
  jq -n \
    --arg user "$KEYCLOAK_ADMIN_USER" \
    --arg pass "$KEYCLOAK_ADMIN_PASSWORD" \
    '{ "admin-user": $user, "admin-password": $pass }'
)"
upsert_secret_json "$KEYCLOAK_SECRET_ID" "$keycloak_payload"

echo "Writing PostgreSQL secret to $POSTGRESQL_SECRET_ID"
postgres_payload="$(
  jq -n \
    --arg pg "$PG_SUPER_PASSWORD" \
    --arg user "$PG_USERNAME" \
    --arg pass "$PG_PASSWORD" \
    --arg su "$STRATIUM_DB_USER" \
    --arg sp "$STRATIUM_DB_PASSWORD" \
    '{ "postgres-password": $pg, "username": $user, "password": $pass, "stratium-user": $su, "stratium-password": $sp }'
)"
upsert_secret_json "$POSTGRESQL_SECRET_ID" "$postgres_payload"

echo "Writing admin key secret to $ADMIN_KEY_SECRET_ID"
if aws secretsmanager describe-secret --region "$AWS_REGION" --secret-id "$ADMIN_KEY_SECRET_ID" >/dev/null 2>&1; then
  aws secretsmanager put-secret-value --region "$AWS_REGION" --secret-id "$ADMIN_KEY_SECRET_ID" --secret-string "$ADMIN_KEY_PAYLOAD" >/dev/null
  echo "Updated secret $ADMIN_KEY_SECRET_ID"
else
  aws secretsmanager create-secret --region "$AWS_REGION" --name "$ADMIN_KEY_SECRET_ID" --secret-string "$ADMIN_KEY_PAYLOAD" >/dev/null
  echo "Created secret $ADMIN_KEY_SECRET_ID"
fi

echo "Done. Secrets are stored in AWS Secrets Manager (region: $AWS_REGION)."
