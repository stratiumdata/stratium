#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  cat <<'EOF' >&2
Usage: ./update-ingress-aliases.sh <hosted-zone-id> [kubectl-context]

Updates Route 53 aliases for auth/api/ui/grpc.demostratium.com to match the
current ALB hostnames published by the corresponding ingresses.
EOF
  exit 1
fi

HOSTED_ZONE_ID="$1"
KUBECTL_CONTEXT="${2:-}"
ALB_ZONE_ID="Z3AADJGX6KTTL2" # us-east-2

if [[ -n "$KUBECTL_CONTEXT" ]]; then
  KCMD=(kubectl --context "$KUBECTL_CONTEXT")
else
  KCMD=(kubectl)
fi

declare -a ENTRIES=(
  "auth.demostratium.com=stratium-keycloak"
  "api.demostratium.com=stratium-pap"
  "ui.demostratium.com=stratium-pap-ui"
  "grpc.demostratium.com=stratium-envoy"
)

for entry in "${ENTRIES[@]}"; do
  host="${entry%%=*}"
  ingress="${entry##*=}"

  echo "Fetching ALB hostname for ingress ${ingress}..."
  alb_dns="$("${KCMD[@]}" -n stratium get ingress "$ingress" -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' || true)"

  if [[ -z "$alb_dns" ]]; then
    echo "  Skipping ${host}: ingress ${ingress} has no hostname yet."
    continue
  fi

  echo "  Updating ${host} -> ${alb_dns}"
  aws route53 change-resource-record-sets \
    --hosted-zone-id "$HOSTED_ZONE_ID" \
    --change-batch "{
      \"Comment\": \"Sync ${host} alias to ${ingress}\",
      \"Changes\": [{
        \"Action\": \"UPSERT\",
        \"ResourceRecordSet\": {
          \"Name\": \"${host}.\",
          \"Type\": \"A\",
          \"AliasTarget\": {
            \"HostedZoneId\": \"${ALB_ZONE_ID}\",
            \"DNSName\": \"${alb_dns}.\",
            \"EvaluateTargetHealth\": false
          }
        }
      }]
    }" >/dev/null
done

echo "DNS aliases updated."
