#!/usr/bin/env bash
set -euo pipefail

DNS_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
HOSTED_ZONE_ID="${1:-}"

usage() {
  cat <<'EOF'
Usage: ./update-aliases.sh <hosted-zone-id> [json-file...]

Applies the Route 53 alias records stored in deployment/dns/*.json to the
specified hosted zone by calling `aws route53 change-resource-record-sets`.

Arguments:
  hosted-zone-id   The Route 53 hosted zone ID (e.g., Z3AADJGX6KTTL2)
  json-file        Optional list of specific JSON change batches to apply.
                   If omitted, all *-alias.json files in this directory are used.
EOF
}

if [[ -z "$HOSTED_ZONE_ID" ]]; then
  usage
  exit 1
fi

shift || true

if [[ $# -gt 0 ]]; then
  CHANGE_FILES=("$@")
else
  CHANGE_FILES=()
  while IFS= read -r file; do
    CHANGE_FILES+=("$file")
  done < <(find "$DNS_DIR" -maxdepth 1 -name "*-alias.json" | sort)
fi

if [[ ${#CHANGE_FILES[@]} -eq 0 ]]; then
  echo "No alias JSON files found in $DNS_DIR" >&2
  exit 1
fi

for file in "${CHANGE_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Skipping missing file: $file" >&2
    continue
  fi
  echo "Applying Route 53 changes from $file"
  aws route53 change-resource-record-sets \
    --hosted-zone-id "$HOSTED_ZONE_ID" \
    --change-batch "file://$file"
done
