#!/bin/sh
# Checks a running demo stack from the outside, the way a visitor reaches it.
#
#   ./smoke-test.sh          the local stack (docker-compose.local.yml), on loopback
#   ./smoke-test.sh --live   the real deployment named by DEMO_HOST in ./.env
#
# Local setup, once: a throwaway authority and certificate in secrets/local/
# (see README.md), then
#   docker compose -f docker-compose.yml -f docker-compose.local.yml up -d --build --wait
set -eu
cd "$(dirname "$0")"
. ./.env

base="https://$DEMO_HOST"
realm="$base/realms/stratium"
jar="$(mktemp)"
trap 'rm -f "$jar"' EXIT

if [ "${1:-}" = --live ]; then
	c() { curl -sS "$@"; }
else
	c() { curl -sS --cacert secrets/local/ca.pem --resolve "$DEMO_HOST:443:127.0.0.1" "$@"; }
fi
fail() { echo "FAIL  $*" >&2; exit 1; }
ok() { echo "ok    $*"; }
status() { c -o /dev/null -w '%{http_code}' "$@"; }

# Keycloak advertises the public name, or every token it issues is rejected.
c "$realm/.well-known/openid-configuration" | grep -q "\"issuer\":\"$realm\"" || fail "issuer is not $realm"
ok "issuer is $realm"

# Nothing of Keycloak's but the demo realm's sign-in is reachable.
for path in /admin/ /admin/master/console/ /realms/master/.well-known/openid-configuration /realms/stratium/account/; do
	[ "$(status "$base$path")" = 404 ] || fail "$path is reachable"
done
ok "admin console, master realm and account console are not routed"

# The admin API refuses a caller with no token.
[ "$(status "$base/v1/policies")" = 401 ] || fail "/v1/policies without a token is not 401"
ok "admin API refuses an anonymous caller"

# A password is not enough to get an admin-plane token.
c -d grant_type=password -d client_id=stratium-pap -d username=demo -d "password=$DEMO_USER_PASSWORD" \
	"$realm/protocol/openid-connect/token" | grep -q unauthorized_client || fail "stratium-pap allows the password grant"
ok "admin-plane client refuses the password grant"

# A visitor can get the principal token a session needs.
c -d grant_type=password -d client_id=stratium-pdp -d username=demo -d "password=$DEMO_USER_PASSWORD" \
	-d 'scope=openid email' "$realm/protocol/openid-connect/token" | grep -q '"access_token"' || fail "no principal token for demo"
ok "demo user gets a principal token"

# Browser sign-in, then the admin API with the resulting token.
redirect="$base/callback.html"
action="$(c -c "$jar" -G "$realm/protocol/openid-connect/auth" -d client_id=stratium-pap -d response_type=code \
	--data-urlencode 'scope=openid profile email' --data-urlencode "redirect_uri=$redirect" |
	sed -n 's/.*action="\([^"]*\)".*/\1/p' | head -1 | sed 's/&amp;/\&/g')"
[ -n "$action" ] || fail "no sign-in form"
code="$(c -b "$jar" -o /dev/null -w '%{redirect_url}' -d username=demo -d "password=$DEMO_USER_PASSWORD" "$action" |
	sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$code" ] || fail "sign-in did not return a code"
token="$(c -d grant_type=authorization_code -d client_id=stratium-pap -d "code=$code" \
	--data-urlencode "redirect_uri=$redirect" "$realm/protocol/openid-connect/token" |
	sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || fail "no admin-plane token"
[ "$(status -H "Authorization: Bearer $token" "$base/v1/policies")" = 200 ] || fail "signed-in demo user cannot list policies"
ok "signed-in demo user reads the admin API"
[ "$(status -X DELETE -H "Authorization: Bearer $token" "$base/v1/policies/none")" = 403 ] || fail "demo user is not refused an admin-only call"
ok "demo user is refused an admin-only call"

# gRPC reaches the PDP: an empty Decide is answered by the PDP itself, with a
# gRPC status, not by Caddy or the admin plane.
printf '\0\0\0\0\0' | c --http2 -o /dev/null -D - -H 'content-type: application/grpc' -H 'te: trailers' \
	--data-binary @- "$base/stratium.pdp.v1.PDPService/Decide" | grep -qi '^grpc-status:' || fail "no gRPC answer from the PDP"
ok "PDP answers gRPC through the proxy"
