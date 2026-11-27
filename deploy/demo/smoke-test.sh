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
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
verifier="$(openssl rand 32 | b64url)"
challenge="$(printf %s "$verifier" | openssl dgst -sha256 -binary | b64url)"
auth() { c -G "$realm/protocol/openid-connect/auth" -d client_id=stratium-pap -d response_type=code \
	--data-urlencode 'scope=openid profile email' --data-urlencode "redirect_uri=$redirect" "$@"; }

# Sign-in without a proof key is refused, as is a redirect anywhere but the UI's callback.
auth -o /dev/null -w '%{http_code} %{redirect_url}' | grep -Eq '^400|error=invalid_request' || fail "sign-in without PKCE is accepted"
[ "$(c -o /dev/null -w '%{http_code}' -G "$realm/protocol/openid-connect/auth" -d client_id=stratium-pap -d response_type=code \
	--data-urlencode "redirect_uri=$base/elsewhere")" = 400 ] || fail "a redirect other than callback.html is accepted"
ok "sign-in requires a proof key and the UI's own callback"

action="$(auth -c "$jar" -d code_challenge_method=S256 -d "code_challenge=$challenge" |
	sed -n 's/.*action="\([^"]*\)".*/\1/p' | head -1 | sed 's/&amp;/\&/g')"
[ -n "$action" ] || fail "no sign-in form"
code="$(c -b "$jar" -o /dev/null -w '%{redirect_url}' -d username=demo -d "password=$DEMO_USER_PASSWORD" "$action" |
	sed -n 's/.*[?&]code=\([^&]*\).*/\1/p')"
[ -n "$code" ] || fail "sign-in did not return a code"
token="$(c -d grant_type=authorization_code -d client_id=stratium-pap -d "code=$code" -d "code_verifier=$verifier" \
	--data-urlencode "redirect_uri=$redirect" "$realm/protocol/openid-connect/token" |
	sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')"
[ -n "$token" ] || fail "no admin-plane token"
[ "$(status -H "Authorization: Bearer $token" "$base/v1/policies")" = 200 ] || fail "signed-in demo user cannot list policies"
ok "signed-in demo user reads the admin API"
[ "$(status -X DELETE -H "Authorization: Bearer $token" "$base/v1/policies/none")" = 403 ] || fail "demo user is not refused an admin-only call"
ok "demo user is refused an admin-only call"

# A signed-in visitor cannot change the shared account. Still holding the
# sign-in session cookie, ask for an account action every way Keycloak takes
# one: in the query, in a POSTed form, inside a request object, and on a path
# dressed up to slip past the proxy's matching.
pkce="-d code_challenge_method=S256 -d code_challenge=$challenge"
for act in UPDATE_PASSWORD UPDATE_PROFILE UPDATE_EMAIL CONFIGURE_TOTP delete_account; do
	[ "$(auth -b "$jar" -o /dev/null -w '%{http_code}' $pkce -d "kc_action=$act")" = 404 ] || fail "kc_action=$act in the query is routed"
done
# 405, not 404: the admin plane answers it, and has that path for no method but GET's fallback.
[ "$(status -b "$jar" -d client_id=stratium-pap -d response_type=code -d kc_action=UPDATE_PASSWORD \
	--data-urlencode "redirect_uri=$redirect" $pkce "$realm/protocol/openid-connect/auth")" = 405 ] || fail "a POST to the sign-in endpoint is routed"
# Queries the proxy and Keycloak could read differently.
for extra in 'kc%5Faction=UPDATE_PASSWORD' '%6bc_action=UPDATE_PASSWORD' 'x=a;kc_action=UPDATE_PASSWORD' 'kc_action=UPDATE_PASSWORD&x=%zz' 'x=1'; do
	[ "$(status -b "$jar" "$realm/protocol/openid-connect/auth?client_id=stratium-pap&response_type=code&$extra")" = 404 ] || fail "sign-in with '$extra' is routed"
done
[ "$(auth -b "$jar" -o /dev/null -w '%{http_code}' $pkce -d request=e30.e30.)" = 404 ] || fail "a request object is routed"
[ "$(auth -b "$jar" -o /dev/null -w '%{http_code}' $pkce -d request_uri=https://example.com/r)" = 404 ] || fail "a request_uri is routed"
for path in "/protocol/openid-connect/auth;kc_action=UPDATE_PASSWORD" "/protocol/openid-connect/auth%3Bx" \
	"/login-actions/required-action?execution=UPDATE_PASSWORD" "/protocol/openid-connect/userinfo"; do
	[ "$(status -b "$jar" --path-as-is "$realm$path")" = 404 ] || fail "$path is routed"
done
for path in "/resources/../realms/stratium/account/" "/resources/..%2frealms/stratium/account/" "/resources/%2e%2e/realms/stratium/account/"; do
	[ "$(status -b "$jar" --path-as-is "$base$path")" != 200 ] || fail "$path reaches the account console"
done
ok "account actions on the shared login are not reachable through the proxy"

# The control the proxy only backs up: no account action is enabled in the
# realm at all. Read from Keycloak's own database, so local runs only.
if [ "${1:-}" != --live ]; then
	enabled="$(docker compose -f docker-compose.yml -f docker-compose.local.yml exec -T postgres psql -U postgres -d keycloak -Atc \
		"select count(*) from required_action_provider a join realm r on r.id = a.realm_id where r.name = 'stratium' and a.enabled")"
	[ "$enabled" = 0 ] || fail "$enabled account action(s) enabled in the realm"
	ok "no account action is enabled in the realm"
fi

# gRPC reaches the PDP: an empty Decide is answered by the PDP itself, with a
# gRPC status, not by Caddy or the admin plane.
printf '\0\0\0\0\0' | c --http2 -o /dev/null -D - -H 'content-type: application/grpc' -H 'te: trailers' \
	--data-binary @- "$base/stratium.pdp.v1.PDPService/Decide" | grep -qi '^grpc-status:' || fail "no gRPC answer from the PDP"
ok "PDP answers gRPC through the proxy"
