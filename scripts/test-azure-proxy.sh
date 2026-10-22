#!/bin/bash
# Tests the console allowlist in the Deploy to Azure template (deploy/azure/Caddyfile), in
# Docker. Altiward and caddy share a network namespace, as the two containers of the
# container app do, and every request comes from a third container standing in for the
# Container Apps ingress, which adds the client's address to the right of
# X-Forwarded-For. Agents must get through from anywhere; the console only from the
# allowed networks, whatever a client writes in the header itself.
#
#   scripts/test-azure-proxy.sh <image>     e.g. altiward-api:ci, as `make image` builds it
set -euo pipefail

IMAGE="${1:?the Altiward image to test}"
cd "$(dirname "$0")/.."
# The template's own caddy image.
CADDY=$(sed -n "s/^var caddyImage = '\(.*\)'$/\1/p" deploy/azure/main.bicep)
[ -n "$CADDY" ] || { echo "FAIL: no caddyImage in deploy/azure/main.bicep" >&2; exit 1; }
CURL=curlimages/curl:8.11.1
P=altiward-proxy-test
INGRESS=172.30.231.0/24 # the test network: requests from it come from "the ingress"
CONSOLE_TOKEN=console-token-00000001

cleanup() {
  docker rm -f "$P-caddy" "$P-api" >/dev/null 2>&1 || true
  docker network rm "$P" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
fail() { echo "FAIL: $*" >&2; docker logs "$P-caddy" >&2 || true; exit 1; }
ok() { echo "ok - $*"; }

docker network create --subnet "$INGRESS" "$P" >/dev/null
docker run -d --name "$P-api" --network "$P" \
  -e ALTIWARD_AGENT_TOKENS=ci=agent-token-0000000001 -e ALTIWARD_CONSOLE_TOKENS="ci=$CONSOLE_TOKEN" \
  "$IMAGE" >/dev/null
docker run -d --name "$P-caddy" --network "container:$P-api" \
  -e ALTIWARD_CONSOLE_ALLOW="192.0.2.0/24 198.51.100.7/32" -e ALTIWARD_INGRESS_PROXIES="$INGRESS" \
  -v "$PWD/deploy/azure/Caddyfile:/etc/caddy/Caddyfile:ro" "$CADDY" >/dev/null
APP="http://$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$P-api"):8081"

# status [curl arguments]: the HTTP status of one request from the ingress's network.
status() { docker run --rm --network "$P" "$CURL" -s -o /dev/null -w '%{http_code}' "$@"; }
# expect STATUS DESCRIPTION [curl arguments]
expect() {
  local want="$1" what="$2" got
  shift 2
  got=$(status "$@") || true
  [ "$got" = "$want" ] || fail "$what: HTTP $got, want $want"
  ok "$what: HTTP $got"
}

for _ in $(seq 1 30); do
  [ "$(status "$APP/healthz")" = 200 ] && break
  sleep 1
done

expect 200 "health check, from anywhere" "$APP/healthz" -H "X-Forwarded-For: 203.0.113.9"
expect 401 "agent enroll without a token reaches Altiward, from anywhere" \
  -X POST "$APP/v1/agent/enroll" -H "X-Forwarded-For: 203.0.113.9" -d '{}'
expect 200 "console from an allowed network" "$APP/" -H "X-Forwarded-For: 192.0.2.10"
expect 200 "console from an allowed address" "$APP/" -H "X-Forwarded-For: 198.51.100.7"
expect 200 "console API from an allowed network, signed in" "$APP/v1/about" \
  -H "X-Forwarded-For: 192.0.2.10" -H "Authorization: Bearer $CONSOLE_TOKEN"
expect 403 "console from another network" "$APP/" -H "X-Forwarded-For: 203.0.113.9"
expect 403 "console API from another network, signed in" "$APP/v1/about" \
  -H "X-Forwarded-For: 203.0.113.9" -H "Authorization: Bearer $CONSOLE_TOKEN"
# A client claims an allowed address; the ingress adds its real one after it.
expect 403 "console with a forged allowed address" "$APP/" -H "X-Forwarded-For: 192.0.2.10, 203.0.113.9"
expect 403 "console with no client address" "$APP/"
expect 403 "console sign-in path from another network" "$APP/v1/auth/config" -H "X-Forwarded-For: 203.0.113.9"
