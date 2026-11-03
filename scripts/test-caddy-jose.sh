#!/bin/bash
# Exercise the local security backport, including upstream interoperability tests.
set -euo pipefail
cd "$(dirname "$0")/../deploy/caddy"
backport="$PWD/third_party/go-jose"
actual=$(GOWORK=off go list -m -f '{{with .Replace}}{{.Dir}}{{end}}' github.com/go-jose/go-jose/v3)
[ "$actual" = "$backport" ] || {
  echo "Caddy must use its tested Go JOSE security backport" >&2
  exit 1
}
cd "$backport"
# Upstream's TestOpaqueKeyRoundtripJWE takes about 30 seconds alone and more than five
# minutes under the race detector, and starts no goroutines, so it runs without it.
slow='^TestOpaqueKeyRoundtripJWE$'
GOWORK=off go test -race -count=1 -skip "$slow" ./...
GOWORK=off go test -count=1 -run "$slow" .
