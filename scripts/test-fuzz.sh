#!/usr/bin/env bash
# Bound each native Go fuzz campaign and run exactly one matching target at a time.
set -euo pipefail
cd "$(dirname "$0")/.."

export GOMAXPROCS="${FUZZ_PARALLEL:-2}"
duration="${FUZZ_TIME:-5s}"
while read -r package target; do
  go test "$package" -run='^$' -fuzz="^${target}$" -fuzztime="$duration" -parallel="$GOMAXPROCS"
done <<'TARGETS'
./backend/internal/event FuzzDecodeValidateEvent
./backend/internal/auth FuzzSignedRequestHeaders
./backend/internal/auth FuzzPublicKey
./backend/internal/auth FuzzRequestSignature
./backend/internal/command FuzzDecodeCommandResult
./backend/internal/api FuzzEnrollmentRequest
TARGETS
